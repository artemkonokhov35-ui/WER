// WER v22.0-UDP — надёжный поток поверх UDP: сессии, SEQ/ACK, окно, ретрансмиссия, FIN.
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading.Channels;

namespace Wer;

public enum UdpFlags : byte
{
    Syn = 0x01,
    SynAck = 0x02,
    Data = 0x04,
    Ack = 0x08,
    Fin = 0x10,
    FinAck = 0x20,
    Rst = 0x40,

    /// <summary>Пакет несёт HMAC-8 после заголовка. Ставится, когда у сессии уже есть транспортный ключ.</summary>
    Auth = 0x80
}

/// <summary>Заголовок датаграммы: [2 magic][1 ver][1 flags][4 session][4 seq][4 ack][2 window].</summary>
public readonly struct UdpHeader
{
    public const int Size = 18;
    public const ushort Magic = 0x5755; // 'W','U'

    /// <summary>Версия 2 добавляет обязательный HMAC-8 после заголовка (после handshake).</summary>
    public const byte Version = 2;

    public readonly UdpFlags Flags;
    public readonly uint Session;
    public readonly uint Seq;
    public readonly uint Ack;
    public readonly ushort Window;

    public UdpHeader(UdpFlags flags, uint session, uint seq, uint ack, ushort window)
    {
        Flags = flags;
        Session = session;
        Seq = seq;
        Ack = ack;
        Window = window;
    }

    public void Write(Span<byte> b)
    {
        BinaryPrimitives.WriteUInt16BigEndian(b, Magic);
        b[2] = Version;
        b[3] = (byte)Flags;
        BinaryPrimitives.WriteUInt32BigEndian(b.Slice(4), Session);
        BinaryPrimitives.WriteUInt32BigEndian(b.Slice(8), Seq);
        BinaryPrimitives.WriteUInt32BigEndian(b.Slice(12), Ack);
        BinaryPrimitives.WriteUInt16BigEndian(b.Slice(16), Window);
    }

    public static bool TryParse(ReadOnlySpan<byte> b, out UdpHeader header, out ReadOnlySpan<byte> payload)
    {
        header = default;
        payload = default;
        if (b.Length < Size) return false;
        if (BinaryPrimitives.ReadUInt16BigEndian(b) != Magic) return false;
        if (b[2] != Version) return false;

        header = new UdpHeader(
            (UdpFlags)b[3],
            BinaryPrimitives.ReadUInt32BigEndian(b.Slice(4)),
            BinaryPrimitives.ReadUInt32BigEndian(b.Slice(8)),
            BinaryPrimitives.ReadUInt32BigEndian(b.Slice(12)),
            BinaryPrimitives.ReadUInt16BigEndian(b.Slice(16)));
        payload = b.Slice(Size);
        return true;
    }
}

internal static class UdpRandom
{
    public static uint Next() => BinaryPrimitives.ReadUInt32LittleEndian(RandomNumberGenerator.GetBytes(sizeof(uint)));
}

/// <summary>
/// Надёжный упорядоченный поток поверх UDP. Сессия идентифицируется (endpoint, sessionId),
/// данные режутся на сегменты по MaxPayload, подтверждаются кумулятивным ACK, окно 256 КиБ.
/// </summary>
public sealed class UdpStream : Stream
{
    public const int MaxPayload = 1200;
    public const int MacSize = 8;
    private const int MaxDatagram = UdpHeader.Size + MacSize + MaxPayload;
    private const int SendWindowBytes = 256 * 1024;
    private const int RecvWindowLimit = 256 * 1024;
    private const int MaxOutOfOrderBytes = 512 * 1024;
    private const int MaxRetries = 40;
    private const long InitialRtoMs = 400;

    internal delegate ValueTask SendDatagram(ReadOnlyMemory<byte> packet, CancellationToken ct);

    private sealed class Segment
    {
        public uint Seq;
        public byte[] Data = Array.Empty<byte>();
        public long LastSent;
        public int Retries;
    }

    private readonly SendDatagram _send;
    private readonly Socket? _socket;
    private readonly IPEndPoint _remote;
    private readonly uint _session;

    private readonly CancellationTokenSource _cts = new();
    private readonly Task _retransmitTask;
    private Task? _receiveTask;
    private readonly SemaphoreSlim _writeLock = new(1, 1);

    // Отправитель.
    private readonly object _sendGate = new();
    private readonly List<Segment> _unacked = new();
    private uint _sendNext;
    private long _inFlightBytes;
    private bool _hasAck;
    private uint _lastAck;
    private long _rtoMs = InitialRtoMs;
    private double _srtt = -1;
    private double _rttvar;
    private TaskCompletionSource _windowSignal = NewSignal();
    private bool _finSent;
    private volatile bool _finAcked;
    private uint _finSeq;
    private long _finLastSent;
    private int _finRetries;
    private ushort _peerWindow = ushort.MaxValue;
    private volatile bool _aborted;

    // Транспортный ключ появляется после crypto-handshake; до него пакеты идут без HMAC.
    private readonly object _authGate = new();
    private readonly List<byte[]> _pendingAuth = new();
    private byte[]? _macKey;
    private volatile bool _handshakeAckPending;
    private long _handshakeAckSent;
    private int _handshakeAckTries;
    private volatile bool _peerPacketsSeen;

    // Получатель.
    private readonly object _recvGate = new();
    private readonly Queue<byte[]> _ready = new();
    private int _readyOffset;
    private long _readyBytes;
    private readonly SortedDictionary<uint, byte[]> _ooo = new();
    private long _oooBytes;
    private uint _recvNext;
    private bool _remoteFin;
    private uint? _pendingFinSeq;
    private TaskCompletionSource _dataSignal = NewSignal();
    private Exception? _fault;

    private volatile bool _disposed;
    private long _lastActivity = Environment.TickCount64;

    public event Action<UdpStream>? Closed;

    internal long LastActivity => Volatile.Read(ref _lastActivity);
    public uint Session => _session;
    public IPEndPoint RemoteEndPoint => _remote;

    internal UdpStream(SendDatagram send, uint session, IPEndPoint remote, uint sendNext, uint recvNext, Socket? ownSocket)
    {
        _send = send;
        _session = session;
        _remote = remote;
        _sendNext = sendNext;
        _recvNext = recvNext;
        _socket = ownSocket;
        _retransmitTask = Task.Run(RetransmitLoopAsync);
        if (_socket is not null) _receiveTask = Task.Run(ReceiveLoopAsync);
    }

    private static TaskCompletionSource NewSignal() =>
        new(TaskCreationOptions.RunContinuationsAsynchronously);

    private static bool SeqBefore(uint a, uint b) => (int)(a - b) < 0;
    private static bool SeqLE(uint a, uint b) => (int)(a - b) <= 0;

    // ------------------------------------------------------------------ клиент

    public static async Task<UdpStream> ConnectAsync(string host, int port, CancellationToken ct)
    {
        IPAddress[] addresses = await Dns.GetHostAddressesAsync(host).ConfigureAwait(false);
        if (addresses.Length == 0) throw new SocketException((int)SocketError.HostNotFound);
        IPAddress addr = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork) ?? addresses[0];
        var remote = new IPEndPoint(addr, port);

        var sock = new Socket(addr.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        try
        {
            sock.ReceiveBufferSize = 1 << 20;
            sock.SendBufferSize = 1 << 20;
            await sock.ConnectAsync(remote, ct).ConfigureAwait(false);
        }
        catch
        {
            sock.Dispose();
            throw;
        }

        uint session = UdpRandom.Next() | 1u;
        uint isn = UdpRandom.Next();
        var buf = new byte[MaxDatagram];

        try
        {
            for (int attempt = 0; attempt < 40; attempt++)
            {
                ct.ThrowIfCancellationRequested();
                await SendSynAsync(sock, session, isn).ConfigureAwait(false);

                using var attemptCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                attemptCts.CancelAfter(250);
                try
                {
                    while (true)
                    {
                        int n = await sock.ReceiveAsync(buf.AsMemory(), SocketFlags.None, attemptCts.Token)
                            .ConfigureAwait(false);
                        if (!UdpHeader.TryParse(buf.AsSpan(0, n), out UdpHeader h, out _)) continue;
                        if (h.Session != session) continue;
                        if ((h.Flags & UdpFlags.Rst) != 0)
                        {
                            // До аутентификации RST подделать может кто угодно (как TCP RST).
                            // Не даём постороннему «ветировать» соединение: ждём SYNACK до таймаута.
                            continue;
                        }
                        if ((h.Flags & UdpFlags.SynAck) != 0)
                        {
                            var stream = new UdpStream(
                                (pkt, _) => SendConnectedAsync(sock, pkt),
                                session, remote, isn + 1, h.Seq + 1, sock);
                            await stream.SendAckAsync().ConfigureAwait(false);
                            stream.BeginHandshakeAck();
                            return stream;
                        }
                    }
                }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                {
                    // SYN потерялся — повтор.
                }
            }
        }
        catch
        {
            sock.Dispose();
            throw;
        }

        sock.Dispose();
        throw new TimeoutException("Сервер не ответил на UDP SYN.");
    }

    private static async ValueTask SendSynAsync(Socket sock, uint session, uint isn)
    {
        var pkt = new byte[UdpHeader.Size];
        new UdpHeader(UdpFlags.Syn, session, isn, 0, ushort.MaxValue).Write(pkt);
        try { await sock.SendAsync(pkt, SocketFlags.None).ConfigureAwait(false); }
        catch (SocketException) { }
        catch (ObjectDisposedException) { }
    }

    private static async ValueTask SendConnectedAsync(Socket sock, ReadOnlyMemory<byte> packet)
    {
        try { await sock.SendAsync(packet, SocketFlags.None).ConfigureAwait(false); }
        catch (SocketException) { }
        catch (ObjectDisposedException) { }
    }

    private async Task ReceiveLoopAsync()
    {
        var buf = new byte[MaxDatagram];
        while (!_cts.IsCancellationRequested)
        {
            int n;
            try
            {
                n = await _socket!.ReceiveAsync(buf.AsMemory(), SocketFlags.None, _cts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { break; }
            catch (ObjectDisposedException) { break; }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionReset) { continue; }
            catch (SocketException) { break; }

            ReadOnlySpan<byte> datagram = buf.AsSpan(0, n);
            if (!UdpHeader.TryParse(datagram, out UdpHeader h, out _)) continue;
            if (h.Session != _session) continue;
            OnPacket(h, datagram);
        }
    }

    // ------------------------------------------------------------------ серверная сторона

    /// <summary>
    /// Включает HMAC на каждый пакет. Вызывается после crypto-handshake, когда у обеих сторон
    /// есть общий секрет: подделанные RST, ACK и window от посторонних перестают приниматься.
    /// Пакеты с флагом Auth, пришедшие до появления ключа, откладываются и разбираются здесь.
    /// </summary>
    public void EnableAuthentication(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);

        byte[][] pending;
        lock (_authGate)
        {
            _macKey = (byte[])key.Clone();
            pending = _pendingAuth.ToArray();
            _pendingAuth.Clear();
        }

        foreach (byte[] datagram in pending)
        {
            if (!UdpHeader.TryParse(datagram, out UdpHeader h, out _)) continue;
            OnPacket(h, datagram);
        }
    }

    private byte[] Mac(ReadOnlySpan<byte> header, ReadOnlySpan<byte> payload)
    {
        var full = new byte[header.Length + payload.Length];
        header.CopyTo(full);
        payload.CopyTo(full.AsSpan(header.Length));
        byte[] tag = HMACSHA256.HashData(_macKey!, full);
        return tag.AsSpan(0, MacSize).ToArray();
    }

    internal void OnPacket(in UdpHeader h, ReadOnlySpan<byte> datagram)
    {
        ReadOnlySpan<byte> payload;
        bool macPresent = (h.Flags & UdpFlags.Auth) != 0;
        byte[]? key;
        lock (_authGate) key = _macKey;

        if (macPresent)
        {
            if (key is null)
            {
                // Пакет опередил включение HMAC (например, Finished): откладываем до появления ключа.
                lock (_authGate)
                {
                    if (_macKey is null)
                    {
                        if (_pendingAuth.Count < 8) _pendingAuth.Add(datagram.ToArray());
                        return;
                    }
                }
            }

            if (datagram.Length < UdpHeader.Size + MacSize) return;
            payload = datagram.Slice(UdpHeader.Size + MacSize);
            byte[] expected = Mac(datagram.Slice(0, UdpHeader.Size), payload);
            if (!CryptographicOperations.FixedTimeEquals(datagram.Slice(UdpHeader.Size, MacSize), expected))
                return; // подделка или мусор: молча отбрасываем, сессию не трогаем
        }
        else
        {
            if (key is not null) return; // после включения HMAC пакеты без тега не принимаются
            payload = datagram.Slice(UdpHeader.Size);
        }

        _peerPacketsSeen = true;
        _handshakeAckPending = false;
        Volatile.Write(ref _lastActivity, Environment.TickCount64);

        if ((h.Flags & UdpFlags.Rst) != 0)
        {
            // До появления транспортного ключа RST ничем не подтверждён — верить ему нельзя.
            if (_macKey is null) return;

            // RST принимается только со счётчиком, который виден лишь участнику сессии:
            // слепой инжектор должен угадать одно из двух 32-битных значений.
            uint recv = _recvNext;
            uint send = _sendNext;
            if (h.Ack == recv || h.Seq == send)
                Fault(new IOException("Соединение сброшено удалённой стороной (UDP RST)."));
            return;
        }

        _peerWindow = h.Window;

        if (h.Ack != 0 && (h.Flags & (UdpFlags.Ack | UdpFlags.Data | UdpFlags.Fin | UdpFlags.FinAck | UdpFlags.SynAck)) != 0)
            ProcessAck(h.Ack);

        if ((h.Flags & UdpFlags.Data) != 0 && payload.Length > 0)
            ReceiveData(h.Seq, payload);

        if ((h.Flags & UdpFlags.Fin) != 0)
            ReceiveFin(h.Seq);

        if ((h.Flags & UdpFlags.Ack) != 0 && (h.Flags & (UdpFlags.Data | UdpFlags.Fin)) == 0)
            _ = SendAckAsync();
    }

    // ------------------------------------------------------------------ ACK / окно

    private void ProcessAck(uint ack)
    {
        long freed = 0;
        long rttSample = -1;

        lock (_sendGate)
        {
            // ACK за пределы отправленного — подделка: игнорируем, иначе теряются неподтверждённые данные.
            if (SeqBefore(_sendNext, ack)) return;
            // Устаревший (переупорядоченный) ACK не должен сдвигать состояние назад.
            if (_hasAck && SeqBefore(ack, _lastAck)) return;

            _hasAck = true;
            _lastAck = ack;

            int i = 0;
            for (; i < _unacked.Count; i++)
            {
                Segment s = _unacked[i];
                if (!SeqBefore(s.Seq, ack)) break;
                freed += s.Data.Length;
                if (s.Retries == 0) rttSample = Environment.TickCount64 - s.LastSent;
            }
            if (i > 0)
            {
                _unacked.RemoveRange(0, i);
                _inFlightBytes -= freed;
            }

            if (_finSent && SeqLE(_finSeq + 1, ack)) _finAcked = true;

            if (rttSample >= 0)
            {
                if (_srtt < 0)
                {
                    _srtt = rttSample;
                    _rttvar = rttSample / 2.0;
                }
                else
                {
                    _rttvar = 0.75 * _rttvar + 0.25 * Math.Abs(_srtt - rttSample);
                    _srtt = 0.875 * _srtt + 0.125 * rttSample;
                }
                _rtoMs = (long)Math.Clamp(_srtt + 4 * _rttvar, 150, 4000);
            }
        }

        TaskCompletionSource sig = Interlocked.Exchange(ref _windowSignal, NewSignal());
        sig.TrySetResult();
    }

    private ushort AdvertisedWindow()
    {
        long used = _readyBytes + _oooBytes;
        long free = RecvWindowLimit - used;
        if (free < 0) free = 0;
        return (ushort)Math.Min(free, ushort.MaxValue);
    }

    private async Task SendAckAsync()
    {
        try
        {
            await SendRawAsync(UdpFlags.Ack, _sendNext, ReadOnlyMemory<byte>.Empty, CancellationToken.None)
                .ConfigureAwait(false);
        }
        catch { /* best effort */ }
    }

    private async Task SendBestEffortAsync(byte[] packet)
    {
        try { await _send(packet, CancellationToken.None).ConfigureAwait(false); }
        catch { /* best effort */ }
    }

    /// <summary>Клиент помнит свой ACK на SYNACK и повторяет его, пока не придёт любой ответ сервера.</summary>
    private void BeginHandshakeAck()
    {
        _handshakeAckSent = Environment.TickCount64;
        _handshakeAckTries = 0;
        _handshakeAckPending = true;
    }

    private async ValueTask SendRawAsync(UdpFlags flags, uint seq, ReadOnlyMemory<byte> payload, CancellationToken ct)
    {
        uint ack;
        ushort win;
        lock (_recvGate)
        {
            ack = _recvNext;
            win = AdvertisedWindow();
        }

        int macLen = _macKey is null ? 0 : MacSize;
        if (macLen > 0) flags |= UdpFlags.Auth;
        var pkt = new byte[UdpHeader.Size + macLen + payload.Length];
        new UdpHeader(flags, _session, seq, ack, win).Write(pkt);
        payload.CopyTo(pkt.AsMemory(UdpHeader.Size + macLen));
        if (macLen > 0)
            Mac(pkt.AsSpan(0, UdpHeader.Size), pkt.AsSpan(UdpHeader.Size + macLen))
                .CopyTo(pkt.AsSpan(UdpHeader.Size, MacSize));

        try { await _send(pkt, ct).ConfigureAwait(false); }
        catch (SocketException) { }
        catch (ObjectDisposedException) { }
    }

    // ------------------------------------------------------------------ приём данных

    private void ReceiveData(uint seq, ReadOnlySpan<byte> payload)
    {
        lock (_recvGate)
        {
            // Пир обязан соблюдать объявленное окно; выход за двойной лимит означает игнор окна.
            if (_readyBytes + _oooBytes + payload.Length > 2L * (RecvWindowLimit + MaxOutOfOrderBytes))
            {
                Fault(new IOException("Получатель переполнен: собеседник не соблюдает окно приёма."));
                return;
            }

            if (SeqBefore(seq, _recvNext))
            {
                // Дубликат — подтверждаем ещё раз.
            }
            else if (seq == _recvNext)
            {
                Enqueue(payload.ToArray());
                _recvNext++;
                DrainOutOfOrder();
                CheckPendingFin();
            }
            else if (!_ooo.ContainsKey(seq) && _oooBytes + payload.Length <= MaxOutOfOrderBytes)
            {
                _ooo[seq] = payload.ToArray();
                _oooBytes += payload.Length;
            }
        }

        SignalData();
        _ = SendAckAsync();
    }

    private void ReceiveFin(uint seq)
    {
        lock (_recvGate)
        {
            if (seq == _recvNext)
            {
                _recvNext++;
                _remoteFin = true;
            }
            else if (!SeqBefore(seq, _recvNext))
            {
                _pendingFinSeq = seq;
                CheckPendingFin();
            }
        }

        SignalData();
        _ = SendAckAsync();
    }

    private void DrainOutOfOrder()
    {
        while (_ooo.Count > 0)
        {
            KeyValuePair<uint, byte[]> first = _ooo.First();
            if (first.Key != _recvNext) break;
            _ooo.Remove(first.Key);
            _oooBytes -= first.Value.Length;
            Enqueue(first.Value);
            _recvNext++;
        }
    }

    private void CheckPendingFin()
    {
        if (_pendingFinSeq.HasValue && _pendingFinSeq.Value == _recvNext)
        {
            _pendingFinSeq = null;
            _recvNext++;
            _remoteFin = true;
        }
    }

    private void Enqueue(byte[] data)
    {
        _ready.Enqueue(data);
        _readyBytes += data.Length;
    }

    private void SignalData() => Interlocked.Exchange(ref _dataSignal, NewSignal()).TrySetResult();

    private void Fault(Exception ex)
    {
        if (_fault is null) _fault = ex;
        Interlocked.Exchange(ref _dataSignal, NewSignal()).TrySetResult();
        Interlocked.Exchange(ref _windowSignal, NewSignal()).TrySetResult();
    }

    // ------------------------------------------------------------------ отправка

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default)
    {
        if (buffer.Length == 0) return;

        await _writeLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            int off = 0;
            while (off < buffer.Length)
            {
                int take = Math.Min(MaxPayload, buffer.Length - off);
                await WaitForWindowAsync(take, ct).ConfigureAwait(false);

                byte[] data = buffer.Slice(off, take).ToArray();
                uint seq;
                lock (_sendGate)
                {
                    ThrowIfFaulted();
                    seq = _sendNext++;
                    _unacked.Add(new Segment { Seq = seq, Data = data, LastSent = Environment.TickCount64 });
                    _inFlightBytes += data.Length;
                }

                await SendRawAsync(UdpFlags.Data, seq, data, ct).ConfigureAwait(false);
                off += take;
            }
        }
        finally
        {
            _writeLock.Release();
        }
    }

    private async ValueTask WaitForWindowAsync(int want, CancellationToken ct)
    {
        while (true)
        {
            Task? wait = null;
            lock (_sendGate)
            {
                ThrowIfFaulted();
                long limit = Math.Min(SendWindowBytes, Math.Max(1, (int)_peerWindow));
                if (_inFlightBytes + want <= limit) return;
                wait = _windowSignal.Task;
            }
            await wait.WaitAsync(ct).ConfigureAwait(false);
        }
    }

    private void ThrowIfFaulted()
    {
        if (_fault is not null) throw new IOException(_fault.Message, _fault);
    }

    private async Task RetransmitLoopAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            try { await Task.Delay(20, _cts.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }

            long now = Environment.TickCount64;
            long rto = Volatile.Read(ref _rtoMs);
            var stale = new List<Segment>();
            Exception? fail = null;

            lock (_sendGate)
            {
                foreach (Segment s in _unacked)
                {
                    if (now - s.LastSent < rto) continue;
                    if (++s.Retries > MaxRetries)
                    {
                        fail = new TimeoutException("Нет подтверждения от собеседника (UDP): слишком много ретрансмиссий.");
                        break;
                    }
                    s.LastSent = now;
                    stale.Add(s);
                }
            }

            if (fail is not null)
            {
                Fault(fail);
                break;
            }

            foreach (Segment s in stale)
                await SendRawAsync(UdpFlags.Data, s.Seq, s.Data, CancellationToken.None).ConfigureAwait(false);

            bool resendFin = false;
            lock (_sendGate)
            {
                if (_finSent && !_finAcked && now - _finLastSent >= rto)
                {
                    _finLastSent = now;
                    _finRetries++;
                    resendFin = _finRetries <= MaxRetries;
                }
            }
            if (resendFin)
                await SendRawAsync(UdpFlags.Fin, _finSeq, ReadOnlyMemory<byte>.Empty, CancellationToken.None)
                    .ConfigureAwait(false);

            // Один потерянный ACK на SYNACK — и сервер не создаст сессию; повторяем, пока он не ответит.
            if (_handshakeAckPending && !_peerPacketsSeen && now - _handshakeAckSent >= 250
                && _handshakeAckTries < 20)
            {
                _handshakeAckTries++;
                _handshakeAckSent = now;
                await SendRawAsync(UdpFlags.Ack, _sendNext, ReadOnlyMemory<byte>.Empty, CancellationToken.None)
                    .ConfigureAwait(false);
            }
        }
    }

    // ------------------------------------------------------------------ чтение

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
    {
        if (buffer.Length == 0) return 0;

        while (true)
        {
            Task wait;
            lock (_recvGate)
            {
                if (_fault is not null) throw new IOException(_fault.Message, _fault);

                if (_ready.Count > 0)
                {
                    byte[] seg = _ready.Peek();
                    int n = Math.Min(seg.Length - _readyOffset, buffer.Length);
                    seg.AsSpan(_readyOffset, n).CopyTo(buffer.Span);
                    _readyOffset += n;
                    _readyBytes -= n;
                    if (_readyOffset == seg.Length)
                    {
                        _ready.Dequeue();
                        _readyOffset = 0;
                    }
                    return n;
                }

                if (_remoteFin) return 0;
                if (_disposed) return 0;

                wait = _dataSignal.Task;
            }
            await wait.WaitAsync(ct).ConfigureAwait(false);
        }
    }

    public override int Read(byte[] buffer, int offset, int count) =>
        ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    public override void Write(byte[] buffer, int offset, int count) =>
        WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    public override void Flush() { }

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => throw new NotSupportedException();
    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();

    // ------------------------------------------------------------------ закрытие

    /// <summary>Сброс сессии (RST) без ожидания FIN.</summary>
    public void Abort()
    {
        if (_disposed) return;
        _aborted = true;
        try
        {
            var pkt = new byte[UdpHeader.Size];
            new UdpHeader(UdpFlags.Rst, _session, _sendNext, _recvNext, 0).Write(pkt);
            _ = SendBestEffortAsync(pkt);
        }
        catch { /* best effort */ }

        try { Dispose(); } catch { /* best effort */ }
    }

    protected override void Dispose(bool disposing)
    {
        if (!disposing)
        {
            base.Dispose(disposing);
            return;
        }
        if (_disposed) return;
        _disposed = true;

        if (!_aborted)
        {
            try
            {
                bool sendFin = false;
                lock (_sendGate)
                {
                    if (!_finSent)
                    {
                        _finSeq = _sendNext++;
                        _finSent = true;
                        _finLastSent = Environment.TickCount64;
                        sendFin = true;
                    }
                }

                if (sendFin)
                {
                    for (int i = 0; i < 3 && !_finAcked; i++)
                    {
                        try
                        {
                            SendRawAsync(UdpFlags.Fin, _finSeq, ReadOnlyMemory<byte>.Empty, CancellationToken.None)
                                .AsTask().Wait(200);
                        }
                        catch { /* best effort */ }

                        for (int w = 0; w < 6 && !_finAcked; w++) Thread.Sleep(50);
                    }
                }
            }
            catch { /* best effort */ }
        }

        try { _cts.Cancel(); } catch { /* ignore */ }
        try { _socket?.Dispose(); } catch { /* ignore */ }
        try { _writeLock.Dispose(); } catch { /* ignore */ }

        Action<UdpStream>? closed = Closed;
        if (closed is not null)
        {
            try { closed(this); } catch { /* ignore */ }
        }

        base.Dispose(disposing);
    }
}

/// <summary>
/// UDP-сервер: одна сокет-приёмная петля, сессии по (endpoint, sessionId).
/// Состояние создаётся только после проверки SYN-cookie: SYN не порождает ни потоков, ни задач.
/// </summary>
public sealed class UdpListener : IDisposable
{
    private const int MaxSessions = 4096;
    private const int SynPerSecondPerIp = 300;
    private const int MaxSynBuckets = 4096;

    private readonly record struct SessionKey(IPEndPoint EndPoint, uint Id);

    private readonly Socket _socket;
    private readonly EndPoint _any;
    private readonly Channel<UdpStream> _incoming = Channel.CreateBounded<UdpStream>(
        new BoundedChannelOptions(MaxSessions)
        {
            SingleReader = false,
            SingleWriter = false,
            FullMode = BoundedChannelFullMode.Wait
        });
    private readonly ConcurrentDictionary<SessionKey, UdpStream> _sessions = new();
    private readonly ConcurrentDictionary<IPAddress, SynBucket> _synBuckets = new();
    private readonly byte[] _cookieSecret = RandomNumberGenerator.GetBytes(32);
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _loop;
    private readonly Task _sweeper;

    private sealed class SynBucket
    {
        public long Second;
        public int Count;
        public long Touched;
    }

    public UdpListener(int port)
    {
        if (Socket.OSSupportsIPv6)
        {
            _socket = new Socket(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp) { DualMode = true };
            _socket.Bind(new IPEndPoint(IPAddress.IPv6Any, port));
            _any = new IPEndPoint(IPAddress.IPv6Any, 0);
        }
        else
        {
            _socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            _socket.Bind(new IPEndPoint(IPAddress.Any, port));
            _any = new IPEndPoint(IPAddress.Any, 0);
        }
        _socket.ReceiveBufferSize = 4 << 20;
        _socket.SendBufferSize = 1 << 20;

        _loop = Task.Run(ReceiveLoopAsync);
        _sweeper = Task.Run(SweepLoopAsync);
    }

    public ValueTask<UdpStream> AcceptAsync(CancellationToken ct) => _incoming.Reader.ReadAsync(ct);

    private async Task ReceiveLoopAsync()
    {
        var buf = new byte[UdpHeader.Size + UdpStream.MacSize + UdpStream.MaxPayload];
        while (!_cts.IsCancellationRequested)
        {
            SocketReceiveFromResult r;
            try
            {
                r = await _socket.ReceiveFromAsync(buf.AsMemory(), SocketFlags.None, _any, _cts.Token)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException) { break; }
            catch (ObjectDisposedException) { break; }
            catch (SocketException ex) when (ex.SocketErrorCode is SocketError.ConnectionReset or SocketError.MessageSize)
            {
                continue;
            }
            catch (SocketException) { continue; }

            var ep = (IPEndPoint)r.RemoteEndPoint;
            ReadOnlySpan<byte> datagram = buf.AsSpan(0, r.ReceivedBytes);
            if (!UdpHeader.TryParse(datagram, out UdpHeader h, out _))
                continue;

            var key = new SessionKey(ep, h.Session);

            if ((h.Flags & UdpFlags.Syn) != 0)
            {
                HandleSyn(ep, h);
                continue;
            }

            if (_sessions.TryGetValue(key, out UdpStream? session))
                session.OnPacket(h, datagram);
            else if (!TryAcceptCookie(ep, key, h, datagram))
                SendRst(ep, h.Session);
        }
    }

    /// <summary>
    /// SYN обрабатывается без создания состояния: серверный ISN выводится из HMAC(endpoint, session, clientIsn).
    /// Клиент возвращает его в ACK, и только тогда появляется сессия — флуд SYN не расходует ни память, ни задачи.
    /// </summary>
    private void HandleSyn(IPEndPoint ep, in UdpHeader h)
    {
        if (!AllowSyn(ep)) return;

        uint serverIsn = CookieServerIsn(ep, h.Session, h.Seq);
        var pkt = new byte[UdpHeader.Size];
        new UdpHeader(UdpFlags.SynAck, h.Session, serverIsn, h.Seq + 1, ushort.MaxValue).Write(pkt);
        _ = SendToAsync(ep, pkt);
    }

    private uint CookieServerIsn(IPEndPoint ep, uint session, uint clientIsn)
    {
        Span<byte> data = stackalloc byte[32];
        if (!ep.Address.TryWriteBytes(data, out int n)) n = 0;
        BinaryPrimitives.WriteInt32BigEndian(data.Slice(n), ep.Port); n += 4;
        BinaryPrimitives.WriteUInt32BigEndian(data.Slice(n), session); n += 4;
        BinaryPrimitives.WriteUInt32BigEndian(data.Slice(n), clientIsn); n += 4;

        Span<byte> mac = stackalloc byte[32];
        HMACSHA256.HashData(_cookieSecret, data.Slice(0, n), mac);
        return BinaryPrimitives.ReadUInt32BigEndian(mac) | 1u;
    }

    /// <summary>Первое не-SYN сообщение от неизвестной сессии: проверяем cookie и только затем создаём поток.</summary>
    private bool TryAcceptCookie(IPEndPoint ep, SessionKey key, in UdpHeader h, ReadOnlySpan<byte> datagram)
    {
        if (h.Seq == 0) return false;

        uint clientIsn = h.Seq - 1;
        if (h.Ack != CookieServerIsn(ep, h.Session, clientIsn) + 1) return false;

        if (_sessions.Count >= MaxSessions)
        {
            SendRst(ep, h.Session);
            return true;
        }

        var stream = new UdpStream(
            (pkt, _) => SendToAsync(ep, pkt),
            h.Session, ep, h.Ack, h.Seq, null);
        stream.Closed += OnSessionClosed;

        if (!_sessions.TryAdd(key, stream))
        {
            stream.Abort();
            return true;
        }

        if (!_incoming.Writer.TryWrite(stream))
        {
            _sessions.TryRemove(key, out _);
            stream.Abort();
            SendRst(ep, h.Session);
            return true;
        }

        stream.OnPacket(h, datagram);
        return true;
    }

    private bool AllowSyn(IPEndPoint ep)
    {
        long now = Environment.TickCount64;
        if (_synBuckets.Count > MaxSynBuckets) _synBuckets.Clear();

        SynBucket b = _synBuckets.GetOrAdd(ep.Address, _ => new SynBucket());
        lock (b)
        {
            long second = now / 1000;
            if (b.Second != second)
            {
                b.Second = second;
                b.Count = 0;
            }
            b.Touched = now;
            return ++b.Count <= SynPerSecondPerIp;
        }
    }

    private void OnSessionClosed(UdpStream s) =>
        _sessions.TryRemove(new SessionKey(s.RemoteEndPoint, s.Session), out _);

    private async ValueTask SendToAsync(IPEndPoint ep, ReadOnlyMemory<byte> packet)
    {
        try { await _socket.SendToAsync(packet, SocketFlags.None, ep).ConfigureAwait(false); }
        catch (SocketException) { }
        catch (ObjectDisposedException) { }
    }

    private void SendRst(IPEndPoint ep, uint session)
    {
        var pkt = new byte[UdpHeader.Size];
        new UdpHeader(UdpFlags.Rst, session, 0, 0, 0).Write(pkt);
        _ = SendToAsync(ep, pkt);
    }

    private async Task SweepLoopAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            try { await Task.Delay(10_000, _cts.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }

            long now = Environment.TickCount64;
            foreach (KeyValuePair<SessionKey, UdpStream> kv in _sessions)
            {
                if (now - kv.Value.LastActivity <= 120_000) continue;
                _sessions.TryRemove(kv.Key, out _);
                try { kv.Value.Abort(); } catch { /* ignore */ }
            }

            foreach (KeyValuePair<IPAddress, SynBucket> kv in _synBuckets)
            {
                if (now - kv.Value.Touched <= 120_000) continue;
                _synBuckets.TryRemove(kv.Key, out _);
            }
        }
    }

    public void Dispose()
    {
        try { _cts.Cancel(); } catch { /* ignore */ }
        try { _socket.Dispose(); } catch { /* ignore */ }
        _incoming.Writer.TryComplete();

        try { Task.WhenAny(Task.WhenAll(_loop, _sweeper), Task.Delay(2000)).GetAwaiter().GetResult(); }
        catch { /* ignore */ }

        foreach (KeyValuePair<SessionKey, UdpStream> kv in _sessions)
        {
            try { kv.Value.Abort(); } catch { /* ignore */ }
        }
        _sessions.Clear();
        _cts.Dispose();
    }
}
