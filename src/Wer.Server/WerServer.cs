// WER v22.0-UDP — асинхронный сервер с возобновляемым приёмом файлов и периодическими ACK.
using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Channels;

namespace Wer;

public sealed record ServerOptions(
    int Port,
    int MaxConnections,
    int MaxPerIp,
    string DataDir,
    string? RegisterToken,
    long MaxFileSize,
    int MaxUsers,
    bool OpenRegistration);

public sealed class WerServer : IDisposable
{
    private readonly ServerOptions _opt;
    private readonly RSA _serverKey;
    private readonly byte[] _serverSpki;
    private readonly RSA _decoyKey;
    private readonly byte[] _decoySpki;
    private readonly string _usersDir;
    private readonly string _receivedDir;
    private readonly SemaphoreSlim _slots;
    private readonly Dictionary<IPAddress, int> _perIp = new();
    private readonly ConcurrentDictionary<Task, byte> _tasks = new();
    private readonly SemaphoreSlim _registerLock = new(1, 1);
    private readonly ConcurrentDictionary<IPAddress, TokenBucket> _handshakes = new();
    private readonly ConcurrentDictionary<string, TokenBucket> _fileMeta = new();

    private const int HandshakesPerMinute = 60;
    private const int HandshakeBurst = 10;
    private const int FileMetaPerMinute = 10;
    private const int FileMetaBurst = 3;

    private sealed class TokenBucket
    {
        public double Tokens;
        public long Last;
    }

    private static bool TakeToken<TKey>(ConcurrentDictionary<TKey, TokenBucket> buckets, TKey key,
        int perMinute, int burst) where TKey : notnull
    {
        if (buckets.Count > 4096) buckets.Clear();

        long now = Environment.TickCount64;
        TokenBucket b = buckets.GetOrAdd(key, _ => new TokenBucket { Tokens = burst, Last = now });

        lock (b)
        {
            b.Tokens = Math.Min(burst, b.Tokens + (now - b.Last) * (perMinute / 60_000.0));
            b.Last = now;
            if (b.Tokens < 1) return false;
            b.Tokens -= 1;
            return true;
        }
    }

    private bool AllowHandshake(IPAddress ip) =>
        TakeToken(_handshakes, ip, HandshakesPerMinute, HandshakeBurst);

    public WerServer(ServerOptions opt)
    {
        if (opt.Port is < 1 or > 65535) throw new ArgumentOutOfRangeException(nameof(opt.Port));
        if (opt.MaxConnections < 1 || opt.MaxPerIp < 1) throw new ArgumentOutOfRangeException(nameof(opt.MaxConnections));
        if (opt.MaxFileSize < 0) throw new ArgumentOutOfRangeException(nameof(opt.MaxFileSize));
        if (opt.MaxUsers < 1) throw new ArgumentOutOfRangeException(nameof(opt.MaxUsers));

        _opt = opt;
        _usersDir = Path.Combine(opt.DataDir, "users");
        _receivedDir = Path.Combine(opt.DataDir, "received");
        Directory.CreateDirectory(_usersDir);
        Directory.CreateDirectory(_receivedDir);
        _slots = new SemaphoreSlim(opt.MaxConnections, opt.MaxConnections);

        string keyPath = Path.Combine(opt.DataDir, "server_key.pem");
        Log.Info("Загрузка ключа сервера (если его нет — генерация RSA-3072, это может занять несколько секунд)...");
        _serverKey = KeyStore.LoadOrCreate(keyPath, Environment.GetEnvironmentVariable("WER_KEY_PASSWORD"), out bool created);
        _serverSpki = _serverKey.ExportSubjectPublicKeyInfo();

        // Ключ-приманка: для незарегистрированного имени сервер отвечает обычным CHALLENGE,
        // чтобы по ответу нельзя было отличить существующего пользователя от несуществующего.
        _decoyKey = RSA.Create(Proto.RsaBits);
        _decoySpki = _decoyKey.ExportSubjectPublicKeyInfo();
        Log.Info(created ? $"Создан новый ключ сервера: {keyPath}" : $"Ключ сервера загружен: {keyPath}");
        Log.Info($"Отпечаток ключа сервера (SHA-256): {Proto.Hex(Proto.Sha256(_serverSpki))}");
        if (opt.RegisterToken is not null)
            Log.Info("Режим регистрации: только с токеном (--reg-token).");
        else if (opt.OpenRegistration)
            Log.Warn("Регистрация ОТКРЫТА: любой может создать пользователя. Задайте --reg-token или уберите --open-registration.");
        else
            Log.Info("Режим регистрации: отключена. Для новых пользователей задайте --reg-token.");
    }

    public async Task RunAsync(CancellationToken ct)
    {
        using var listener = new UdpListener(_opt.Port);
        Log.Info($"WER v22.2-UDP сервер слушает UDP-порт {_opt.Port} (макс. подключений: {_opt.MaxConnections}, на IP: {_opt.MaxPerIp}).");

        try
        {
            while (!ct.IsCancellationRequested)
            {
                UdpStream client;
                try
                {
                    client = await listener.AcceptAsync(ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException) { break; }
                catch (ChannelClosedException) { break; }

                string remote = client.RemoteEndPoint.ToString();
                IPAddress ip = client.RemoteEndPoint.Address;
                if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();

                // Глобальный лимит одновременных подключений.
                if (!_slots.Wait(0))
                {
                    Log.WarnThrottled(5, "conn-limit", $"{remote}: отклонён — достигнут лимит подключений.");
                    client.Abort();
                    continue;
                }
                if (!TryAcquireIp(ip))
                {
                    Log.WarnThrottled(5, "per-ip", $"{remote}: отклонён — слишком много подключений с одного IP.");
                    _slots.Release();
                    client.Abort();
                    continue;
                }

                var task = Task.Run(() => HandleAsync(client, ip, remote, ct), CancellationToken.None);
                _tasks[task] = 0;
                _ = task.ContinueWith(t => _tasks.TryRemove(t, out _), TaskScheduler.Default);
            }
        }
        finally
        {
            Log.Info("Остановка: ожидание завершения активных соединений...");
            var all = Task.WhenAll(_tasks.Keys.ToArray());
            await Task.WhenAny(all, Task.Delay(TimeSpan.FromSeconds(5))).ConfigureAwait(false);
        }
    }

    private bool TryAcquireIp(IPAddress ip)
    {
        lock (_perIp)
        {
            _perIp.TryGetValue(ip, out int n);
            if (n >= _opt.MaxPerIp) return false;
            _perIp[ip] = n + 1;
            return true;
        }
    }

    private void ReleaseIp(IPAddress ip)
    {
        lock (_perIp)
        {
            if (!_perIp.TryGetValue(ip, out int n)) return;
            if (n <= 1) _perIp.Remove(ip); else _perIp[ip] = n - 1;
        }
    }

    // ------------------------------------------------------------------ соединение

    private async Task HandleAsync(UdpStream session, IPAddress ip, string remote, CancellationToken shutdown)
    {
        try
        {
            using (session)
            {
                Stream stream = session;
                SecureChannel? channel = null;
                string user = "";
                try
                {
                    if (!AllowHandshake(ip))
                    {
                        Log.WarnThrottled(5, "hs-budget", $"{remote}: отклонён — слишком частые попытки handshake.");
                        return;
                    }

                    using (var hs = CancellationTokenSource.CreateLinkedTokenSource(shutdown))
                    {
                        hs.CancelAfter(Proto.HandshakeTimeout);
                        try
                        {
                            (channel, user) = await HandshakeAsync(stream, remote, hs.Token).ConfigureAwait(false);
                        }
                        catch (OperationCanceledException) when (!shutdown.IsCancellationRequested)
                        {
                            throw new TimeoutException($"Таймаут handshake ({Proto.HandshakeTimeout.TotalSeconds:0} с).");
                        }
                    }

                    if (channel is null) return; // регистрация завершена
                    using (channel)
                    {
                        Log.Info($"{remote}: пользователь '{user}' аутентифицирован, канал AES-256-GCM установлен.");
                        await SessionAsync(channel, user, remote, shutdown).ConfigureAwait(false);
                    }
                }
                catch (ProtocolException ex)
                {
                    Log.WarnThrottled(5, "proto:" + ex.Message, $"{remote}: нарушение протокола: {ex.Message}");
                    await TrySendPlainErrorAsync(stream, ex.Message).ConfigureAwait(false);
                }
                catch (TimeoutException ex)
                {
                    Log.WarnThrottled(5, "timeout:" + ex.Message, $"{remote}: {ex.Message}");
                }
                catch (EndOfStreamException)
                {
                    Log.Info($"{remote}: соединение закрыто клиентом.");
                }
                catch (OperationCanceledException)
                {
                    // остановка сервера
                }
                catch (IOException ex)
                {
                    Log.WarnThrottled(5, "io:" + ex.Message, $"{remote}: ошибка ввода-вывода: {ex.Message}");
                }
                catch (Exception ex)
                {
                    Log.Error($"{remote}: внутренняя ошибка: {ex}");
                    await TrySendPlainErrorAsync(stream, "Внутренняя ошибка сервера.").ConfigureAwait(false);
                }
            }
        }
        catch (Exception ex)
        {
            Log.Error($"{remote}: {ex.Message}");
        }
        finally
        {
            ReleaseIp(ip);
            _slots.Release();
        }
    }

    private static async Task TrySendPlainErrorAsync(Stream s, string text)
    {
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            byte[] msg = Encoding.UTF8.GetBytes(text.Length > 500 ? text[..500] : text);
            await Proto.SendPlainAsync(s, MsgType.Error, msg, cts.Token).ConfigureAwait(false);
        }
        catch { /* best effort */ }
    }

    // ------------------------------------------------------------------ handshake

    private async Task<(SecureChannel? Channel, string User)> HandshakeAsync(Stream s, string remote, CancellationToken ct)
    {
        PlainMsg first = await Proto.ReadPlainAsync(s, ct).ConfigureAwait(false);
        if (first.Type == MsgType.Register)
        {
            await HandleRegisterAsync(s, first.Payload, remote, ct).ConfigureAwait(false);
            return (null, "");
        }
        if (first.Type != MsgType.Hello)
            throw new ProtocolException("Ожидалось REGISTER или HELLO.");

        using var transcript = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        transcript.AppendData(first.Raw);

        string user = Proto.Utf8(first.Payload);
        if (!Validation.IsValidUserName(user)) throw new ProtocolException("Недопустимое имя пользователя.");

        // Незарегистрированное имя обрабатывается тем же путём: CHALLENGE, ожидание подписи,
        // проверка по приманочному ключу. Наружу это неотличимо от неверной подписи.
        byte[]? storedSpki = await LoadUserKeyAsync(user, ct).ConfigureAwait(false);
        using RSA clientPub = Proto.ImportPublicKey(storedSpki ?? _decoySpki);

        // Каждый handshake получает свежий 256-битный challenge из CSPRNG; значение между сессиями не переиспользуется.
        byte[] challenge = RandomNumberGenerator.GetBytes(Proto.ChallengeSize);
        byte[] raw = await Proto.SendPlainAsync(s, MsgType.Challenge, Proto.Concat(challenge, _serverSpki), ct)
            .ConfigureAwait(false);
        transcript.AppendData(raw);

        PlainMsg auth = await Proto.ReadPlainAsync(s, ct).ConfigureAwait(false);
        if (auth.Type != MsgType.AuthResponse) throw new ProtocolException("Ожидался AUTH_RESPONSE.");
        transcript.AppendData(auth.Raw);
        if (auth.Payload.Length != Proto.RsaBits / 8 || !Proto.VerifyPss(clientPub, challenge, auth.Payload))
        {
            Log.WarnThrottled(10, "auth-fail", $"{remote}: неверная подпись challenge.");
            throw new ProtocolException("Аутентификация не пройдена.");
        }

        PlainMsg kx = await Proto.ReadPlainAsync(s, ct).ConfigureAwait(false);
        if (kx.Type != MsgType.KeyExchange) throw new ProtocolException("Ожидался KEY_EXCHANGE.");
        transcript.AppendData(kx.Raw);
        if (kx.Payload.Length != Proto.RsaBits / 8) throw new ProtocolException("Неверный размер KEY_EXCHANGE.");

        byte[] premaster;
        try { premaster = Proto.OaepDecrypt(_serverKey, kx.Payload); }
        catch (CryptographicException) { throw new ProtocolException("Не удалось расшифровать premaster_secret."); }
        if (premaster.Length != Proto.PremasterSize)
        {
            CryptographicOperations.ZeroMemory(premaster);
            throw new ProtocolException("Неверный размер premaster_secret.");
        }

        var (key, clientPrefix, serverPrefix) = Proto.DeriveKeys(premaster, challenge);
        CryptographicOperations.ZeroMemory(premaster);
        byte[] th = transcript.GetHashAndReset();

        if (s is UdpStream transport) transport.EnableAuthentication(Proto.TransportKey(key));

        // Сервер: отправляет с префиксом сервера, принимает с префиксом клиента.
        var channel = new SecureChannel(s, key, serverPrefix, clientPrefix);
        try
        {
            var (type, payload) = await channel.ReceiveAsync(ct).ConfigureAwait(false);
            if (type != MsgType.Finished || payload.Length != Proto.RsaBits / 8 ||
                !Proto.VerifyPss(clientPub, Proto.ClientFinishedData(th), payload))
                throw new ProtocolException("Неверное сообщение Finished от клиента.");

            await channel.SendAsync(MsgType.Finished, Proto.ServerFinishedMac(key, th), ct).ConfigureAwait(false);
        }
        catch
        {
            channel.Dispose();
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
        return (channel, user);
    }

    private string UserPath(string user) => Path.Combine(_usersDir, "u_" + user + ".pub");

    private async Task<byte[]?> LoadUserKeyAsync(string user, CancellationToken ct)
    {
        string path = UserPath(user);
        if (!File.Exists(path)) return null;
        return await File.ReadAllBytesAsync(path, ct).ConfigureAwait(false);
    }

    /// <summary>REGISTER: [1 ulen][user][1 tlen][token][SPKI DER].</summary>
    private async Task HandleRegisterAsync(Stream s, byte[] p, string remote, CancellationToken ct)
    {
        int o = 0;
        if (p.Length < 3) throw new ProtocolException("Некорректное сообщение REGISTER.");
        int ul = p[o++];
        if (o + ul + 1 > p.Length) throw new ProtocolException("Некорректное сообщение REGISTER.");
        string user = Proto.Utf8(p.AsSpan(o, ul)); o += ul;
        int tl = p[o++];
        if (o + tl > p.Length) throw new ProtocolException("Некорректное сообщение REGISTER.");
        byte[] token = p.AsSpan(o, tl).ToArray(); o += tl;
        byte[] spki = p.AsSpan(o).ToArray();

        if (!Validation.IsValidUserName(user)) throw new ProtocolException("Недопустимое имя пользователя.");
        if (_opt.RegisterToken is not null)
        {
            byte[] a = SHA256.HashData(token);
            byte[] b = SHA256.HashData(Encoding.UTF8.GetBytes(_opt.RegisterToken));
            if (!CryptographicOperations.FixedTimeEquals(a, b))
                throw new ProtocolException("Неверный токен регистрации.");
        }
        else if (!_opt.OpenRegistration)
        {
            throw new ProtocolException(
                "Регистрация отключена. Задайте --reg-token на сервере или запустите с --open-registration.");
        }

        using RSA pub = Proto.ImportPublicKey(spki);
        byte[] canonical = pub.ExportSubjectPublicKeyInfo();
        string path = UserPath(user);

        await _registerLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (File.Exists(path)) throw new ProtocolException("Пользователь уже существует.");
            if (Directory.EnumerateFiles(_usersDir).Count() >= _opt.MaxUsers)
                throw new ProtocolException("Достигнут лимит зарегистрированных пользователей.");

            string tmp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try
            {
                await File.WriteAllBytesAsync(tmp, canonical, ct).ConfigureAwait(false);
                File.Move(tmp, path, false);
            }
            catch
            {
                try { File.Delete(tmp); } catch { /* ignore */ }
                throw;
            }
        }
        finally
        {
            _registerLock.Release();
        }

        Log.Info($"{remote}: зарегистрирован пользователь '{user}' (отпечаток {Proto.Hex(Proto.Sha256(canonical))[..16]}…).");
        await Proto.SendPlainAsync(s, MsgType.RegisterOk, ReadOnlyMemory<byte>.Empty, ct).ConfigureAwait(false);
    }

    // ------------------------------------------------------------------ передача файлов

    private async Task SessionAsync(SecureChannel ch, string user, string remote, CancellationToken ct)
    {
        string userDir = Path.Combine(_receivedDir, user);
        Directory.CreateDirectory(userDir);
        FileReceiver? current = null;
        long lastAcked = 0;

        try
        {
            while (true)
            {
                MsgType type;
                byte[] payload;
                try
                {
                    (type, payload) = await ch.ReceiveAsync(Proto.IdleTimeout, ct).ConfigureAwait(false);
                }
                catch (EndOfStreamException)
                {
                    if (current is not null) Log.Warn($"{remote}: клиент отключился посреди передачи файла; partial сохранён.");
                    else Log.Info($"{remote}: сессия завершена.");
                    return;
                }

                switch (type)
                {
                    case MsgType.FileMeta:
                    {
                        if (current is not null) throw new ProtocolException("FILE_META во время передачи другого файла.");
                        FileMetaDto? meta;
                        try { meta = JsonSerializer.Deserialize<FileMetaDto>(payload); }
                        catch (JsonException) { throw new ProtocolException("Некорректный JSON метаданных."); }
                        if (meta is null) throw new ProtocolException("Пустые метаданные файла.");

                        try
                        {
                            if (!TakeToken(_fileMeta, user, FileMetaPerMinute, FileMetaBurst))
                                throw new ProtocolException("Слишком частые FILE_META, повторите позже.");

                            current = await FileReceiver.OpenAsync(userDir, meta, _opt.MaxFileSize, ct).ConfigureAwait(false);
                        }
                        catch (IOException)
                        {
                            throw new ProtocolException("Не удалось открыть partial-файл (возможно, эта передача уже выполняется).");
                        }

                        Log.Info($"{remote}: приём файла '{current.FileName}' ({meta.Size} байт) от '{user}', смещение {current.Received}.");
                        await ch.SendAsync(MsgType.FileAck, Proto.EncodeOffset(current.Received), ct).ConfigureAwait(false);
                        lastAcked = current.Received;
                        break;
                    }
                    case MsgType.FileChunk:
                    {
                        if (current is null) throw new ProtocolException("FILE_CHUNK без FILE_META.");
                        if (payload.Length == 0) throw new ProtocolException("Пустой FILE_CHUNK.");

                        await current.WriteAsync(payload, ct).ConfigureAwait(false);
                        if (current.Received - lastAcked >= Proto.AckIntervalBytes)
                        {
                            await current.FlushForAckAsync(ct).ConfigureAwait(false);
                            await ch.SendAsync(MsgType.FileAck, Proto.EncodeOffset(current.Received), ct).ConfigureAwait(false);
                            lastAcked = current.Received;
                        }
                        break;
                    }
                    case MsgType.FileEof:
                    {
                        if (current is null) throw new ProtocolException("EOF без FILE_META.");
                        if (payload.Length != 0) throw new ProtocolException("FILE_EOF должен быть пустым.");

                        string hash = await current.CompleteAsync(ct).ConfigureAwait(false);
                        var result = new ResultDto
                        {
                            Ok = true,
                            Name = current.FileName,
                            Size = current.Received,
                            Sha256 = hash
                        };
                        Log.Info($"{remote}: файл '{current.FileName}' принят, SHA-256 совпал: {hash}");
                        current.Dispose();
                        current = null;
                        lastAcked = 0;
                        await ch.SendAsync(MsgType.Result, JsonSerializer.SerializeToUtf8Bytes(result), ct).ConfigureAwait(false);
                        break;
                    }
                    default:
                        throw new ProtocolException($"Неожиданный тип сообщения 0x{(byte)type:X2}.");
                }
            }
        }
        catch (ProtocolException ex)
        {
            current?.Discard();
            current = null;
            Log.Warn($"{remote}: {ex.Message}");
            try
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                await ch.SendAsync(MsgType.AppError, Encoding.UTF8.GetBytes(ex.Message), cts.Token).ConfigureAwait(false);
            }
            catch { /* best effort */ }
        }
        finally
        {
            current?.Dispose(); // при обрыве/таймауте незавершённый partial сохраняется
        }
    }

    public void Dispose()
    {
        _serverKey.Dispose();
        _decoyKey.Dispose();
        _slots.Dispose();
        _registerLock.Dispose();
    }
}

/// <summary>
/// Приём одного файла. Детерминированный .part переживает разрыв; при resume префикс перечитывается
/// для восстановления состояния IncrementalHash. Каждый FILE_ACK отправляется только после Flush(true).
/// </summary>
internal sealed class FileReceiver : IDisposable
{
    private readonly FileStream _fs;
    private readonly IncrementalHash _hash;
    private readonly string _tmpPath;
    private readonly string _finalPath;
    private readonly long _expectedSize;
    private readonly byte[] _expectedHash;
    private bool _completed;
    private bool _streamClosed;
    private bool _hashDisposed;
    private bool _hashStashed;

    // Кэш состояния SHA-256 по пути .part: убирает повторное чтение файла при resume.
    private const int MaxCachedHashes = 256;
    private const long CacheTtlMs = 30 * 60 * 1000;
    private static readonly ConcurrentDictionary<string, CachedHash> Resumable = new();
    private readonly record struct CachedHash(long Length, IncrementalHash Hash, long Touched);

    private static void SweepCache()
    {
        long now = Environment.TickCount64;
        foreach (KeyValuePair<string, CachedHash> kv in Resumable)
        {
            if (now - kv.Value.Touched <= CacheTtlMs && Resumable.Count <= MaxCachedHashes) continue;
            if (Resumable.TryRemove(kv.Key, out CachedHash stale)) stale.Hash.Dispose();
        }
    }

    public string FileName { get; }
    public long Received { get; private set; }

    private FileReceiver(
        string tmp, string final, string name, long size, byte[] expectedHash,
        FileStream fs, IncrementalHash hash, long received)
    {
        _tmpPath = tmp;
        _finalPath = final;
        FileName = name;
        _expectedSize = size;
        _expectedHash = expectedHash;
        _fs = fs;
        _hash = hash;
        Received = received;
    }

    public static async Task<FileReceiver> OpenAsync(
        string userDir, FileMetaDto meta, long maxSize, CancellationToken ct)
    {
        string name = Validation.ValidateFileName(meta.Name);
        if (meta.Size < 0) throw new ProtocolException("Отрицательный размер файла.");
        if (meta.Size > maxSize) throw new ProtocolException($"Файл превышает лимит сервера ({maxSize} байт).");
        if (string.IsNullOrEmpty(meta.Sha256) || meta.Sha256.Length != 64)
            throw new ProtocolException("Некорректный SHA-256.");

        byte[] expected;
        try { expected = Convert.FromHexString(meta.Sha256); }
        catch (FormatException) { throw new ProtocolException("Некорректный SHA-256."); }

        Directory.CreateDirectory(userDir);
        string final = Path.Combine(userDir, name);
        string identity = name + "\n" + meta.Size.ToString(CultureInfo.InvariantCulture) + "\n" + Proto.Hex(expected);
        string id = Proto.Hex(SHA256.HashData(Encoding.UTF8.GetBytes(identity)));
        string tmp = Path.Combine(userDir, ".wer-" + id + ".part");

        IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        bool restored = false;
        FileStream? fs = null;
        try
        {
            var options = new FileStreamOptions
            {
                Mode = FileMode.OpenOrCreate,
                Access = FileAccess.ReadWrite,
                Share = FileShare.None,
                Options = FileOptions.Asynchronous | FileOptions.SequentialScan,
                BufferSize = 1 << 16
            };
            if (!OperatingSystem.IsWindows())
                options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;

            var stream = new FileStream(tmp, options);
            fs = stream;
            if (stream.Length > meta.Size) stream.SetLength(0);
            long received = stream.Length;

            // Состояние хэша держим в памяти: повторный FILE_META по тому же partial не перечитывает файл.
            if (Resumable.TryRemove(tmp, out CachedHash cached))
            {
                if (cached.Length == received)
                {
                    hash.Dispose();
                    hash = cached.Hash;
                    restored = true;
                }
                else
                {
                    cached.Hash.Dispose();
                }
            }

            if (!restored)
            {
                // IncrementalHash не сериализуем: пересчитываем уже сохранённый префикс.
                stream.Position = 0;
                byte[] buffer = new byte[1 << 16];
                long remaining = received;
                while (remaining > 0)
                {
                    int want = (int)Math.Min((long)buffer.Length, remaining);
                    int n = await stream.ReadAsync(buffer.AsMemory(0, want), ct).ConfigureAwait(false);
                    if (n == 0) throw new EndOfStreamException("Partial-файл неожиданно укоротился.");
                    hash.AppendData(buffer.AsSpan(0, n));
                    remaining -= n;
                }
            }

            stream.Position = received;
            return new FileReceiver(tmp, final, name, meta.Size, expected, stream, hash, received);
        }
        catch
        {
            hash.Dispose();
            if (fs is not null) await fs.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    public async Task WriteAsync(byte[] data, CancellationToken ct)
    {
        if (data.Length == 0) throw new ProtocolException("Пустой FILE_CHUNK.");
        if (data.LongLength > _expectedSize - Received)
            throw new ProtocolException("Получено больше данных, чем заявлено в метаданных.");

        await _fs.WriteAsync(data, ct).ConfigureAwait(false);
        _hash.AppendData(data);
        Received += data.LongLength;
    }

    public async Task FlushForAckAsync(CancellationToken ct)
    {
        await _fs.FlushAsync(ct).ConfigureAwait(false);
        _fs.Flush(flushToDisk: true);
    }

    public async Task<string> CompleteAsync(CancellationToken ct)
    {
        if (Received != _expectedSize)
        {
            long received = Received;
            Discard();
            throw new ProtocolException($"Размер не совпадает: получено {received}, заявлено {_expectedSize}.");
        }

        await _fs.FlushAsync(ct).ConfigureAwait(false);
        _fs.Flush(flushToDisk: true);
        byte[] actual = _hash.GetHashAndReset();
        if (!CryptographicOperations.FixedTimeEquals(actual, _expectedHash))
        {
            Discard();
            throw new ProtocolException("SHA-256 файла не совпадает с заявленным.");
        }

        await _fs.DisposeAsync().ConfigureAwait(false);
        _streamClosed = true;
        File.Move(_tmpPath, _finalPath, true);
        _completed = true;
        Resumable.TryRemove(_tmpPath, out _);
        DisposeHash();
        return Proto.Hex(actual);
    }

    /// <summary>Закрывает дескрипторы, но сохраняет .part для следующего подключения.</summary>
    public void Dispose()
    {
        StashHash();
        CloseStream();
    }

    /// <summary>Удаляет partial, если передача признана некорректной.</summary>
    public void Discard()
    {
        if (_completed) return;
        if (Resumable.TryRemove(_tmpPath, out _)) _hashStashed = false;
        DisposeHash();
        try { CloseStream(); } catch { /* best effort */ }
        try { File.Delete(_tmpPath); } catch { /* best effort */ }
    }

    /// <summary>Кладёт состояние хэша в кэш, чтобы resume не перечитывал файл.</summary>
    private void StashHash()
    {
        if (_hashDisposed || _hashStashed) return;
        if (_completed)
        {
            DisposeHash();
            return;
        }

        _hashStashed = true;
        SweepCache();
        Resumable[_tmpPath] = new CachedHash(Received, _hash, Environment.TickCount64);
    }

    private void DisposeHash()
    {
        if (_hashDisposed) return;
        _hashDisposed = true;
        if (!_hashStashed) _hash.Dispose();
    }

    private void CloseStream()
    {
        if (_streamClosed) return;
        _streamClosed = true;
        _fs.Dispose();
    }
}
