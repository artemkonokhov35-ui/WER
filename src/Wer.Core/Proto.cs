// WER v22.0 — протокол, фрейминг, HKDF, RSA-хелперы и AES-256-GCM SecureChannel.
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Wer;

/// <summary>0x01..0x1F — plaintext handshake; 0x20..0x3F — внутри AES-GCM-фреймов.</summary>
public enum MsgType : byte
{
    // клиент -> сервер (plaintext handshake)
    Register = 0x01,      // [1 ulen][user][1 tlen][token][SPKI DER публичного ключа RSA-3072]
    Hello = 0x02,         // [user]
    AuthResponse = 0x03,  // [RSA-PSS подпись challenge]
    KeyExchange = 0x04,   // [RSA-OAEP(premaster)]

    // сервер -> клиент (plaintext handshake)
    Challenge = 0x11,     // [32 байта challenge][SPKI DER публичного ключа сервера]
    RegisterOk = 0x12,    // []
    Error = 0x1F,         // [utf8 текст]

    // внутри зашифрованных фреймов
    Finished = 0x20,      // клиент: RSA-PSS транскрипта; сервер: HMAC-SHA256 транскрипта
    FileMeta = 0x30,      // JSON {"name","size","sha256"}
    FileChunk = 0x31,     // бинарные данные
    FileEof = 0x32,       // конец файла
    Result = 0x33,        // сервер -> клиент: JSON результат
    FileAck = 0x34,       // сервер -> клиент: [8 байт uint64 BE — сохранённое смещение]
    AppError = 0x3F       // utf8 текст ошибки
}

public sealed class ProtocolException : Exception
{
    public ProtocolException(string message) : base(message) { }
}

public readonly record struct PlainMsg(MsgType Type, byte[] Payload, byte[] Raw);

public static class Proto
{
    public const int RsaBits = 3072;
    public const int ChallengeSize = 32;
    public const int PremasterSize = 32;
    public const int KeySize = 32;
    public const int PrefixSize = 4;
    public const int NonceSize = 12;
    public const int TagSize = 16;
    public const int ChunkSize = 64 * 1024;
    public const int MaxHandshakeMsg = 4096;
    public const int LengthHeader = 4;
    public const int AckOffsetSize = 8;
    public const long AckIntervalBytes = 1L << 20; // 1 МиБ

    // plaintext внутри фрейма: [1 байт типа][payload]
    public const int MaxPlaintext = 1 + ChunkSize;
    // тело фрейма после length: nonce + ciphertext + tag
    public const int MaxFrameBody = NonceSize + MaxPlaintext + TagSize;
    public const int MinFrameBody = NonceSize + 1 + TagSize;

    public static readonly TimeSpan HandshakeTimeout = TimeSpan.FromSeconds(5);
    public static readonly TimeSpan IdleTimeout = TimeSpan.FromSeconds(60);
    public static readonly TimeSpan AckTimeout = TimeSpan.FromMinutes(5);

    public static readonly byte[] KdfInfo = Encoding.ASCII.GetBytes("WER v22.0 key expansion");
    private static readonly byte[] ClientFinishedLabel = Encoding.ASCII.GetBytes("WER v22.0 client finished");
    private static readonly byte[] ServerFinishedLabel = Encoding.ASCII.GetBytes("WER v22.0 server finished");
    private static readonly byte[] TransportMacLabel = Encoding.ASCII.GetBytes("WER v22.2 transport mac");

    // ---------- Асинхронный ввод/вывод ----------

    public static async Task ReadExactAsync(Stream s, Memory<byte> buffer, CancellationToken ct)
    {
        int off = 0;
        while (off < buffer.Length)
        {
            int n = await s.ReadAsync(buffer.Slice(off), ct).ConfigureAwait(false);
            if (n == 0) throw new EndOfStreamException("Соединение закрыто удалённой стороной.");
            off += n;
        }
    }

    /// <summary>Открытое handshake-сообщение: [4 BE длина][1 тип][payload].</summary>
    public static async Task<byte[]> SendPlainAsync(Stream s, MsgType type, ReadOnlyMemory<byte> payload, CancellationToken ct)
    {
        int bodyLen = 1 + payload.Length;
        if (bodyLen > MaxHandshakeMsg) throw new ProtocolException("Handshake-сообщение слишком велико.");
        var buf = new byte[LengthHeader + bodyLen];
        BinaryPrimitives.WriteUInt32BigEndian(buf, (uint)bodyLen);
        buf[LengthHeader] = (byte)type;
        payload.CopyTo(buf.AsMemory(LengthHeader + 1));
        await s.WriteAsync(buf, ct).ConfigureAwait(false);
        await s.FlushAsync(ct).ConfigureAwait(false);
        return buf.AsSpan(LengthHeader).ToArray();
    }

    /// <summary>Возвращает сырые байты (тип+payload) для handshake-транскрипта.</summary>
    public static async Task<PlainMsg> ReadPlainAsync(Stream s, CancellationToken ct)
    {
        var hdr = new byte[LengthHeader];
        await ReadExactAsync(s, hdr, ct).ConfigureAwait(false);
        uint len = BinaryPrimitives.ReadUInt32BigEndian(hdr);
        if (len < 1 || len > MaxHandshakeMsg)
            throw new ProtocolException("Недопустимая длина handshake-сообщения.");
        var body = new byte[(int)len];
        await ReadExactAsync(s, body, ct).ConfigureAwait(false);
        return new PlainMsg((MsgType)body[0], body.AsSpan(1).ToArray(), body);
    }

    // ---------- Криптография ----------

    public static byte[] Sha256(ReadOnlySpan<byte> data) => SHA256.HashData(data);

    public static string Hex(ReadOnlySpan<byte> data) => Convert.ToHexString(data).ToLowerInvariant();

    /// <summary>HKDF-SHA256 (salt = challenge) -> [32 ключ AES][4 префикс клиента][4 префикс сервера].</summary>
    public static (byte[] Key, byte[] ClientPrefix, byte[] ServerPrefix) DeriveKeys(byte[] premaster, byte[] challenge)
    {
        byte[] okm = HKDF.DeriveKey(HashAlgorithmName.SHA256, premaster, KeySize + 2 * PrefixSize, challenge, KdfInfo);
        try
        {
            return (okm.AsSpan(0, KeySize).ToArray(),
                    okm.AsSpan(KeySize, PrefixSize).ToArray(),
                    okm.AsSpan(KeySize + PrefixSize, PrefixSize).ToArray());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(okm);
        }
    }

    /// <summary>Отдельный ключ для HMAC на транспортных пакетах — выводится из сессионного ключа.</summary>
    public static byte[] TransportKey(byte[] sessionKey) =>
        HKDF.DeriveKey(HashAlgorithmName.SHA256, sessionKey, KeySize, null, TransportMacLabel);

    public static byte[] SignPss(RSA key, ReadOnlySpan<byte> data) =>
        key.SignData(data.ToArray(), HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

    public static bool VerifyPss(RSA key, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        try { return key.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss); }
        catch (CryptographicException) { return false; }
    }

    public static byte[] OaepEncrypt(RSA serverPub, byte[] data) => serverPub.Encrypt(data, RSAEncryptionPadding.OaepSHA256);

    public static byte[] OaepDecrypt(RSA serverPriv, byte[] data) => serverPriv.Decrypt(data, RSAEncryptionPadding.OaepSHA256);

    public static byte[] ClientFinishedData(byte[] transcriptHash) => Concat(ClientFinishedLabel, transcriptHash);

    public static byte[] ServerFinishedMac(byte[] key, byte[] transcriptHash) =>
        HMACSHA256.HashData(key, Concat(ServerFinishedLabel, transcriptHash));

    public static byte[] EncodeOffset(long offset)
    {
        if (offset < 0) throw new ArgumentOutOfRangeException(nameof(offset));
        var payload = new byte[AckOffsetSize];
        BinaryPrimitives.WriteUInt64BigEndian(payload, (ulong)offset);
        return payload;
    }

    public static long DecodeOffset(ReadOnlySpan<byte> payload)
    {
        if (payload.Length != AckOffsetSize)
            throw new ProtocolException("Некорректная длина FILE_ACK.");
        ulong value = BinaryPrimitives.ReadUInt64BigEndian(payload);
        if (value > long.MaxValue)
            throw new ProtocolException("Смещение FILE_ACK слишком велико.");
        return (long)value;
    }

    public static byte[] Concat(params byte[][] parts)
    {
        int total = 0;
        foreach (var p in parts) total = checked(total + p.Length);
        var r = new byte[total];
        int o = 0;
        foreach (var p in parts) { Buffer.BlockCopy(p, 0, r, o, p.Length); o += p.Length; }
        return r;
    }

    /// <summary>Разбор RSA-3072 SubjectPublicKeyInfo DER.</summary>
    public static RSA ImportPublicKey(ReadOnlySpan<byte> spki)
    {
        var rsa = RSA.Create();
        try
        {
            rsa.ImportSubjectPublicKeyInfo(spki, out int read);
            if (read != spki.Length) throw new ProtocolException("Лишние данные после публичного ключа.");
            if (rsa.KeySize != RsaBits) throw new ProtocolException($"Требуется RSA-{RsaBits}.");
            return rsa;
        }
        catch (CryptographicException)
        {
            rsa.Dispose();
            throw new ProtocolException("Некорректный публичный ключ.");
        }
        catch
        {
            rsa.Dispose();
            throw;
        }
    }

    public static string Utf8(ReadOnlySpan<byte> b) => Encoding.UTF8.GetString(b);
}

/// <summary>
/// AES-GCM-фрейм: [4 байта длины][12 nonce = 4 prefix + 8 counter BE][ciphertext][16 tag].
/// Length входит в AAD; получатель строго проверяет nonce и счётчик направления.
/// </summary>
public sealed class SecureChannel : IDisposable
{
    private readonly Stream _stream;
    private readonly AesGcm _aes;
    private readonly byte[] _sendPrefix;
    private readonly byte[] _recvPrefix;
    private ulong _sendCounter;
    private ulong _recvCounter;

    public SecureChannel(Stream stream, byte[] key, byte[] sendPrefix, byte[] recvPrefix)
    {
        if (key.Length != Proto.KeySize || sendPrefix.Length != Proto.PrefixSize || recvPrefix.Length != Proto.PrefixSize)
            throw new ArgumentException("Некорректные размеры ключа или nonce-префиксов.");
        _stream = stream;
        _aes = new AesGcm(key, Proto.TagSize);
        _sendPrefix = sendPrefix.ToArray();
        _recvPrefix = recvPrefix.ToArray();
    }

    private static void BuildNonce(Span<byte> nonce, byte[] prefix, ulong counter)
    {
        prefix.AsSpan().CopyTo(nonce);
        BinaryPrimitives.WriteUInt64BigEndian(nonce.Slice(Proto.PrefixSize), counter);
    }

    public async Task SendAsync(MsgType type, ReadOnlyMemory<byte> payload, CancellationToken ct)
    {
        int plainLen = 1 + payload.Length;
        if (plainLen > Proto.MaxPlaintext) throw new ProtocolException("Payload слишком велик для одного фрейма.");
        if (_sendCounter == ulong.MaxValue) throw new ProtocolException("Счётчик nonce исчерпан.");

        int bodyLen = Proto.NonceSize + plainLen + Proto.TagSize;
        var frame = new byte[Proto.LengthHeader + bodyLen];
        BinaryPrimitives.WriteUInt32BigEndian(frame, (uint)bodyLen);

        var plain = new byte[plainLen];
        plain[0] = (byte)type;
        payload.Span.CopyTo(plain.AsSpan(1));

        BuildNonce(frame.AsSpan(Proto.LengthHeader, Proto.NonceSize), _sendPrefix, _sendCounter);
        _sendCounter++; // nonce не используется повторно даже при ошибке отправки

        int cipherOffset = Proto.LengthHeader + Proto.NonceSize;
        _aes.Encrypt(
            frame.AsSpan(Proto.LengthHeader, Proto.NonceSize),
            plain,
            frame.AsSpan(cipherOffset, plainLen),
            frame.AsSpan(cipherOffset + plainLen, Proto.TagSize),
            frame.AsSpan(0, Proto.LengthHeader));

        await _stream.WriteAsync(frame, ct).ConfigureAwait(false);
        await _stream.FlushAsync(ct).ConfigureAwait(false);
    }

    public async Task<(MsgType Type, byte[] Payload)> ReceiveAsync(TimeSpan timeout, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        try { return await ReceiveAsync(cts.Token).ConfigureAwait(false); }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new TimeoutException("Таймаут ожидания данных от собеседника.");
        }
    }

    public async Task<(MsgType Type, byte[] Payload)> ReceiveAsync(CancellationToken ct)
    {
        if (_recvCounter == ulong.MaxValue) throw new ProtocolException("Счётчик nonce исчерпан.");
        var hdr = new byte[Proto.LengthHeader];
        await Proto.ReadExactAsync(_stream, hdr, ct).ConfigureAwait(false);
        uint len = BinaryPrimitives.ReadUInt32BigEndian(hdr);
        if (len < Proto.MinFrameBody || len > Proto.MaxFrameBody)
            throw new ProtocolException("Недопустимая длина фрейма.");

        var body = new byte[(int)len];
        await Proto.ReadExactAsync(_stream, body, ct).ConfigureAwait(false);

        var expected = new byte[Proto.NonceSize];
        BuildNonce(expected, _recvPrefix, _recvCounter);
        if (!CryptographicOperations.FixedTimeEquals(body.AsSpan(0, Proto.NonceSize), expected))
            throw new ProtocolException("Неверный nonce (replay / нарушение порядка фреймов).");

        int plainLen = (int)len - Proto.NonceSize - Proto.TagSize;
        var plain = new byte[plainLen];
        try
        {
            _aes.Decrypt(
                body.AsSpan(0, Proto.NonceSize),
                body.AsSpan(Proto.NonceSize, plainLen),
                body.AsSpan(Proto.NonceSize + plainLen, Proto.TagSize),
                plain,
                hdr);
        }
        catch (CryptographicException)
        {
            throw new ProtocolException("Ошибка аутентификации фрейма (неверный тег GCM).");
        }

        _recvCounter++;
        return ((MsgType)plain[0], plain.AsSpan(1).ToArray());
    }

    public void Dispose() => _aes.Dispose();
}
