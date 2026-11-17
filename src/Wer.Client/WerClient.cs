// WER v22.0-UDP — асинхронный клиент: регистрация и возобновляемая отправка файла поверх UDP.
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Wer;

public static class WerClient
{
    public static string DefaultHome() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".wer");

    private static string KeyPath(string home, string user) => Path.Combine(home, "wer_" + user + ".key.pem");

    private static string? KeyPassword => Environment.GetEnvironmentVariable("WER_KEY_PASSWORD");

    // ------------------------------------------------------------------ REGISTER

    public static async Task RegisterAsync(string host, int port, string user, string home, string token, CancellationToken ct)
    {
        if (!Validation.IsValidUserName(user))
            throw new ArgumentException("Имя пользователя: 1-32 символа [A-Za-z0-9_.-], первый — буква или цифра.");
        byte[] tokenBytes = Encoding.UTF8.GetBytes(token);
        if (tokenBytes.Length > 255) throw new ArgumentException("Токен регистрации слишком длинный (макс. 255 байт).");

        Directory.CreateDirectory(home);
        string keyPath = KeyPath(home, user);
        Console.WriteLine(File.Exists(keyPath)
            ? $"Используется существующий приватный ключ: {keyPath}"
            : $"Генерация RSA-{Proto.RsaBits} ключа (несколько секунд)...");
        using RSA key = KeyStore.LoadOrCreate(keyPath, KeyPassword, out bool created);
        if (created) Console.WriteLine($"Приватный ключ сохранён: {keyPath} (храните его в секрете!)");

        byte[] spki = key.ExportSubjectPublicKeyInfo();
        byte[] userBytes = Encoding.UTF8.GetBytes(user);
        byte[] payload = Proto.Concat(
            new[] { (byte)userBytes.Length }, userBytes,
            new[] { (byte)tokenBytes.Length }, tokenBytes,
            spki);

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(Proto.HandshakeTimeout + TimeSpan.FromSeconds(2));
        try
        {
            await using UdpStream s = await UdpStream.ConnectAsync(host, port, cts.Token).ConfigureAwait(false);
            await Proto.SendPlainAsync(s, MsgType.Register, payload, cts.Token).ConfigureAwait(false);
            PlainMsg resp = await Proto.ReadPlainAsync(s, cts.Token).ConfigureAwait(false);
            ThrowIfServerError(resp);
            if (resp.Type != MsgType.RegisterOk) throw new ProtocolException("Неожиданный ответ сервера на REGISTER.");
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new TimeoutException("Таймаут регистрации (10 с).");
        }
        Console.WriteLine($"Пользователь '{user}' успешно зарегистрирован. Отпечаток вашего ключа: {Proto.Hex(Proto.Sha256(spki))}");
    }

    // ------------------------------------------------------------------ SEND FILE

    public static async Task SendFileAsync(string host, int port, string user, string filePath, string home, string? pin, CancellationToken ct)
    {
        if (!Validation.IsValidUserName(user)) throw new ArgumentException("Недопустимое имя пользователя.");
        var info = new FileInfo(filePath);
        if (!info.Exists) throw new FileNotFoundException("Файл не найден.", filePath);
        string name = Validation.ValidateFileName(info.Name);

        string keyPath = KeyPath(home, user);
        if (!File.Exists(keyPath))
            throw new FileNotFoundException($"Приватный ключ не найден ({keyPath}). Сначала выполните: wer register ...");
        using RSA clientKey = KeyStore.LoadOrCreate(keyPath, KeyPassword, out _);

        // Хешируем исходный файл до handshake, затем сервер проверит его при EOF.
        Console.WriteLine("Вычисление SHA-256 файла...");
        byte[] fileHash;
        long size;
        await using (var hs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 16,
                         FileOptions.Asynchronous | FileOptions.SequentialScan))
        {
            size = hs.Length;
            fileHash = await SHA256.HashDataAsync(hs, ct).ConfigureAwait(false);
            if (hs.Length != size) throw new IOException("Файл изменился во время вычисления SHA-256.");
        }
        string hashHex = Proto.Hex(fileHash);

        // UDP-сессия + handshake (общий таймаут 10 секунд).
        UdpStream udp;
        SecureChannel channel;
        using (var hsCts = CancellationTokenSource.CreateLinkedTokenSource(ct))
        {
            hsCts.CancelAfter(Proto.HandshakeTimeout + TimeSpan.FromSeconds(2));
            try
            {
                udp = await UdpStream.ConnectAsync(host, port, hsCts.Token).ConfigureAwait(false);
                string hostKey = $"{host.ToLowerInvariant()}:{port}";
                channel = await HandshakeAsync(udp, user, clientKey, hostKey, home, pin, hsCts.Token)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                throw new TimeoutException($"Таймаут handshake ({Proto.HandshakeTimeout.TotalSeconds:0} с).");
            }
        }

        using (udp)
        using (channel)
        {
            Console.WriteLine("Handshake завершён: канал AES-256-GCM поверх UDP установлен.");
            var meta = new FileMetaDto { Name = name, Size = size, Sha256 = hashHex };

            // Открываем до FILE_META: локальная ошибка не создаст лишний partial на сервере.
            await using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 16,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            if (fs.Length != size) throw new IOException("Файл изменился после вычисления SHA-256.");

            try
            {
                await channel.SendAsync(MsgType.FileMeta, JsonSerializer.SerializeToUtf8Bytes(meta), ct)
                    .ConfigureAwait(false);

                long offset = await ReceiveFileAckAsync(channel, size, expectedOffset: null, ct: ct).ConfigureAwait(false);
                Console.WriteLine($"Продолжение передачи с {offset}/{size} байт.");
                fs.Position = offset;

                var buf = new byte[Proto.ChunkSize];
                long sent = offset, lastReport = offset, sinceAck = 0;
                while (true)
                {
                    int n = await fs.ReadAsync(buf.AsMemory(), ct).ConfigureAwait(false);
                    if (n == 0) break;

                    await channel.SendAsync(MsgType.FileChunk, buf.AsMemory(0, n), ct).ConfigureAwait(false);
                    sent += n;
                    sinceAck += n;

                    if (sinceAck >= Proto.AckIntervalBytes)
                    {
                        // ACK должен подтвердить ровно тот offset, до которого клиент уже отправил данные.
                        await ReceiveFileAckAsync(channel, size, expectedOffset: sent, ct: ct).ConfigureAwait(false);
                        sinceAck = 0;
                    }

                    if (sent - lastReport >= Proto.AckIntervalBytes || sent == size)
                    {
                        lastReport = sent;
                        Console.Write($"\rОтправлено: {sent}/{size} байт ({(size == 0 ? 100 : sent * 100 / size)}%)   ");
                    }
                }
                Console.WriteLine();

                if (sent != size) throw new IOException("Файл изменился во время отправки.");
                await channel.SendAsync(MsgType.FileEof, ReadOnlyMemory<byte>.Empty, ct).ConfigureAwait(false);
            }
            catch (IOException) when (!ct.IsCancellationRequested)
            {
                // Сервер мог закрыть соединение, отправив причину.
                string? reason = await TryReadServerErrorAsync(channel).ConfigureAwait(false);
                if (reason is not null) throw new ProtocolException("Сервер отклонил передачу: " + reason);
                throw;
            }

            var (type, payload) = await channel.ReceiveAsync(Proto.IdleTimeout, ct).ConfigureAwait(false);
            if (type == MsgType.AppError)
                throw new ProtocolException("Сервер отклонил файл: " + Proto.Utf8(payload));
            if (type != MsgType.Result)
                throw new ProtocolException("Неожиданный ответ сервера после EOF.");

            ResultDto? res = JsonSerializer.Deserialize<ResultDto>(payload);
            if (res is null || !res.Ok || res.Size != size ||
                !string.Equals(res.Sha256, hashHex, StringComparison.OrdinalIgnoreCase))
                throw new ProtocolException("Сервер вернул неподтверждённый результат.");

            Console.WriteLine($"Готово: '{res.Name}' ({res.Size} байт) принят сервером, SHA-256 подтверждён: {res.Sha256}");
        }
    }

    private static async Task<long> ReceiveFileAckAsync(
        SecureChannel channel, long fileSize, long? expectedOffset, CancellationToken ct)
    {
        var (type, payload) = await channel.ReceiveAsync(Proto.AckTimeout, ct).ConfigureAwait(false);
        if (type == MsgType.AppError)
            throw new ProtocolException("Сервер отклонил передачу: " + Proto.Utf8(payload));
        if (type != MsgType.FileAck)
            throw new ProtocolException("Ожидался FILE_ACK от сервера.");

        long offset = Proto.DecodeOffset(payload);
        if (offset > fileSize)
            throw new ProtocolException("Сервер сообщил смещение больше размера файла.");
        if (expectedOffset.HasValue && offset != expectedOffset.Value)
            throw new ProtocolException($"Неверное смещение FILE_ACK: {offset}, ожидалось {expectedOffset.Value}.");
        return offset;
    }

    private static async Task<string?> TryReadServerErrorAsync(SecureChannel ch)
    {
        try
        {
            var (t, p) = await ch.ReceiveAsync(TimeSpan.FromSeconds(2), CancellationToken.None).ConfigureAwait(false);
            return t == MsgType.AppError ? Proto.Utf8(p) : null;
        }
        catch { return null; }
    }

    // ------------------------------------------------------------------ HANDSHAKE

    private static async Task<SecureChannel> HandshakeAsync(
        Stream s, string user, RSA clientKey, string hostKey, string home, string? pin, CancellationToken ct)
    {
        using var transcript = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

        // --- HELLO ---
        byte[] raw = await Proto.SendPlainAsync(s, MsgType.Hello, Encoding.UTF8.GetBytes(user), ct).ConfigureAwait(false);
        transcript.AppendData(raw);

        // --- CHALLENGE ---
        PlainMsg chMsg = await Proto.ReadPlainAsync(s, ct).ConfigureAwait(false);
        ThrowIfServerError(chMsg);
        if (chMsg.Type != MsgType.Challenge || chMsg.Payload.Length <= Proto.ChallengeSize)
            throw new ProtocolException("Ожидался CHALLENGE от сервера.");
        transcript.AppendData(chMsg.Raw);
        byte[] challenge = chMsg.Payload.AsSpan(0, Proto.ChallengeSize).ToArray();
        byte[] serverSpki = chMsg.Payload.AsSpan(Proto.ChallengeSize).ToArray();
        using RSA serverPub = Proto.ImportPublicKey(serverSpki);
        VerifyServerPin(serverSpki, hostKey, home, pin);

        // --- AUTH_RESPONSE: RSA-PSS(SHA-256) подпись challenge ---
        byte[] signature = Proto.SignPss(clientKey, challenge);
        raw = await Proto.SendPlainAsync(s, MsgType.AuthResponse, signature, ct).ConfigureAwait(false);
        transcript.AppendData(raw);

        // --- KEY_EXCHANGE: RSA-OAEP(SHA-256) premaster_secret ---
        byte[] premaster = RandomNumberGenerator.GetBytes(Proto.PremasterSize);
        byte[] encrypted = Proto.OaepEncrypt(serverPub, premaster);
        raw = await Proto.SendPlainAsync(s, MsgType.KeyExchange, encrypted, ct).ConfigureAwait(false);
        transcript.AppendData(raw);

        // --- HKDF ---
        var (key, clientPrefix, serverPrefix) = Proto.DeriveKeys(premaster, challenge);
        CryptographicOperations.ZeroMemory(premaster);
        byte[] th = transcript.GetHashAndReset();

        if (s is UdpStream transport) transport.EnableAuthentication(Proto.TransportKey(key));

        // Клиент: отправляет с префиксом клиента, принимает с префиксом сервера.
        var channel = new SecureChannel(s, key, clientPrefix, serverPrefix);
        try
        {
            await channel.SendAsync(MsgType.Finished, Proto.SignPss(clientKey, Proto.ClientFinishedData(th)), ct)
                .ConfigureAwait(false);

            (MsgType type, byte[] payload) msg;
            try { msg = await channel.ReceiveAsync(ct).ConfigureAwait(false); }
            catch (Exception ex) when (ex is ProtocolException or EndOfStreamException or IOException)
            {
                throw new ProtocolException(
                    "Сервер отклонил handshake или оборвал соединение (неверный ключ/подпись? проверьте журнал сервера).");
            }
            if (msg.type != MsgType.Finished ||
                !CryptographicOperations.FixedTimeEquals(msg.payload, Proto.ServerFinishedMac(key, th)))
                throw new ProtocolException("Сервер не подтвердил владение ключами (возможна MITM-атака).");
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
        return channel;
    }

    private static void ThrowIfServerError(PlainMsg m)
    {
        if (m.Type == MsgType.Error) throw new ProtocolException("Сервер: " + Proto.Utf8(m.Payload));
    }

    /// <summary>Проверка закреплённого отпечатка сервера: --pin либо TOFU-файл known_servers.</summary>
    private static void VerifyServerPin(byte[] serverSpki, string hostKey, string home, string? pin)
    {
        string fp = Proto.Hex(Proto.Sha256(serverSpki));
        if (!string.IsNullOrWhiteSpace(pin))
        {
            string expected = pin.Replace(":", "").Trim();
            if (!string.Equals(expected, fp, StringComparison.OrdinalIgnoreCase))
                throw new ProtocolException($"Отпечаток ключа сервера ({fp}) не совпадает с --pin.");
            return;
        }

        Directory.CreateDirectory(home);
        string file = Path.Combine(home, "known_servers");
        if (File.Exists(file))
        {
            foreach (string line in File.ReadAllLines(file))
            {
                string[] parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length != 2 || !string.Equals(parts[0], hostKey, StringComparison.OrdinalIgnoreCase)) continue;
                if (string.Equals(parts[1], fp, StringComparison.OrdinalIgnoreCase)) return;
                throw new ProtocolException(
                    $"ВНИМАНИЕ: ключ сервера {hostKey} ИЗМЕНИЛСЯ (было {parts[1]}, сейчас {fp}). Возможна MITM-атака. " +
                    $"Если смена ключа легитимна — удалите строку из {file}.");
            }
        }

        Console.WriteLine($"Первое подключение к {hostKey}. Отпечаток ключа сервера (SHA-256): {fp}");
        Console.WriteLine($"Отпечаток сохранён в {file} (TOFU). Для строгой проверки используйте --pin.");
        File.AppendAllText(file, $"{hostKey} {fp}{Environment.NewLine}");
    }
}
