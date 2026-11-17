// WER v22.0-UDP — клиент: wer-client register | send
using System.Net.Sockets;

namespace Wer;

internal static class Program
{
    private const string UsageText = @"
wer-client v22.2-UDP — клиент передачи файлов (UDP + RSA-3072 / HKDF / AES-256-GCM)

Использование:
  wer-client register <host> <port> <user> [--token TOKEN] [--home DIR]
  wer-client send     <host> <port> <user> <file> [--pin SHA256_HEX] [--home DIR]

При разрыве передачи повторный запуск wer-client send с теми же параметрами продолжит загрузку.

Переменные окружения:
  WER_KEY_PASSWORD     пароль для шифрования приватных ключей на диске (PKCS#8 + PBES2)
  WER_REGISTER_TOKEN   токен регистрации (аналог --token)
";

    private static async Task<int> Main(string[] argv)
    {
        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            try { cts.Cancel(); } catch (ObjectDisposedException) { }
        };

        try
        {
            if (argv.Length == 0) { Console.WriteLine(UsageText); return 1; }
            string cmd = argv[0].ToLowerInvariant();
            Args a = Args.Parse(argv.Skip(1));

            switch (cmd)
            {
                case "register":
                {
                    if (a.Positional.Count != 3) { Console.WriteLine(UsageText); return 1; }
                    string token = a.Get("token") ?? Environment.GetEnvironmentVariable("WER_REGISTER_TOKEN") ?? "";
                    await WerClient.RegisterAsync(
                        a.Positional[0], ParsePort(a.Positional[1]), a.Positional[2],
                        a.Get("home", WerClient.DefaultHome()), token, cts.Token).ConfigureAwait(false);
                    return 0;
                }
                case "send":
                {
                    if (a.Positional.Count != 4) { Console.WriteLine(UsageText); return 1; }
                    await WerClient.SendFileAsync(
                        a.Positional[0], ParsePort(a.Positional[1]), a.Positional[2], a.Positional[3],
                        a.Get("home", WerClient.DefaultHome()), a.Get("pin"), cts.Token).ConfigureAwait(false);
                    return 0;
                }
                default:
                    Console.WriteLine(UsageText);
                    return 1;
            }
        }
        catch (ArgumentException ex) { Console.Error.WriteLine("Ошибка аргументов: " + ex.Message); return 1; }
        catch (ProtocolException ex) { Console.Error.WriteLine("Ошибка протокола: " + ex.Message); return 2; }
        catch (TimeoutException ex) { Console.Error.WriteLine("Таймаут: " + ex.Message); return 3; }
        catch (OperationCanceledException) { Console.Error.WriteLine("Отменено."); return 130; }
        catch (SocketException ex) { Console.Error.WriteLine($"Сетевая ошибка: {ex.SocketErrorCode} ({ex.Message})"); return 4; }
        catch (FileNotFoundException ex) { Console.Error.WriteLine(ex.Message); return 5; }
        catch (IOException ex) { Console.Error.WriteLine("Ошибка ввода-вывода: " + ex.Message); return 5; }
        catch (InvalidOperationException ex) { Console.Error.WriteLine(ex.Message); return 6; }
        catch (Exception ex) { Console.Error.WriteLine("Непредвиденная ошибка: " + ex); return 99; }
    }

    private static int ParsePort(string s)
    {
        if (!int.TryParse(s, out int p) || p < 1 || p > 65535)
            throw new ArgumentException("Порт должен быть 1..65535.");
        return p;
    }
}
