// WER v22.0-UDP — серверная часть: wer-server [--port 9021] ...
using System.Net.Sockets;

namespace Wer;

internal static class Program
{
    private const string UsageText = @"
wer-server v22.2-UDP — сервер приёма файлов (UDP + RSA-3072 / HKDF / AES-256-GCM)

Использование:
  wer-server [--port 9021] [--max-conn 100] [--max-per-ip 16] [--data ./wer-data]
             [--reg-token TOKEN] [--max-file-size БАЙТ] [--max-users 10000]
             [--open-registration]

  Регистрация по умолчанию ОТКЛЮЧЕНА. Чтобы разрешить новых пользователей, задайте
  --reg-token TOKEN (или WER_REGISTER_TOKEN). Флаг --open-registration открывает
  регистрацию без токена — только для локальных тестов.

Переменные окружения:
  WER_KEY_PASSWORD     пароль для шифрования приватных ключей на диске (PKCS#8 + PBES2)
  WER_REGISTER_TOKEN   токен регистрации (аналог --reg-token)
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
            Args a = Args.Parse(argv);

            int port = a.GetInt("port", 9021);
            int maxConn = a.GetInt("max-conn", 100);
            int maxPerIp = a.GetInt("max-per-ip", 16);
            long maxFileSize = a.GetLong("max-file-size", 4L * 1024 * 1024 * 1024);
            int maxUsers = a.GetInt("max-users", 10_000);

            if (port is < 1 or > 65535) throw new ArgumentException("--port: 1..65535");
            if (maxConn < 1 || maxPerIp < 1) throw new ArgumentException("--max-conn и --max-per-ip должны быть >= 1");
            if (maxFileSize < 0) throw new ArgumentException("--max-file-size должен быть >= 0");
            if (maxUsers < 1) throw new ArgumentException("--max-users должен быть >= 1");

            var opt = new ServerOptions(
                port, maxConn, maxPerIp,
                a.Get("data", "./wer-data"),
                a.Get("reg-token") ?? Environment.GetEnvironmentVariable("WER_REGISTER_TOKEN"),
                maxFileSize,
                maxUsers,
                a.GetFlag("open-registration"));
            using var server = new WerServer(opt);
            await server.RunAsync(cts.Token).ConfigureAwait(false);
            return 0;
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
}
