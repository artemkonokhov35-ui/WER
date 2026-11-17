// Вспомогательные классы: логирование, хранение ключей, разбор аргументов командной строки.
using System.Security.Cryptography;
using System.Text;

namespace Wer;

public static class Log
{
    private static readonly object Gate = new();
    private static readonly Dictionary<string, (long Until, int Suppressed)> Throttle = new();

    public static void Info(string msg) => Write("INFO ", msg);
    public static void Warn(string msg) => Write("WARN ", msg);
    public static void Error(string msg) => Write("ERROR", msg);

    public static void WarnThrottled(int seconds, string key, string msg)
    {
        lock (Gate)
        {
            long now = Environment.TickCount64;
            if (Throttle.TryGetValue(key, out var state))
            {
                if (now < state.Until)
                {
                    Throttle[key] = (state.Until, state.Suppressed + 1);
                    return;
                }
                if (state.Suppressed > 0) msg += $" (подавлено {state.Suppressed} повторов)";
            }
            if (Throttle.Count > 512) Throttle.Clear();
            Throttle[key] = (now + seconds * 1000L, 0);
            Console.WriteLine($"{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}Z [WARN ] {msg}");
        }
    }

    private static void Write(string level, string msg)
    {
        lock (Gate)
            Console.WriteLine($"{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}Z [{level}] {msg}");
    }
}

public static class KeyStore
{
    /// <summary>Загружает RSA-3072 PEM (PKCS#8, опционально PBES2) или создаёт новый ключ.</summary>
    public static RSA LoadOrCreate(string path, string? password, out bool created)
    {
        created = false;
        if (File.Exists(path))
        {
            string pem = File.ReadAllText(path);
            var rsa = RSA.Create();
            try
            {
                if (pem.Contains("ENCRYPTED PRIVATE KEY", StringComparison.Ordinal))
                {
                    if (string.IsNullOrEmpty(password))
                        throw new InvalidOperationException(
                            $"Ключ {path} зашифрован: задайте пароль в переменной окружения WER_KEY_PASSWORD.");
                    rsa.ImportFromEncryptedPem(pem, password);
                }
                else
                {
                    rsa.ImportFromPem(pem);
                }
                if (rsa.KeySize != Proto.RsaBits)
                    throw new InvalidOperationException($"Ключ {path} не является RSA-{Proto.RsaBits}.");
                return rsa;
            }
            catch
            {
                rsa.Dispose();
                throw;
            }
        }

        string? dir = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        var key = RSA.Create(Proto.RsaBits);
        string outPem = string.IsNullOrEmpty(password)
            ? key.ExportPkcs8PrivateKeyPem()
            : key.ExportEncryptedPkcs8PrivateKeyPem(
                password,
                new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 210_000));

        var opts = new FileStreamOptions
        {
            Mode = FileMode.CreateNew,
            Access = FileAccess.Write,
            Share = FileShare.None
        };
        if (!OperatingSystem.IsWindows())
            opts.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;

        try
        {
            using var fs = new FileStream(path, opts);
            using var w = new StreamWriter(fs, new UTF8Encoding(false));
            w.Write(outPem);
        }
        catch
        {
            key.Dispose();
            throw;
        }

        created = true;
        return key;
    }
}

public sealed class Args
{
    private static readonly HashSet<string> BoolFlags = new(StringComparer.OrdinalIgnoreCase)
    {
        "open-registration"
    };

    public List<string> Positional { get; } = new();
    private readonly HashSet<string> _flags = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _opts = new(StringComparer.OrdinalIgnoreCase);

    public static Args Parse(IEnumerable<string> args)
    {
        var r = new Args();
        var list = args.ToList();
        for (int i = 0; i < list.Count; i++)
        {
            string a = list[i];
            if (a.StartsWith("--", StringComparison.Ordinal))
            {
                string name = a[2..];
                int eq = name.IndexOf('=');
                if (eq >= 0)
                {
                    r._opts[name[..eq]] = name[(eq + 1)..];
                }
                else if (i + 1 < list.Count && !list[i + 1].StartsWith("--", StringComparison.Ordinal))
                {
                    r._opts[name] = list[++i];
                }
                else if (BoolFlags.Contains(name))
                {
                    r._flags.Add(name);
                }
                else
                {
                    throw new ArgumentException($"Опция --{name} требует значение.");
                }
            }
            else
            {
                r.Positional.Add(a);
            }
        }
        return r;
    }

    public bool GetFlag(string name) => _flags.Contains(name);

    public string? Get(string name) => _opts.TryGetValue(name, out var v) ? v : null;
    public string Get(string name, string def) => Get(name) ?? def;

    public int GetInt(string name, int def)
    {
        string? v = Get(name);
        if (v is null) return def;
        if (!int.TryParse(v, out int r)) throw new ArgumentException($"--{name}: ожидается целое число.");
        return r;
    }

    public long GetLong(string name, long def)
    {
        string? v = Get(name);
        if (v is null) return def;
        if (!long.TryParse(v, out long r)) throw new ArgumentException($"--{name}: ожидается целое число.");
        return r;
    }
}
