// DTO для JSON-сообщений и валидация входных данных.
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace Wer;

public sealed class FileMetaDto
{
    [JsonPropertyName("name")] public string Name { get; set; } = "";
    [JsonPropertyName("size")] public long Size { get; set; }
    [JsonPropertyName("sha256")] public string Sha256 { get; set; } = "";
}

public sealed class ResultDto
{
    [JsonPropertyName("ok")] public bool Ok { get; set; }
    [JsonPropertyName("name")] public string Name { get; set; } = "";
    [JsonPropertyName("size")] public long Size { get; set; }
    [JsonPropertyName("sha256")] public string Sha256 { get; set; } = "";
}

public static class Validation
{
    private static readonly Regex UserRx = new(
        "^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly HashSet<string> ReservedWindowsNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
    };

    public static bool IsValidUserName(string? user) => user is not null && UserRx.IsMatch(user);

    /// <summary>Проверяет имя файла без каталога; бросает ProtocolException при ошибке.</summary>
    public static string ValidateFileName(string? name)
    {
        if (string.IsNullOrEmpty(name) || name.Length > 200)
            throw new ProtocolException("Недопустимая длина имени файла.");
        foreach (char c in name)
        {
            if (c < 32 || "\\/:*?\"<>|".IndexOf(c) >= 0)
                throw new ProtocolException("Имя файла содержит недопустимые символы.");
        }
        if (name == "." || name == ".." || name.EndsWith('.') || name.EndsWith(' ') || name.StartsWith(' '))
            throw new ProtocolException("Недопустимое имя файла.");
        int dot = name.IndexOf('.');
        string stem = dot >= 0 ? name[..dot] : name;
        if (ReservedWindowsNames.Contains(stem))
            throw new ProtocolException("Зарезервированное имя файла.");
        return name;
    }
}
