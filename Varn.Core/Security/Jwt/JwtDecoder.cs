using System.Text;
using System.Text.Json;

namespace Varn.Core.Security.Jwt;

public sealed class JwtDecodeResult
{
    public bool IsValidStructure { get; init; }
    public string HeaderJson { get; init; } = "{}";
    public string PayloadJson { get; init; } = "{}";
    public string Algorithm { get; init; } = string.Empty;

    /// <summary>Время в локальной зоне; null, если поля нет или оно не число.</summary>
    public DateTime? ExpirationTime { get; init; }
    public DateTime? NotBefore { get; init; }
    public DateTime? IssuedAt { get; init; }
}

public static class JwtDecoder
{
    private static readonly JsonSerializerOptions Indented = new() { WriteIndented = true };

    public static JwtDecodeResult Decode(string? token)
    {
        if (string.IsNullOrWhiteSpace(token)) return new JwtDecodeResult();

        string[] parts = token.Trim().Split('.');
        if (parts.Length != 3) return new JwtDecodeResult();

        try
        {
            string headerText = Encoding.UTF8.GetString(JwtBase64Url.Decode(parts[0]));
            string payloadText = Encoding.UTF8.GetString(JwtBase64Url.Decode(parts[1]));

            using var headerDoc = JsonDocument.Parse(headerText);
            using var payloadDoc = JsonDocument.Parse(payloadText);

            string algorithm =
                headerDoc.RootElement.ValueKind == JsonValueKind.Object &&
                headerDoc.RootElement.TryGetProperty("alg", out var alg) &&
                alg.ValueKind == JsonValueKind.String
                    ? alg.GetString() ?? string.Empty
                    : string.Empty;

            return new JwtDecodeResult
            {
                IsValidStructure = true,
                HeaderJson = JsonSerializer.Serialize(headerDoc.RootElement, Indented),
                PayloadJson = JsonSerializer.Serialize(payloadDoc.RootElement, Indented),
                Algorithm = algorithm,
                ExpirationTime = ReadTime(payloadDoc.RootElement, "exp"),
                NotBefore = ReadTime(payloadDoc.RootElement, "nbf"),
                IssuedAt = ReadTime(payloadDoc.RootElement, "iat")
            };
        }
        catch (Exception ex) when (ex is FormatException or JsonException or ArgumentException)
        {
            return new JwtDecodeResult();
        }
    }

    private static DateTime? ReadTime(JsonElement root, string name)
    {
        if (root.ValueKind != JsonValueKind.Object ||
            !root.TryGetProperty(name, out var prop) ||
            prop.ValueKind != JsonValueKind.Number ||
            !prop.TryGetDouble(out double seconds))
        {
            return null;
        }

        try
        {
            return DateTimeOffset.FromUnixTimeSeconds((long)seconds).LocalDateTime;
        }
        catch (ArgumentOutOfRangeException)
        {
            return null;
        }
    }
}