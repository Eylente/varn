using System.Security.Cryptography;
using System.Text;
using OtpNet;

namespace Varn.Core.Security.Otp;

public enum TotpHashAlgorithm { Sha1, Sha256, Sha512 }

public sealed record TotpOptions(
    int Digits = 6,
    int PeriodSeconds = 30,
    TotpHashAlgorithm Algorithm = TotpHashAlgorithm.Sha1);

public sealed record TotpSnapshot(string Code, int RemainingSeconds, int PeriodSeconds);

public static class TotpService
{
    /// <summary>Убирает пробелы, дефисы и '=' и приводит к верхнему регистру (инвариантно к культуре).</summary>
    public static string NormalizeSecret(string? input)
    {
        if (string.IsNullOrWhiteSpace(input)) return string.Empty;

        var sb = new StringBuilder(input.Length);
        foreach (char c in input)
        {
            if (char.IsWhiteSpace(c) || c is '-' or '=') continue;
            sb.Append(char.ToUpperInvariant(c));
        }

        return sb.ToString();
    }

    public static bool IsValidSecret(string? input)
    {
        bool ok = TryDecode(input, out byte[] secret);
        CryptographicOperations.ZeroMemory(secret);
        return ok;
    }

    public static string GenerateSecret(int byteLength = 20)
    {
        if (byteLength < 10)
            throw new ArgumentOutOfRangeException(nameof(byteLength), "Use at least 10 bytes (80 bits); 20 is recommended.");

        byte[] bytes = RandomNumberGenerator.GetBytes(byteLength);
        try
        {
            return Base32Encoding.ToString(bytes).TrimEnd('=');
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    public static TotpSnapshot GetSnapshot(string base32Secret, TotpOptions? options = null, DateTime? utcNow = null)
    {
        options ??= new TotpOptions();
        if (!TryDecode(base32Secret, out byte[] secret))
            throw new FormatException("The secret is not valid Base32.");

        try
        {
            var totp = CreateTotp(secret, options);
            DateTime now = utcNow ?? DateTime.UtcNow;
            return new TotpSnapshot(totp.ComputeTotp(now), totp.RemainingSeconds(now), options.PeriodSeconds);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    /// <param name="windowSteps">Сколько периодов назад и вперёд допускается (компенсация расхождения часов).</param>
    public static bool Verify(
        string base32Secret,
        string code,
        TotpOptions? options = null,
        int windowSteps = 1,
        DateTime? utcNow = null)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(windowSteps);
        if (string.IsNullOrWhiteSpace(code)) return false;

        options ??= new TotpOptions();
        if (!TryDecode(base32Secret, out byte[] secret))
            throw new FormatException("The secret is not valid Base32.");

        try
        {
            var totp = CreateTotp(secret, options);
            var window = new VerificationWindow(previous: windowSteps, future: windowSteps);
            return totp.VerifyTotp(utcNow ?? DateTime.UtcNow, code.Replace(" ", string.Empty), out _, window);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    /// <summary>otpauth://-ссылка для QR-кода приложений-аутентификаторов.</summary>
    public static string BuildOtpAuthUri(string issuer, string account, string base32Secret, TotpOptions? options = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(account);
        options ??= new TotpOptions();

        string label = string.IsNullOrWhiteSpace(issuer)
            ? Uri.EscapeDataString(account)
            : $"{Uri.EscapeDataString(issuer)}:{Uri.EscapeDataString(account)}";

        var uri = new StringBuilder($"otpauth://totp/{label}?secret={NormalizeSecret(base32Secret)}");
        if (!string.IsNullOrWhiteSpace(issuer)) uri.Append($"&issuer={Uri.EscapeDataString(issuer)}");

        string algorithm = options.Algorithm switch
        {
            TotpHashAlgorithm.Sha256 => "SHA256",
            TotpHashAlgorithm.Sha512 => "SHA512",
            _ => "SHA1"
        };

        uri.Append($"&algorithm={algorithm}&digits={options.Digits}&period={options.PeriodSeconds}");
        return uri.ToString();
    }

    private static bool TryDecode(string? input, out byte[] secret)
    {
        secret = [];
        string normalized = NormalizeSecret(input);
        if (normalized.Length == 0) return false;

        foreach (char c in normalized)
        {
            if (!(c is >= 'A' and <= 'Z' || c is >= '2' and <= '7')) return false;
        }

        try
        {
            secret = Base32Encoding.ToBytes(normalized);
            return secret.Length > 0;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    private static Totp CreateTotp(byte[] secret, TotpOptions options)
    {
        if (options.Digits is < 6 or > 8)
            throw new ArgumentOutOfRangeException(nameof(options), "Digits must be between 6 and 8.");
        if (options.PeriodSeconds < 1)
            throw new ArgumentOutOfRangeException(nameof(options), "The period must be at least 1 second.");

        OtpHashMode mode = options.Algorithm switch
        {
            TotpHashAlgorithm.Sha256 => OtpHashMode.Sha256,
            TotpHashAlgorithm.Sha512 => OtpHashMode.Sha512,
            _ => OtpHashMode.Sha1
        };

        return new Totp(secret, options.PeriodSeconds, mode, options.Digits);
    }
}