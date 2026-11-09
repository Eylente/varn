using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Konscious.Security.Cryptography;
using Org.BouncyCastle.Crypto.Generators;
using Status = Varn.Core.Security.Verification.HashVerificationStatus;

namespace Varn.Core.Security.Verification;

public static partial class PasswordVerifier
{
    private const long MaxMemoryBytes = 1L << 30; // 1 ГиБ
    private const int MaxArgon2Iterations = 100;
    private const int MaxParallelism = 64;
    private const int MaxPbkdf2Iterations = 20_000_000;
    private const int MaxBcryptCost = 20;

    [GeneratedRegex(@"^\$2[aby]\$(\d\d)\$[./A-Za-z0-9]{53}$")]
    private static partial Regex BcryptRegex();

    public static HashVerificationResult Verify(string password, string hash)
    {
        ArgumentNullException.ThrowIfNull(password);

        string value = (hash ?? string.Empty).Trim();
        if (value.Length == 0 || value[0] != '$')
            return Result(Status.UnrecognizedFormat);

        if (value.StartsWith("$2", StringComparison.Ordinal))
            return VerifyBcrypt(password, value);

        string[] parts = value.Split('$');
        string id = parts.Length > 1 ? parts[1] : string.Empty;

        bool known = id is "argon2id" or "argon2i" or "argon2d" or "scrypt"
                     || id.StartsWith("pbkdf2-", StringComparison.Ordinal);
        if (!known)
            return Result(Status.UnrecognizedFormat);

        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
        try
        {
            return id switch
            {
                "argon2id" or "argon2i" or "argon2d" => VerifyArgon2(id, parts, passwordBytes),
                "scrypt" => VerifyScrypt(parts, passwordBytes),
                _ => VerifyPbkdf2(id, parts, passwordBytes)
            };
        }
        catch (OutOfMemoryException)
        {
            return Result(Status.ParametersTooLarge, DisplayName(id));
        }
        catch (Exception ex) when (ex is ArgumentException or CryptographicException)
        {
            return Result(Status.UnsupportedParameters, DisplayName(id));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
        }
    }

    private static HashVerificationResult VerifyBcrypt(string password, string hash)
    {
        const string name = "bcrypt";

        Match match = BcryptRegex().Match(hash);
        if (!match.Success)
            return Result(Status.Malformed, name);

        int cost = int.Parse(match.Groups[1].Value, CultureInfo.InvariantCulture);
        string description = $"cost={cost}";

        if (cost < 4)
            return Result(Status.Malformed, name, description);
        if (cost > MaxBcryptCost)
            return Result(Status.ParametersTooLarge, name, description);

        try
        {
            bool ok = BCrypt.Net.BCrypt.Verify(password, hash);
            return Result(ok ? Status.Match : Status.NoMatch, name, description);
        }
        catch (Exception)
        {
            return Result(Status.Malformed, name, description);
        }
    }

    private static HashVerificationResult VerifyArgon2(string id, string[] parts, byte[] password)
    {
        string name = DisplayName(id);
        int index = 2;

        if (parts.Length > index && parts[index].StartsWith("v=", StringComparison.Ordinal))
        {
            if (parts[index] != "v=19")
                return Result(Status.UnsupportedParameters, name, parts[index]);
            index++;
        }

        if (parts.Length != index + 3)
            return Result(Status.Malformed, name);

        Dictionary<string, string> p = ParseParameters(parts[index]);
        if (!TryGetInt(p, "m", out int memory) ||
            !TryGetInt(p, "t", out int iterations) ||
            !TryGetInt(p, "p", out int parallelism))
        {
            return Result(Status.Malformed, name);
        }

        string description = $"m={memory}, t={iterations}, p={parallelism}";
        byte[]? salt = DecodeBase64(parts[index + 1]);
        byte[]? expected = DecodeBase64(parts[index + 2]);

        if (salt is null || expected is null || salt.Length < 8 || expected.Length < 4 ||
            iterations < 1 || parallelism < 1 || memory < 8 * parallelism)
        {
            return Result(Status.Malformed, name, description);
        }

        if ((long)memory * 1024 > MaxMemoryBytes || iterations > MaxArgon2Iterations || parallelism > MaxParallelism)
            return Result(Status.ParametersTooLarge, name, description);

        using Argon2 argon2 = id switch
        {
            "argon2i" => new Argon2i(password),
            "argon2d" => new Argon2d(password),
            _ => new Argon2id(password)
        };

        argon2.Salt = salt;
        argon2.DegreeOfParallelism = parallelism;
        argon2.Iterations = iterations;
        argon2.MemorySize = memory;

        byte[] actual = argon2.GetBytes(expected.Length);
        bool ok = CryptographicOperations.FixedTimeEquals(actual, expected);
        return Result(ok ? Status.Match : Status.NoMatch, name, description);
    }

    private static HashVerificationResult VerifyScrypt(string[] parts, byte[] password)
    {
        const string name = "scrypt";

        if (parts.Length != 5)
            return Result(Status.Malformed, name);

        Dictionary<string, string> p = ParseParameters(parts[2]);
        if (!TryGetInt(p, "ln", out int logN) ||
            !TryGetInt(p, "r", out int blockSize) ||
            !TryGetInt(p, "p", out int parallelism))
        {
            return Result(Status.Malformed, name);
        }

        string description = $"ln={logN}, r={blockSize}, p={parallelism}";
        byte[]? salt = DecodeBase64(parts[3]);
        byte[]? expected = DecodeBase64(parts[4]);

        if (salt is null || expected is null || logN < 1 || logN > 24 || blockSize < 1 || parallelism < 1)
            return Result(Status.Malformed, name, description);

        if (parallelism > MaxParallelism || 128L * (1L << logN) * blockSize > MaxMemoryBytes)
            return Result(Status.ParametersTooLarge, name, description);

        byte[] actual = SCrypt.Generate(password, salt, 1 << logN, blockSize, parallelism, expected.Length);
        bool ok = CryptographicOperations.FixedTimeEquals(actual, expected);
        return Result(ok ? Status.Match : Status.NoMatch, name, description);
    }

    private static HashVerificationResult VerifyPbkdf2(string id, string[] parts, byte[] password)
    {
        string suffix = id["pbkdf2-".Length..];

        HashAlgorithmName? algorithm = suffix switch
        {
            "sha1" => HashAlgorithmName.SHA1,
            "sha256" => HashAlgorithmName.SHA256,
            "sha384" => HashAlgorithmName.SHA384,
            "sha512" => HashAlgorithmName.SHA512,
            _ => null
        };

        if (algorithm is null)
            return Result(Status.UnsupportedParameters, "PBKDF2", id);

        string name = $"PBKDF2 ({suffix.ToUpperInvariant()})";

        if (parts.Length != 5)
            return Result(Status.Malformed, name);
        
        int iterations;
        string field = parts[2];
        if (field.Length > 0 && field.All(char.IsAsciiDigit))
        {
            if (!int.TryParse(field, NumberStyles.None, CultureInfo.InvariantCulture, out iterations))
                return Result(Status.Malformed, name);
        }
        else if (!TryGetInt(ParseParameters(field), "i", out iterations))
        {
            return Result(Status.Malformed, name);
        }

        string description = $"i={iterations}";
        byte[]? salt = DecodeBase64(parts[3]);
        byte[]? expected = DecodeBase64(parts[4]);

        if (salt is null || expected is null || iterations < 1)
            return Result(Status.Malformed, name, description);

        if (iterations > MaxPbkdf2Iterations)
            return Result(Status.ParametersTooLarge, name, description);

        byte[] actual = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, algorithm.Value, expected.Length);
        bool ok = CryptographicOperations.FixedTimeEquals(actual, expected);
        return Result(ok ? Status.Match : Status.NoMatch, name, description);
    }

    private static Dictionary<string, string> ParseParameters(string text)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string pair in text.Split(',', StringSplitOptions.RemoveEmptyEntries))
        {
            int separator = pair.IndexOf('=');
            if (separator > 0)
                result[pair[..separator]] = pair[(separator + 1)..];
        }

        return result;
    }

    private static bool TryGetInt(Dictionary<string, string> parameters, string key, out int value)
    {
        value = 0;
        return parameters.TryGetValue(key, out string? text) &&
               int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out value);
    }

    private static byte[]? DecodeBase64(string text)
    {
        string s = text.TrimEnd('=').Replace('.', '+');
        if (s.Length == 0) return null;

        switch (s.Length % 4)
        {
            case 2: s += "=="; break;
            case 3: s += "="; break;
            case 1: return null;
        }

        try
        {
            return Convert.FromBase64String(s);
        }
        catch (FormatException)
        {
            return null;
        }
    }

    private static string DisplayName(string id) => id switch
    {
        "argon2id" => "Argon2id",
        "argon2i" => "Argon2i",
        "argon2d" => "Argon2d",
        "scrypt" => "scrypt",
        _ => "PBKDF2"
    };

    private static HashVerificationResult Result(Status status, string? algorithm = null, string? parameters = null) =>
        new(status, algorithm, parameters);
}