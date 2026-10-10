using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using static Varn.Core.Security.Jwt.JwtVerificationStatus;

namespace Varn.Core.Security.Jwt;

public enum JwtVerificationStatus
{
    Valid,
    InvalidSignature,
    UnsupportedAlgorithm,
    AlgorithmNone,
    MalformedToken,
    KeyMissing,
    KeyInvalid
}

public sealed record JwtVerificationResult(JwtVerificationStatus Status, string? Message = null)
{
    public bool IsValid => Status == Valid;
}

public static class JwtVerifier
{
    /// <summary>
    /// Для HS* ключ — общий секрет, для RS*/PS*/ES* — публичный (или приватный) ключ в PEM.
    /// Алгоритм берётся из заголовка токена, но неизвестные алгоритмы никогда не сводятся к HS256.
    /// </summary>
    public static JwtVerificationResult Verify(string? token, string? key, bool secretIsBase64 = false)
    {
        if (string.IsNullOrWhiteSpace(token))
            return Result(MalformedToken, "The token is empty.");

        string[] parts = token.Trim().Split('.');
        if (parts.Length != 3)
            return Result(MalformedToken, "A signed JWT must have exactly three parts.");

        string algName;
        try
        {
            algName = ReadAlgorithm(parts[0]);
        }
        catch (Exception ex) when (ex is FormatException or JsonException)
        {
            return Result(MalformedToken, "The header is not valid Base64Url-encoded JSON.");
        }

        if (algName.Length == 0)
            return Result(MalformedToken, "The header has no 'alg' field.");

        if (string.Equals(algName, "none", StringComparison.OrdinalIgnoreCase))
            return Result(AlgorithmNone, "alg is 'none': the token is unsigned and must never be trusted.");

        if (!JwtAlgorithmExtensions.TryParse(algName, out var algorithm))
            return Result(UnsupportedAlgorithm, $"Algorithm '{algName}' is not supported.");

        if (string.IsNullOrEmpty(key))
            return Result(KeyMissing, "Provide a key to verify the signature.");

        byte[] signature;
        try
        {
            signature = JwtBase64Url.Decode(parts[2]);
        }
        catch (FormatException)
        {
            return Result(MalformedToken, "The signature is not valid Base64Url.");
        }

        byte[] data = Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}");

        if (algorithm.IsHmac()) return VerifyHmac(algorithm, data, signature, key, secretIsBase64);
        if (algorithm.IsEcdsa()) return VerifyEcdsa(algorithm, data, signature, key);
        return VerifyRsa(algorithm, data, signature, key);
    }

    private static JwtVerificationResult VerifyHmac(
        JwtAlgorithm algorithm, byte[] data, byte[] signature, string key, bool secretIsBase64)
    {
        if (key.Contains("-----BEGIN", StringComparison.Ordinal))
        {
            return Result(KeyInvalid,
                "The token uses an HMAC algorithm but a PEM key was supplied. Using a public key as an HMAC " +
                "secret is the classic algorithm-confusion attack; supply the shared secret instead.");
        }

        byte[] secret;
        try
        {
            secret = secretIsBase64 ? Convert.FromBase64String(key.Trim()) : Encoding.UTF8.GetBytes(key);
        }
        catch (FormatException)
        {
            return Result(KeyInvalid, "The secret is not valid Base64.");
        }

        try
        {
            using HMAC hmac = algorithm.CreateHmac(secret);
            byte[] expected = hmac.ComputeHash(data);
            return CryptographicOperations.FixedTimeEquals(expected, signature)
                ? Result(Valid)
                : Result(InvalidSignature);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    private static JwtVerificationResult VerifyRsa(
        JwtAlgorithm algorithm, byte[] data, byte[] signature, string key)
    {
        using var rsa = RSA.Create();
        try
        {
            rsa.ImportFromPem(key);
        }
        catch (Exception ex) when (ex is ArgumentException or CryptographicException)
        {
            return Result(KeyInvalid, $"{algorithm} needs an RSA key in PEM format (PUBLIC KEY or PRIVATE KEY).");
        }

        var padding = algorithm.IsRsaPss() ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;

        try
        {
            return rsa.VerifyData(data, signature, algorithm.HashName(), padding)
                ? Result(Valid)
                : Result(InvalidSignature);
        }
        catch (CryptographicException)
        {
            return Result(InvalidSignature);
        }
    }

    private static JwtVerificationResult VerifyEcdsa(
        JwtAlgorithm algorithm, byte[] data, byte[] signature, string key)
    {
        using var ecdsa = ECDsa.Create();
        try
        {
            ecdsa.ImportFromPem(key);
        }
        catch (Exception ex) when (ex is ArgumentException or CryptographicException)
        {
            return Result(KeyInvalid, $"{algorithm} needs an EC key in PEM format (PUBLIC KEY or PRIVATE KEY).");
        }

        int expectedSize = algorithm.EcdsaKeySize();
        if (ecdsa.KeySize != expectedSize)
        {
            return Result(KeyInvalid,
                $"{algorithm} requires a P-{expectedSize} key, but the supplied key is {ecdsa.KeySize} bits.");
        }

        try
        {
            return ecdsa.VerifyData(data, signature, algorithm.HashName())
                ? Result(Valid)
                : Result(InvalidSignature);
        }
        catch (CryptographicException)
        {
            return Result(InvalidSignature);
        }
    }

    private static string ReadAlgorithm(string headerPart)
    {
        string json = Encoding.UTF8.GetString(JwtBase64Url.Decode(headerPart));
        using var doc = JsonDocument.Parse(json);

        return doc.RootElement.ValueKind == JsonValueKind.Object &&
               doc.RootElement.TryGetProperty("alg", out var alg) &&
               alg.ValueKind == JsonValueKind.String
            ? alg.GetString() ?? string.Empty
            : string.Empty;
    }

    private static JwtVerificationResult Result(JwtVerificationStatus status, string? message = null) =>
        new(status, message);
}