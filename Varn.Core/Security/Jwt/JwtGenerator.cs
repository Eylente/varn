using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Varn.Core.Security.Jwt;

public sealed record JwtGenerationResult(
    string Token,
    string? Warning,
    string? WarningCode = null,
    IReadOnlyList<string>? WarningArguments = null);

public static class JwtGenerator
{
    public static JwtGenerationResult Generate(
        JwtAlgorithm algorithm,
        string key,
        string payloadJson,
        string? keyId = null,
        bool secretIsBase64 = false,
        string? privateKeyPassword = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(key);
        ArgumentException.ThrowIfNullOrWhiteSpace(payloadJson);

        string header = BuildHeader(algorithm, keyId);
        string payload = NormalizePayload(payloadJson);

        string signingInput =
            $"{JwtBase64Url.Encode(Encoding.UTF8.GetBytes(header))}.{JwtBase64Url.Encode(Encoding.UTF8.GetBytes(payload))}";

        var (signature, warning) = Sign(
            algorithm, Encoding.ASCII.GetBytes(signingInput), key, secretIsBase64, privateKeyPassword);

        return new JwtGenerationResult(
            $"{signingInput}.{JwtBase64Url.Encode(signature)}",
            warning?.Message,
            warning?.Code,
            warning?.Arguments);
    }

    private static string BuildHeader(JwtAlgorithm algorithm, string? keyId)
    {
        var header = new Dictionary<string, string>
        {
            ["alg"] = algorithm.ToString(),
            ["typ"] = "JWT"
        };

        if (!string.IsNullOrWhiteSpace(keyId)) header["kid"] = keyId;

        return JsonSerializer.Serialize(header);
    }

    private static string NormalizePayload(string payloadJson)
    {
        try
        {
            using var doc = JsonDocument.Parse(payloadJson);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
            {
                throw Error("The payload must be a JSON object.", nameof(payloadJson),
                    MessageCodes.PayloadNotObject);
            }

            return JsonSerializer.Serialize(doc.RootElement);
        }
        catch (JsonException ex)
        {
            throw Error($"The payload is not valid JSON: {ex.Message}", nameof(payloadJson),
                MessageCodes.PayloadInvalidJson, ex, ex.Message);
        }
    }

    private static (byte[] Signature, CoreWarning? Warning) Sign(
        JwtAlgorithm algorithm, byte[] data, string key, bool secretIsBase64, string? privateKeyPassword)
    {
        if (algorithm.IsHmac()) return SignHmac(algorithm, data, key, secretIsBase64);
        if (algorithm.IsEcdsa()) return SignEcdsa(algorithm, data, key, privateKeyPassword);
        return SignRsa(algorithm, data, key, privateKeyPassword);
    }

    private static (byte[] Signature, CoreWarning? Warning) SignHmac(
        JwtAlgorithm algorithm, byte[] data, string key, bool secretIsBase64)
    {
        if (key.Contains("-----BEGIN", StringComparison.Ordinal))
        {
            throw Error("HMAC algorithms need a shared secret, not a PEM key.", nameof(key),
                MessageCodes.HmacWithPemKey);
        }

        byte[] secret;
        try
        {
            secret = secretIsBase64 ? Convert.FromBase64String(key.Trim()) : Encoding.UTF8.GetBytes(key);
        }
        catch (FormatException ex)
        {
            throw Error("The secret is not valid Base64.", nameof(key), MessageCodes.SecretNotBase64, ex);
        }

        try
        {
            int minBytes = algorithm.HashSizeBytes();
            CoreWarning? warning = secret.Length < minBytes
                ? new CoreWarning(
                    $"The secret is {secret.Length * 8} bits; RFC 7518 requires at least {minBytes * 8} bits for {algorithm}.",
                    MessageCodes.WarnHmacSecretShort,
                    [(secret.Length * 8).ToString(), (minBytes * 8).ToString(), algorithm.ToString()])
                : null;

            using HMAC hmac = algorithm.CreateHmac(secret);
            return (hmac.ComputeHash(data), warning);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    private static (byte[] Signature, CoreWarning? Warning) SignRsa(
        JwtAlgorithm algorithm, byte[] data, string key, string? password)
    {
        using var rsa = RSA.Create();
        try
        {
            if (string.IsNullOrEmpty(password)) rsa.ImportFromPem(key);
            else rsa.ImportFromEncryptedPem(key, password);
        }
        catch (Exception ex) when (ex is ArgumentException or CryptographicException)
        {
            throw Error(
                "Could not read the RSA private key. Expected PEM (PKCS#8); if it is encrypted, supply the password.",
                nameof(key), MessageCodes.RsaPrivateKeyUnreadable, ex);
        }

        CoreWarning? warning = rsa.KeySize < 2048
            ? new CoreWarning(
                $"The RSA key is {rsa.KeySize} bits; RFC 7518 requires at least 2048 bits.",
                MessageCodes.WarnRsaKeyShort,
                [rsa.KeySize.ToString()])
            : null;

        var padding = algorithm.IsRsaPss() ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;

        try
        {
            return (rsa.SignData(data, algorithm.HashName(), padding), warning);
        }
        catch (CryptographicException ex)
        {
            throw Error("Signing failed: the key may contain only the public part.", nameof(key),
                MessageCodes.KeyHasNoPrivatePart, ex);
        }
    }

    private static (byte[] Signature, CoreWarning? Warning) SignEcdsa(
        JwtAlgorithm algorithm, byte[] data, string key, string? password)
    {
        using var ecdsa = ECDsa.Create();
        try
        {
            if (string.IsNullOrEmpty(password)) ecdsa.ImportFromPem(key);
            else ecdsa.ImportFromEncryptedPem(key, password);
        }
        catch (Exception ex) when (ex is ArgumentException or CryptographicException)
        {
            throw Error(
                "Could not read the EC private key. Expected PEM (PKCS#8); if it is encrypted, supply the password.",
                nameof(key), MessageCodes.EcPrivateKeyUnreadable, ex);
        }

        int expectedSize = algorithm.EcdsaKeySize();
        if (ecdsa.KeySize != expectedSize)
        {
            throw Error(
                $"{algorithm} requires a P-{expectedSize} key, but the supplied key is {ecdsa.KeySize} bits.",
                nameof(key), MessageCodes.EcCurveMismatch, null,
                algorithm.ToString(), expectedSize.ToString(), ecdsa.KeySize.ToString());
        }

        try
        {
            return (ecdsa.SignData(data, algorithm.HashName()), null);
        }
        catch (CryptographicException ex)
        {
            throw Error("Signing failed: the key may contain only the public part.", nameof(key),
                MessageCodes.KeyHasNoPrivatePart, ex);
        }
    }
    
    private static ArgumentException Error(
        string message, string paramName, string code, Exception? inner = null, params string[] arguments)
    {
        var exception = new ArgumentException(message, paramName, inner);
        exception.Data["code"] = code;
        for (int i = 0; i < arguments.Length; i++)
        {
            exception.Data[$"arg{i}"] = arguments[i];
        }

        return exception;
    }
}