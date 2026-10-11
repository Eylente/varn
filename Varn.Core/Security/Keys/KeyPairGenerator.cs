using System.Security.Cryptography;
using System.Text.Json;
using Varn.Core.Security.Jwt;

namespace Varn.Core.Security.Keys;

public enum EcCurveName { P256, P384, P521 }

/// <param name="PrivateKeyPem">PKCS#8 (при указании пароля — зашифрованный PKCS#8, AES-256-CBC).</param>
/// <param name="PublicKeyPem">SubjectPublicKeyInfo.</param>
/// <param name="PublicJwk">Публичный ключ в формате JWK (для JWKS).</param>
public sealed record KeyPairResult(string PrivateKeyPem, string PublicKeyPem, string PublicJwk, string Description);

public static class KeyPairGenerator
{
    private const int PbeIterations = 600_000;

    public static readonly IReadOnlyList<int> RsaKeySizes = [2048, 3072, 4096];

    public static KeyPairResult GenerateRsa(int keySizeBits = 3072, string? privateKeyPassword = null)
    {
        if (!RsaKeySizes.Contains(keySizeBits))
            throw new ArgumentOutOfRangeException(nameof(keySizeBits), "Supported RSA sizes: 2048, 3072, 4096.");

        using var rsa = RSA.Create(keySizeBits);
        RSAParameters p = rsa.ExportParameters(false);

        string jwk = JsonSerializer.Serialize(new
        {
            kty = "RSA",
            n = JwtBase64Url.Encode(p.Modulus!),
            e = JwtBase64Url.Encode(p.Exponent!)
        });

        return new KeyPairResult(
            ExportPrivatePem(rsa, privateKeyPassword),
            rsa.ExportSubjectPublicKeyInfoPem(),
            jwk,
            $"RSA {keySizeBits}-bit (RS256/RS384/RS512, PS256/PS384/PS512)");
    }

    public static KeyPairResult GenerateEc(EcCurveName curve = EcCurveName.P256, string? privateKeyPassword = null)
    {
        (ECCurve ecCurve, string crv, string alg) = curve switch
        {
            EcCurveName.P256 => (ECCurve.NamedCurves.nistP256, "P-256", "ES256"),
            EcCurveName.P384 => (ECCurve.NamedCurves.nistP384, "P-384", "ES384"),
            EcCurveName.P521 => (ECCurve.NamedCurves.nistP521, "P-521", "ES512"),
            _ => throw new ArgumentOutOfRangeException(nameof(curve))
        };

        using var ecdsa = ECDsa.Create(ecCurve);
        ECParameters p = ecdsa.ExportParameters(false);

        string jwk = JsonSerializer.Serialize(new
        {
            kty = "EC",
            crv,
            x = JwtBase64Url.Encode(p.Q.X!),
            y = JwtBase64Url.Encode(p.Q.Y!)
        });

        return new KeyPairResult(
            ExportPrivatePem(ecdsa, privateKeyPassword),
            ecdsa.ExportSubjectPublicKeyInfoPem(),
            jwk,
            $"ECDSA {crv} ({alg})");
    }

    private static string ExportPrivatePem(AsymmetricAlgorithm key, string? password) =>
        string.IsNullOrEmpty(password)
            ? key.ExportPkcs8PrivateKeyPem()
            : key.ExportEncryptedPkcs8PrivateKeyPem(
                password,
                new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, PbeIterations));
    
    /// <summary>Восстанавливает публичный ключ (PEM) из приватного. Возвращает null, если ключ не читается.</summary>
    public static string? TryDerivePublicPem(string privateKeyPem, string? password = null)
    {
        if (string.IsNullOrWhiteSpace(privateKeyPem)) return null;

        using var rsa = RSA.Create();
        if (TryImport(rsa, privateKeyPem, password)) return rsa.ExportSubjectPublicKeyInfoPem();

        using var ecdsa = ECDsa.Create();
        if (TryImport(ecdsa, privateKeyPem, password)) return ecdsa.ExportSubjectPublicKeyInfoPem();

        return null;
    }

    private static bool TryImport(AsymmetricAlgorithm key, string pem, string? password)
    {
        try
        {
            if (string.IsNullOrEmpty(password)) key.ImportFromPem(pem);
            else key.ImportFromEncryptedPem(pem, password);
            return true;
        }
        catch (Exception ex) when (ex is ArgumentException or CryptographicException)
        {
            return false;
        }
    }
}