using System.Security.Cryptography;

namespace Varn.Core.Security.Jwt;

public enum JwtAlgorithm
{
    HS256, HS384, HS512,
    RS256, RS384, RS512,
    PS256, PS384, PS512,
    ES256, ES384, ES512
}

public static class JwtAlgorithmExtensions
{
    private static readonly Dictionary<string, JwtAlgorithm> ByName =
        Enum.GetValues<JwtAlgorithm>().ToDictionary(a => a.ToString());

    /// <summary>Имена алгоритмов в JWT регистрозависимы: "hs256" не принимается.</summary>
    public static bool TryParse(string? value, out JwtAlgorithm algorithm)
    {
        algorithm = default;
        return value is not null && ByName.TryGetValue(value, out algorithm);
    }

    public static bool IsHmac(this JwtAlgorithm a) =>
        a is JwtAlgorithm.HS256 or JwtAlgorithm.HS384 or JwtAlgorithm.HS512;

    public static bool IsRsaPkcs1(this JwtAlgorithm a) =>
        a is JwtAlgorithm.RS256 or JwtAlgorithm.RS384 or JwtAlgorithm.RS512;

    public static bool IsRsaPss(this JwtAlgorithm a) =>
        a is JwtAlgorithm.PS256 or JwtAlgorithm.PS384 or JwtAlgorithm.PS512;

    public static bool IsEcdsa(this JwtAlgorithm a) =>
        a is JwtAlgorithm.ES256 or JwtAlgorithm.ES384 or JwtAlgorithm.ES512;

    public static HashAlgorithmName HashName(this JwtAlgorithm a) => a switch
    {
        JwtAlgorithm.HS256 or JwtAlgorithm.RS256 or JwtAlgorithm.PS256 or JwtAlgorithm.ES256 => HashAlgorithmName.SHA256,
        JwtAlgorithm.HS384 or JwtAlgorithm.RS384 or JwtAlgorithm.PS384 or JwtAlgorithm.ES384 => HashAlgorithmName.SHA384,
        _ => HashAlgorithmName.SHA512
    };

    public static int HashSizeBytes(this JwtAlgorithm a) =>
        a.HashName() == HashAlgorithmName.SHA256 ? 32 :
        a.HashName() == HashAlgorithmName.SHA384 ? 48 : 64;

    /// <summary>ES256 → P-256, ES384 → P-384, ES512 → P-521.</summary>
    public static int EcdsaKeySize(this JwtAlgorithm a) => a switch
    {
        JwtAlgorithm.ES256 => 256,
        JwtAlgorithm.ES384 => 384,
        JwtAlgorithm.ES512 => 521,
        _ => throw new ArgumentException("Not an ECDSA algorithm.", nameof(a))
    };

    internal static HMAC CreateHmac(this JwtAlgorithm a, byte[] key) => a switch
    {
        JwtAlgorithm.HS384 => new HMACSHA384(key),
        JwtAlgorithm.HS512 => new HMACSHA512(key),
        _ => new HMACSHA256(key)
    };
}