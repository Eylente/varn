using System.Text;
using Varn.Core.Security.Jwt;
using Varn.Core.Security.Keys;

namespace Varn.Core.Tests;

public class JwtTests
{
    // Классический пример с jwt.io: секрет "your-256-bit-secret"
    private const string KnownToken =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    private const string KnownSecret = "your-256-bit-secret";
    private const string LongSecret = "a-secret-that-is-long-enough-even-for-hs512-0123456789-0123456789";
    private const string Payload = "{\"sub\":\"1\",\"name\":\"Test\"}";

    private static readonly Lazy<KeyPairResult> Rsa = new(() => KeyPairGenerator.GenerateRsa(2048));
    private static readonly Lazy<KeyPairResult> P256 = new(() => KeyPairGenerator.GenerateEc(EcCurveName.P256));
    private static readonly Lazy<KeyPairResult> P384 = new(() => KeyPairGenerator.GenerateEc(EcCurveName.P384));
    private static readonly Lazy<KeyPairResult> P521 = new(() => KeyPairGenerator.GenerateEc(EcCurveName.P521));

    private static string B64(string text) => JwtBase64Url.Encode(Encoding.UTF8.GetBytes(text));

    private static (string SignKey, string VerifyKey) KeysFor(JwtAlgorithm a) => a switch
    {
        _ when a.IsHmac() => (LongSecret, LongSecret),
        _ when a.IsRsaPkcs1() || a.IsRsaPss() => (Rsa.Value.PrivateKeyPem, Rsa.Value.PublicKeyPem),
        JwtAlgorithm.ES256 => (P256.Value.PrivateKeyPem, P256.Value.PublicKeyPem),
        JwtAlgorithm.ES384 => (P384.Value.PrivateKeyPem, P384.Value.PublicKeyPem),
        _ => (P521.Value.PrivateKeyPem, P521.Value.PublicKeyPem)
    };

    public static IEnumerable<object[]> AllAlgorithms() =>
        Enum.GetValues<JwtAlgorithm>().Select(a => new object[] { a });

    // Известный токен

    [Fact]
    public void Verify_KnownHs256Token_IsValid()
    {
        var result = JwtVerifier.Verify(KnownToken, KnownSecret);

        Assert.True(result.IsValid);
    }

    [Fact]
    public void Verify_WrongSecret_IsInvalidSignature()
    {
        var result = JwtVerifier.Verify(KnownToken, "wrong-secret");

        Assert.Equal(JwtVerificationStatus.InvalidSignature, result.Status);
    }

    [Fact]
    public void Decode_KnownToken_ParsesHeaderAndClaims()
    {
        var decoded = JwtDecoder.Decode(KnownToken);

        Assert.True(decoded.IsValidStructure);
        Assert.Equal("HS256", decoded.Algorithm);
        Assert.Contains("John Doe", decoded.PayloadJson);
        Assert.NotNull(decoded.IssuedAt);
        Assert.Null(decoded.ExpirationTime);
    }

    [Theory]
    [InlineData("")]
    [InlineData("abc")]
    [InlineData("a.b")]
    [InlineData("!!!.???.###")]
    public void Decode_Garbage_IsNotValidStructure(string token) =>
        Assert.False(JwtDecoder.Decode(token).IsValidStructure);

    // Генерация и проверка всех алгоритмов

    [Theory]
    [MemberData(nameof(AllAlgorithms))]
    public void GenerateThenVerify_RoundTrips(JwtAlgorithm algorithm)
    {
        var (signKey, verifyKey) = KeysFor(algorithm);

        var generated = JwtGenerator.Generate(algorithm, signKey, Payload, keyId: "k1");
        var verified = JwtVerifier.Verify(generated.Token, verifyKey);

        Assert.True(verified.IsValid, verified.Message);
        Assert.Contains("\"kid\":\"k1\"", Encoding.UTF8.GetString(
            Convert.FromBase64String(PadBase64(generated.Token.Split('.')[0]))));
    }

    private static string PadBase64(string s)
    {
        s = s.Replace('-', '+').Replace('_', '/');
        return s.PadRight(s.Length + (4 - s.Length % 4) % 4, '=');
    }

    [Fact]
    public void Verify_TamperedPayload_IsInvalidSignature()
    {
        var token = JwtGenerator.Generate(JwtAlgorithm.HS256, LongSecret, Payload).Token;
        var parts = token.Split('.');
        parts[1] = B64("{\"sub\":\"attacker\"}");

        var result = JwtVerifier.Verify(string.Join('.', parts), LongSecret);

        Assert.Equal(JwtVerificationStatus.InvalidSignature, result.Status);
    }

    // Безопасность проверки

    [Theory]
    [InlineData("none")]
    [InlineData("None")]
    [InlineData("NONE")]
    public void Verify_AlgNone_IsFlagged(string alg)
    {
        string token = $"{B64($"{{\"alg\":\"{alg}\"}}")}.{B64(Payload)}.";

        var result = JwtVerifier.Verify(token, "anything");

        Assert.Equal(JwtVerificationStatus.AlgorithmNone, result.Status);
    }

    [Theory]
    [InlineData("HS999")]
    [InlineData("hs256")]
    [InlineData("EdDSA")]
    public void Verify_UnknownAlgorithm_IsNeverFallenBackToHs256(string alg)
    {
        string token = $"{B64($"{{\"alg\":\"{alg}\"}}")}.{B64(Payload)}.AAAA";

        var result = JwtVerifier.Verify(token, "secret");

        Assert.Equal(JwtVerificationStatus.UnsupportedAlgorithm, result.Status);
    }

    [Fact]
    public void Verify_HmacToken_WithPemKey_IsRejectedAsAlgorithmConfusion()
    {
        var token = JwtGenerator.Generate(JwtAlgorithm.HS256, LongSecret, Payload).Token;

        var result = JwtVerifier.Verify(token, Rsa.Value.PublicKeyPem);

        Assert.Equal(JwtVerificationStatus.KeyInvalid, result.Status);
    }

    [Fact]
    public void Verify_RsaToken_WithPlainSecret_IsKeyInvalid()
    {
        var token = JwtGenerator.Generate(JwtAlgorithm.RS256, Rsa.Value.PrivateKeyPem, Payload).Token;

        var result = JwtVerifier.Verify(token, LongSecret);

        Assert.Equal(JwtVerificationStatus.KeyInvalid, result.Status);
    }

    [Fact]
    public void Verify_Es256Token_WithP384Key_IsKeyInvalid()
    {
        var token = JwtGenerator.Generate(JwtAlgorithm.ES256, P256.Value.PrivateKeyPem, Payload).Token;

        var result = JwtVerifier.Verify(token, P384.Value.PublicKeyPem);

        Assert.Equal(JwtVerificationStatus.KeyInvalid, result.Status);
    }

    [Fact]
    public void Verify_WrongRsaKey_IsInvalidSignature()
    {
        var token = JwtGenerator.Generate(JwtAlgorithm.RS256, Rsa.Value.PrivateKeyPem, Payload).Token;
        var otherKey = KeyPairGenerator.GenerateRsa(2048).PublicKeyPem;

        var result = JwtVerifier.Verify(token, otherKey);

        Assert.Equal(JwtVerificationStatus.InvalidSignature, result.Status);
    }

    [Fact]
    public void Verify_WithoutKey_ReportsKeyMissing() =>
        Assert.Equal(JwtVerificationStatus.KeyMissing, JwtVerifier.Verify(KnownToken, "").Status);

    [Theory]
    [InlineData("")]
    [InlineData("only.two")]
    [InlineData("!!!.???.###")]
    public void Verify_MalformedToken_IsReported(string token) =>
        Assert.Equal(JwtVerificationStatus.MalformedToken, JwtVerifier.Verify(token, "secret").Status);

    // Генерация: валидация и предупреждения

    [Fact]
    public void Generate_ShortHmacSecret_ReturnsWarning() =>
        Assert.NotNull(JwtGenerator.Generate(JwtAlgorithm.HS256, "short", Payload).Warning);

    [Fact]
    public void Generate_LongHmacSecret_HasNoWarning() =>
        Assert.Null(JwtGenerator.Generate(JwtAlgorithm.HS256, LongSecret, Payload).Warning);

    [Theory]
    [InlineData("[1,2,3]")]
    [InlineData("not json")]
    public void Generate_InvalidPayload_Throws(string payload) =>
        Assert.Throws<ArgumentException>(() => JwtGenerator.Generate(JwtAlgorithm.HS256, LongSecret, payload));

    [Fact]
    public void Generate_Hs256_WithPemKey_Throws() =>
        Assert.Throws<ArgumentException>(
            () => JwtGenerator.Generate(JwtAlgorithm.HS256, Rsa.Value.PrivateKeyPem, Payload));

    [Fact]
    public void Generate_Es256_WithWrongCurve_Throws() =>
        Assert.Throws<ArgumentException>(
            () => JwtGenerator.Generate(JwtAlgorithm.ES256, P384.Value.PrivateKeyPem, Payload));

    [Fact]
    public void Generate_WithPublicKeyOnly_Throws() =>
        Assert.Throws<ArgumentException>(
            () => JwtGenerator.Generate(JwtAlgorithm.RS256, Rsa.Value.PublicKeyPem, Payload));

    [Fact]
    public void Generate_WithEncryptedPrivateKey_NeedsPassword()
    {
        var pair = KeyPairGenerator.GenerateEc(EcCurveName.P256, privateKeyPassword: "correct horse");

        var token = JwtGenerator.Generate(
            JwtAlgorithm.ES256, pair.PrivateKeyPem, Payload, privateKeyPassword: "correct horse").Token;

        Assert.True(JwtVerifier.Verify(token, pair.PublicKeyPem).IsValid);
        Assert.Throws<ArgumentException>(
            () => JwtGenerator.Generate(JwtAlgorithm.ES256, pair.PrivateKeyPem, Payload));
    }

    [Fact]
    public void Base64Secret_IsDecodedBeforeUse()
    {
        string base64Secret = Convert.ToBase64String(Encoding.UTF8.GetBytes(LongSecret));

        var token = JwtGenerator.Generate(JwtAlgorithm.HS256, base64Secret, Payload, secretIsBase64: true).Token;

        Assert.True(JwtVerifier.Verify(token, LongSecret).IsValid);
        Assert.True(JwtVerifier.Verify(token, base64Secret, secretIsBase64: true).IsValid);
    }
}