using System.Security.Cryptography;
using Varn.Core.Security.Keys;

namespace Varn.Core.Tests;

public class KeyTests
{
    [Theory]
    [InlineData(128, 16)]
    [InlineData(256, 32)]
    [InlineData(512, 64)]
    public void SecretKey_HasRequestedLength(int bits, int bytes) =>
        Assert.Equal(bytes, SecretKeyGenerator.Generate(bits).Length);

    [Theory]
    [InlineData(0)]
    [InlineData(-8)]
    [InlineData(7)]
    public void SecretKey_InvalidLength_Throws(int bits) =>
        Assert.Throws<ArgumentException>(() => SecretKeyGenerator.Generate(bits));

    [Fact]
    public void SecretKey_IsUnique() =>
        Assert.NotEqual(SecretKeyGenerator.Generate(256), SecretKeyGenerator.Generate(256));

    [Fact]
    public void SecretKey_Encodings_AreConsistent()
    {
        byte[] key = [0x00, 0x01, 0xAB, 0xFF];

        Assert.Equal("AAGr/w==", SecretKeyGenerator.ToBase64(key));
        Assert.Equal("0001ABFF", SecretKeyGenerator.ToHex(key));
        Assert.DoesNotContain('=', SecretKeyGenerator.ToBase32(key));
    }

    [Fact]
    public void Rsa_ProducesStandardPemAndJwk()
    {
        var pair = KeyPairGenerator.GenerateRsa(2048);

        Assert.StartsWith("-----BEGIN PRIVATE KEY-----", pair.PrivateKeyPem);
        Assert.StartsWith("-----BEGIN PUBLIC KEY-----", pair.PublicKeyPem);
        Assert.Contains("\"kty\":\"RSA\"", pair.PublicJwk);
        Assert.DoesNotContain("\"d\"", pair.PublicJwk);
    }

    [Fact]
    public void Rsa_UnsupportedSize_Throws() =>
        Assert.Throws<ArgumentOutOfRangeException>(() => KeyPairGenerator.GenerateRsa(1024));

    [Theory]
    [InlineData(EcCurveName.P256, "P-256")]
    [InlineData(EcCurveName.P384, "P-384")]
    [InlineData(EcCurveName.P521, "P-521")]
    public void Ec_JwkContainsCurve(EcCurveName curve, string expectedCrv)
    {
        var pair = KeyPairGenerator.GenerateEc(curve);

        Assert.Contains($"\"crv\":\"{expectedCrv}\"", pair.PublicJwk);
        Assert.StartsWith("-----BEGIN PRIVATE KEY-----", pair.PrivateKeyPem);
    }

    [Fact]
    public void EncryptedPrivateKey_HasEncryptedHeader_AndImportsOnlyWithPassword()
    {
        var pair = KeyPairGenerator.GenerateEc(EcCurveName.P256, privateKeyPassword: "pw-123");

        Assert.StartsWith("-----BEGIN ENCRYPTED PRIVATE KEY-----", pair.PrivateKeyPem);

        using var ok = ECDsa.Create();
        ok.ImportFromEncryptedPem(pair.PrivateKeyPem, "pw-123");

        using var bad = ECDsa.Create();
        Assert.ThrowsAny<CryptographicException>(() => bad.ImportFromEncryptedPem(pair.PrivateKeyPem, "wrong"));
    }
    
    [Fact]
    public void TryDerivePublicPem_ReturnsMatchingPublicKey()
    {
        var rsa = KeyPairGenerator.GenerateRsa(2048);
        var ec = KeyPairGenerator.GenerateEc(EcCurveName.P256);

        Assert.Equal(rsa.PublicKeyPem, KeyPairGenerator.TryDerivePublicPem(rsa.PrivateKeyPem));
        Assert.Equal(ec.PublicKeyPem, KeyPairGenerator.TryDerivePublicPem(ec.PrivateKeyPem));
    }

    [Fact]
    public void TryDerivePublicPem_Encrypted_NeedsCorrectPassword()
    {
        var pair = KeyPairGenerator.GenerateEc(EcCurveName.P256, privateKeyPassword: "pw-1");

        Assert.Equal(pair.PublicKeyPem, KeyPairGenerator.TryDerivePublicPem(pair.PrivateKeyPem, "pw-1"));
        Assert.Null(KeyPairGenerator.TryDerivePublicPem(pair.PrivateKeyPem, "wrong"));
        Assert.Null(KeyPairGenerator.TryDerivePublicPem(pair.PrivateKeyPem));
        Assert.Null(KeyPairGenerator.TryDerivePublicPem("not a key"));
    }
}