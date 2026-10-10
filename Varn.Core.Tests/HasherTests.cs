using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Varn.Core.Security.Models;
using Varn.Core.Security.Services;

namespace Varn.Core.Tests;

public class HasherTests
{
    // Быстрые параметры, чтобы тесты шли за секунды
    private static readonly HasherSettings Fast = new()
    {
        Argon2 = new Argon2Options(Iterations: 1, MemoryKb: 8192, Parallelism: 1),
        BCryptWorkFactor = 4,
        Pbkdf2Iterations = 1000,
        Scrypt = new ScryptOptions(CostFactor: 1024, BlockSize: 8, Parallelization: 1)
    };

    private static string Hex(string base64) =>
        Convert.ToHexString(Convert.FromBase64String(base64)).ToLowerInvariant();

    // Known-answer тесты

    [Theory]
    [InlineData(1, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b")]
    [InlineData(2, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43")]
    [InlineData(4096, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a")]
    public void Pbkdf2Sha256_MatchesKnownVectors(int iterations, string expectedHex)
    {
        var hasher = new Pbkdf2Hasher(iterations, HashAlgorithmName.SHA256, PasswordOutputFormat.RawFields);
        var result = hasher.HashWithSalt("password", Encoding.UTF8.GetBytes("salt"));

        Assert.Equal(expectedHex, Hex(result.Hash));
    }

    [Fact]
    public void Scrypt_MatchesRfc7914Vector()
    {
        // RFC 7914: scrypt("password", "NaCl", N=1024, r=8, p=16); берём первые 32 байта
        var hasher = new ScryptHasher(new ScryptOptions(1024, 8, 16), PasswordOutputFormat.RawFields);
        var result = hasher.HashWithSalt("password", Encoding.UTF8.GetBytes("NaCl"));

        Assert.Equal("fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162", Hex(result.Hash));
    }

    [Theory]
    [InlineData(PasswordAlgorithm.Md5Legacy, "5f4dcc3b5aa765d61d8327deb882cf99")]
    [InlineData(PasswordAlgorithm.Sha1Legacy, "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8")]
    [InlineData(PasswordAlgorithm.Sha256Legacy, "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8")]
    public void LegacyUnsalted_MatchesKnownHashOfPassword(PasswordAlgorithm algorithm, string expectedHex)
    {
        var result = new LegacyHasher(algorithm, useSalt: false).Hash("password");

        Assert.Null(result.Salt);
        Assert.Equal(expectedHex, Hex(result.Hash));
    }

    // Форматы вывода

    [Fact]
    public void Argon2_Phc_HasExpectedShape()
    {
        var result = PasswordHasherFactory.Create(PasswordAlgorithm.Argon2id, Fast).Hash("password");

        Assert.Matches(new Regex(@"^\$argon2id\$v=19\$m=8192,t=1,p=1\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$"), result.Hash);
        Assert.Null(result.Salt);
        Assert.True(result.SaltEmbeddedInHash);
    }

    [Fact]
    public void Argon2_RawFields_ReturnsSaltAndParameters()
    {
        var settings = Fast with { OutputFormat = PasswordOutputFormat.RawFields };
        var result = PasswordHasherFactory.Create(PasswordAlgorithm.Argon2id, settings).Hash("password");

        Assert.NotNull(result.Salt);
        Assert.False(result.SaltEmbeddedInHash);
        Assert.Contains("\"m\":8192", result.ParametersJson);
    }

    [Fact]
    public void Pbkdf2_Phc_HasExpectedShape()
    {
        var result = PasswordHasherFactory.Create(PasswordAlgorithm.Pbkdf2, Fast).Hash("password");

        Assert.StartsWith("$pbkdf2-sha256$i=1000$", result.Hash);
    }

    [Fact]
    public void Scrypt_Phc_HasExpectedShape()
    {
        var result = PasswordHasherFactory.Create(PasswordAlgorithm.Scrypt, Fast).Hash("password");

        Assert.StartsWith("$scrypt$ln=10,r=8,p=1$", result.Hash);
    }

    [Fact]
    public void BCrypt_ProducesStandardString()
    {
        var result = PasswordHasherFactory.Create(PasswordAlgorithm.BCrypt, Fast).Hash("password");

        Assert.StartsWith("$2", result.Hash);
        Assert.Equal(60, result.Hash.Length);
        Assert.Null(result.Warning);
    }

    [Fact]
    public void BCrypt_LongPassword_ReturnsWarning()
    {
        var result = PasswordHasherFactory.Create(PasswordAlgorithm.BCrypt, Fast).Hash(new string('a', 80));

        Assert.NotNull(result.Warning);
    }

    // Общие свойства

    public static IEnumerable<object[]> AllAlgorithms() =>
        Enum.GetValues<PasswordAlgorithm>().Select(a => new object[] { a });

    [Theory]
    [MemberData(nameof(AllAlgorithms))]
    public void EmptyPassword_Throws(PasswordAlgorithm algorithm)
    {
        var hasher = PasswordHasherFactory.Create(algorithm, Fast);

        Assert.ThrowsAny<ArgumentException>(() => hasher.Hash(""));
    }

    [Theory]
    [MemberData(nameof(AllAlgorithms))]
    public void SamePassword_ProducesDifferentResults(PasswordAlgorithm algorithm)
    {
        var hasher = PasswordHasherFactory.Create(algorithm, Fast);

        var first = hasher.Hash("password");
        var second = hasher.Hash("password");

        Assert.NotEqual(first.Hash + first.Salt, second.Hash + second.Salt);
    }

    // Валидация параметров

    [Fact]
    public void Argon2_TooLittleMemory_Throws() =>
        Assert.Throws<ArgumentOutOfRangeException>(() => new Argon2Hasher(new Argon2Options(1, 4, 1)));

    [Fact]
    public void Scrypt_NonPowerOfTwo_Throws() =>
        Assert.Throws<ArgumentOutOfRangeException>(() => new ScryptHasher(new ScryptOptions(1000, 8, 1)));

    [Fact]
    public void BCrypt_WorkFactorOutOfRange_Throws() =>
        Assert.Throws<ArgumentOutOfRangeException>(() => new BCryptHasher(3));
}