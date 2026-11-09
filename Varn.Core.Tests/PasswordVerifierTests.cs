using Varn.Core.Security.Models;
using Varn.Core.Security.Services;
using Varn.Core.Security.Verification;

namespace Varn.Core.Tests;

public class PasswordVerifierTests
{
    private static readonly HasherSettings Fast = new()
    {
        Argon2 = new Argon2Options(Iterations: 1, MemoryKb: 8192, Parallelism: 1),
        BCryptWorkFactor = 4,
        Pbkdf2Iterations = 1000,
        Scrypt = new ScryptOptions(CostFactor: 1024, BlockSize: 8, Parallelization: 1)
    };

    [Theory]
    [InlineData(PasswordAlgorithm.Argon2id)]
    [InlineData(PasswordAlgorithm.BCrypt)]
    [InlineData(PasswordAlgorithm.Pbkdf2)]
    [InlineData(PasswordAlgorithm.Scrypt)]
    public void OwnHashes_AreVerified(PasswordAlgorithm algorithm)
    {
        string hash = PasswordHasherFactory.Create(algorithm, Fast).Hash("correct horse").Hash;

        var good = PasswordVerifier.Verify("correct horse", hash);
        var bad = PasswordVerifier.Verify("wrong horse", hash);

        Assert.Equal(HashVerificationStatus.Match, good.Status);
        Assert.NotNull(good.Algorithm);
        Assert.Equal(HashVerificationStatus.NoMatch, bad.Status);
    }

    [Theory]
    [InlineData("password", "$pbkdf2-sha256$i=1000$c2FsdA$YywoEuRtRgQQK6dhjp1tfS+BKPYma0oDJk0qBGC33LM")]
    [InlineData("password", "$pbkdf2-sha256$1000$c2FsdA$YywoEuRtRgQQK6dhjp1tfS.BKPYma0oDJk0qBGC33LM")]
    [InlineData("password", "$pbkdf2-sha512$i=1000$c2FsdA$r+bFUweFtsxrHGRTOEcxvV7kMu5Un9QvtmlXea2KHFs")]
    [InlineData("password", "$pbkdf2-sha1$i=2$c2FsdA$6mwBTcctb4zNHtkqzh1B8NjeiVc")]
    [InlineData("password", "$pbkdf2-sha256$i=1$c2FsdA$Eg+2z/z4syxD5yJSVsT4N6hlSMkszDVICAWYfLcL4Xs")]
    [InlineData("password", "$scrypt$ln=10,r=8,p=16$TmFDbA$/bq+HJ00cgB4VucZDQHp/nxq18vII3gw53N2Y0s3MWIurzDZLiKjiG/xCSedmDDaxyevuUqD7m2DYMvfoswGQA")]
    [InlineData("password", "$scrypt$ln=10,r=8,p=1$TmFDbA$J7QYxnTHadElAfux9TusMt9lFMDyjQQ4crFIs0iWGnk")]
    [InlineData("correct horse", "$argon2id$v=19$m=8192,t=1,p=1$c29tZXNhbHQxMjM0NTY3$rbk5DjsbsWVGSoMTsP+UepPPk7apQPCYpBjo6iuiHXc")]
    [InlineData("correct horse", "$argon2i$v=19$m=8192,t=2,p=2$c29tZXNhbHQxMjM0NTY3$o1PnrNjWEmLsjs+EmWrSiNjZkLuyJcjxAix07XUhRQs")]
    [InlineData("correct horse", "$argon2d$v=19$m=8192,t=2,p=2$c29tZXNhbHQxMjM0NTY3$N7l9bgldvlTT4yibbz5jQDyEOgUaQsjippucOEc2J+g")]
    [InlineData("password", "$2b$04$SXJ.eLjpA4/1Gx8DTjkPUeg5GFc.ELHioIx2HN0RUWaK4YYFmwF3C")]
    [InlineData("password", "$2a$04$NlCyc9PyhT7sxd8hD9cfGOplh.eft3qReB6g35OR.UCMdod4l8Ip2")]
    public void ReferenceHashes_Match_AndWrongPasswordDoesNot(string password, string hash)
    {
        Assert.Equal(HashVerificationStatus.Match, PasswordVerifier.Verify(password, hash).Status);
        Assert.Equal(HashVerificationStatus.NoMatch, PasswordVerifier.Verify(password + "x", hash).Status);
    }

    [Fact]
    public void Result_ContainsAlgorithmAndParameters()
    {
        var result = PasswordVerifier.Verify(
            "correct horse",
            "$argon2id$v=19$m=8192,t=1,p=1$c29tZXNhbHQxMjM0NTY3$rbk5DjsbsWVGSoMTsP+UepPPk7apQPCYpBjo6iuiHXc");

        Assert.Equal("Argon2id", result.Algorithm);
        Assert.Equal("m=8192, t=1, p=1", result.Parameters);
    }

    [Fact]
    public void SurroundingWhitespace_IsIgnored()
    {
        var result = PasswordVerifier.Verify(
            "password",
            "  \n$pbkdf2-sha256$i=1000$c2FsdA$YywoEuRtRgQQK6dhjp1tfS+BKPYma0oDJk0qBGC33LM\r\n");

        Assert.True(result.IsMatch);
    }

    [Fact]
    public void EmptyPassword_DoesNotThrow()
    {
        var result = PasswordVerifier.Verify(
            "",
            "$pbkdf2-sha256$i=1000$c2FsdA$YywoEuRtRgQQK6dhjp1tfS+BKPYma0oDJk0qBGC33LM");

        Assert.Equal(HashVerificationStatus.NoMatch, result.Status);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("hello")]
    [InlineData("5f4dcc3b5aa765d61d8327deb882cf99")] // обычный MD5 в hex
    [InlineData("$unknown$a$b")]
    public void Unrecognized_Formats(string hash) =>
        Assert.Equal(HashVerificationStatus.UnrecognizedFormat, PasswordVerifier.Verify("x", hash).Status);

    [Theory]
    [InlineData("$argon2id$v=19$m=8192,t=1,p=1$c29tZXNhbHQxMjM0NTY3")]                         // нет хэша
    [InlineData("$argon2id$v=19$m=8192,t=1,p=1$c2hvcnQ$rbk5DjsbsWVGSoMTsP+UepPPk7apQPCYpBjo6iuiHXc")] // соль короче 8 байт
    [InlineData("$argon2id$v=19$m=8192,t=1$c29tZXNhbHQxMjM0NTY3$rbk5DjsbsWVGSoMTsP+UepPPk7apQPCYpBjo6iuiHXc")] // нет параметра p
    [InlineData("$scrypt$ln=10,r=8$TmFDbA$J7QYxnTHadElAfux9TusMt9lFMDyjQQ4crFIs0iWGnk")]        // нет параметра p
    [InlineData("$pbkdf2-sha256$i=1000$!!!$???")]                                              // неверный Base64
    [InlineData("$pbkdf2-sha256$i=abc$c2FsdA$YywoEuRtRgQQK6dhjp1tfS+BKPYma0oDJk0qBGC33LM")]    // итерации не число
    [InlineData("$2b$04$short")]                                                               // обрезанный bcrypt
    public void Malformed_Hashes(string hash) =>
        Assert.Equal(HashVerificationStatus.Malformed, PasswordVerifier.Verify("x", hash).Status);

    [Theory]
    [InlineData("$argon2id$v=16$m=8192,t=1,p=1$c29tZXNhbHQxMjM0NTY3$rbk5DjsbsWVGSoMTsP+UepPPk7apQPCYpBjo6iuiHXc")] // старая версия Argon2
    [InlineData("$pbkdf2-md5$i=1$c2FsdA$AAAA")]                                                                   // неподдерживаемая хэш-функция
    public void Unsupported_Parameters(string hash) =>
        Assert.Equal(HashVerificationStatus.UnsupportedParameters, PasswordVerifier.Verify("x", hash).Status);

    [Theory]
    [InlineData("$argon2id$v=19$m=4194304,t=1,p=1$c29tZXNhbHQxMjM0NTY3$rbk5DjsbsWVGSoMTsP+UepPPk7apQPCYpBjo6iuiHXc")] // 4 ГиБ памяти
    [InlineData("$argon2id$v=19$m=8192,t=1000,p=1$c29tZXNhbHQxMjM0NTY3$rbk5DjsbsWVGSoMTsP+UepPPk7apQPCYpBjo6iuiHXc")] // 1000 проходов
    [InlineData("$pbkdf2-sha256$i=100000000$c2FsdA$YywoEuRtRgQQK6dhjp1tfS+BKPYma0oDJk0qBGC33LM")]                    // 100 млн итераций
    [InlineData("$scrypt$ln=24,r=8,p=1$TmFDbA$J7QYxnTHadElAfux9TusMt9lFMDyjQQ4crFIs0iWGnk")]                         // 16 ГиБ памяти
    public void ExcessiveParameters_AreRejected_WithoutComputing(string hash) =>
        Assert.Equal(HashVerificationStatus.ParametersTooLarge, PasswordVerifier.Verify("x", hash).Status);

    [Fact]
    public void Bcrypt_ExcessiveCost_IsRejected() =>
        Assert.Equal(
            HashVerificationStatus.ParametersTooLarge,
            PasswordVerifier.Verify("x", "$2b$31$" + new string('a', 53)).Status);
}