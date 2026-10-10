using System.Text;
using OtpNet;
using Varn.Core.Security.Otp;

namespace Varn.Core.Tests;

public class TotpTests
{
    private static string Base32Of(string ascii) => Base32Encoding.ToString(Encoding.ASCII.GetBytes(ascii));

    private static DateTime At(long unixSeconds) => DateTimeOffset.FromUnixTimeSeconds(unixSeconds).UtcDateTime;

    // RFC 6238, Appendix B (8 цифр)
    [Theory]
    [InlineData(59L, "94287082")]
    [InlineData(1111111109L, "07081804")]
    [InlineData(1111111111L, "14050471")]
    [InlineData(1234567890L, "89005924")]
    [InlineData(2000000000L, "69279037")]
    [InlineData(20000000000L, "65353130")]
    public void Sha1_MatchesRfc6238(long time, string expected)
    {
        var options = new TotpOptions(Digits: 8, Algorithm: TotpHashAlgorithm.Sha1);

        var snapshot = TotpService.GetSnapshot(Base32Of("12345678901234567890"), options, At(time));

        Assert.Equal(expected, snapshot.Code);
    }

    [Fact]
    public void Sha256_MatchesRfc6238()
    {
        var options = new TotpOptions(Digits: 8, Algorithm: TotpHashAlgorithm.Sha256);

        var snapshot = TotpService.GetSnapshot(Base32Of("12345678901234567890123456789012"), options, At(59));

        Assert.Equal("46119246", snapshot.Code);
    }

    [Fact]
    public void Sha512_MatchesRfc6238()
    {
        var options = new TotpOptions(Digits: 8, Algorithm: TotpHashAlgorithm.Sha512);
        string secret = Base32Of("1234567890123456789012345678901234567890123456789012345678901234");

        var snapshot = TotpService.GetSnapshot(secret, options, At(59));

        Assert.Equal("90693936", snapshot.Code);
    }

    [Fact]
    public void RemainingSeconds_IsCountedWithinPeriod()
    {
        var snapshot = TotpService.GetSnapshot(Base32Of("12345678901234567890"), utcNow: At(59));

        Assert.Equal(1, snapshot.RemainingSeconds);
        Assert.Equal(30, snapshot.PeriodSeconds);
    }

    [Theory]
    [InlineData("jbsw y3dp-ehpk 3pxp", "JBSWY3DPEHPK3PXP")]
    [InlineData("  jbswy3dpehpk3pxp==  ", "JBSWY3DPEHPK3PXP")]
    public void NormalizeSecret_RemovesFormatting(string input, string expected) =>
        Assert.Equal(expected, TotpService.NormalizeSecret(input));

    [Theory]
    [InlineData("jbsw y3dp ehpk 3pxp", true)]
    [InlineData("JBSWY3DPEHPK3PXP", true)]
    [InlineData("", false)]
    [InlineData("   ", false)]
    [InlineData("abc!", false)]
    [InlineData("1189", false)]
    public void IsValidSecret_AcceptsOnlyBase32(string input, bool expected) =>
        Assert.Equal(expected, TotpService.IsValidSecret(input));

    [Fact]
    public void Verify_AcceptsAdjacentPeriod_ButNotFarOnes()
    {
        string secret = Base32Of("12345678901234567890");
        string code = TotpService.GetSnapshot(secret, utcNow: At(1_000_000_000)).Code;

        Assert.True(TotpService.Verify(secret, code, utcNow: At(1_000_000_000)));
        Assert.True(TotpService.Verify(secret, code, utcNow: At(1_000_000_030), windowSteps: 1));
        Assert.False(TotpService.Verify(secret, code, utcNow: At(1_000_000_090), windowSteps: 1));
        Assert.False(TotpService.Verify(secret, code, utcNow: At(1_000_000_030), windowSteps: 0));
    }

    [Fact]
    public void Verify_IgnoresSpacesInCode()
    {
        string secret = Base32Of("12345678901234567890");
        string code = TotpService.GetSnapshot(secret, utcNow: At(1_000_000_000)).Code;
        string spaced = $"{code[..3]} {code[3..]}";

        Assert.True(TotpService.Verify(secret, spaced, utcNow: At(1_000_000_000)));
    }

    [Fact]
    public void GetSnapshot_InvalidSecret_Throws() =>
        Assert.Throws<FormatException>(() => TotpService.GetSnapshot("not base32!"));

    [Fact]
    public void GenerateSecret_IsValid_AndHas160Bits()
    {
        string secret = TotpService.GenerateSecret();

        Assert.True(TotpService.IsValidSecret(secret));
        Assert.Equal(32, secret.Length);
    }

    [Fact]
    public void OtpAuthUri_ContainsAllParameters()
    {
        string uri = TotpService.BuildOtpAuthUri(
            "Varn Test", "user@example.com", "jbsw y3dp ehpk 3pxp",
            new TotpOptions(Digits: 8, PeriodSeconds: 60, Algorithm: TotpHashAlgorithm.Sha256));

        Assert.StartsWith("otpauth://totp/Varn%20Test:user%40example.com?secret=JBSWY3DPEHPK3PXP", uri);
        Assert.Contains("&issuer=Varn%20Test", uri);
        Assert.Contains("&algorithm=SHA256&digits=8&period=60", uri);
    }
}