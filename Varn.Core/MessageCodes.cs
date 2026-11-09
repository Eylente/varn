namespace Varn.Core;

public static class MessageCodes
{
    public const string TokenEmpty = nameof(TokenEmpty);
    public const string TokenNotThreeParts = nameof(TokenNotThreeParts);
    public const string HeaderInvalid = nameof(HeaderInvalid);
    public const string HeaderNoAlg = nameof(HeaderNoAlg);
    public const string UnsupportedAlgorithm = nameof(UnsupportedAlgorithm);
    public const string SignatureNotBase64 = nameof(SignatureNotBase64);
    public const string HmacWithPemKey = nameof(HmacWithPemKey);
    public const string SecretNotBase64 = nameof(SecretNotBase64);
    public const string RsaKeyNotPem = nameof(RsaKeyNotPem);
    public const string EcKeyNotPem = nameof(EcKeyNotPem);
    public const string EcCurveMismatch = nameof(EcCurveMismatch);
    public const string RsaPrivateKeyUnreadable = nameof(RsaPrivateKeyUnreadable);
    public const string EcPrivateKeyUnreadable = nameof(EcPrivateKeyUnreadable);
    public const string KeyHasNoPrivatePart = nameof(KeyHasNoPrivatePart);
    public const string PayloadNotObject = nameof(PayloadNotObject);
    public const string PayloadInvalidJson = nameof(PayloadInvalidJson);
    public const string WarnHmacSecretShort = nameof(WarnHmacSecretShort);
    public const string WarnRsaKeyShort = nameof(WarnRsaKeyShort);
    public const string WarnBcryptTruncated = nameof(WarnBcryptTruncated);
}

public sealed record CoreWarning(string Message, string Code, IReadOnlyList<string> Arguments);