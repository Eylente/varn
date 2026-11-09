namespace Varn.Core.Security.Verification;

public enum HashVerificationStatus
{
    Match,
    NoMatch,
    UnrecognizedFormat,
    Malformed,
    UnsupportedParameters,
    ParametersTooLarge
}

/// <param name="Algorithm">Название алгоритма, если формат удалось распознать.</param>
/// <param name="Parameters">Параметры из строки хэша в нейтральной записи, например «m=65536, t=3, p=4».</param>
public sealed record HashVerificationResult(
    HashVerificationStatus Status,
    string? Algorithm = null,
    string? Parameters = null)
{
    public bool IsMatch => Status == HashVerificationStatus.Match;
}