using System.Security.Cryptography;

namespace Varn.Core.Security.Models;

public enum PasswordAlgorithm
{
    Argon2id,
    BCrypt,
    Pbkdf2,
    Scrypt,
    Sha256Legacy,
    Md5Legacy,
    Sha1Legacy
}

public enum PasswordOutputFormat
{
    /// <summary>Одна строка PHC: параметры и соль внутри (для bcrypt — родная строка $2a$...).</summary>
    Phc,

    /// <summary>Отдельно: хэш (Base64), соль (Base64) и параметры (JSON).</summary>
    RawFields
}

public sealed record PasswordHashResult(
    string Hash,
    string? Salt,
    string Algorithm,
    bool SaltEmbeddedInHash,
    string? ParametersJson = null,
    string? Warning = null);

/// <summary>Значения по умолчанию: RFC 9106 §4, вариант с меньшей памятью (t=3, m=64 MiB, p=4).</summary>
public sealed record Argon2Options(int Iterations = 3, int MemoryKb = 65536, int Parallelism = 4);

/// <summary>N — степень двойки. По умолчанию N=2^16, r=8, p=2 (рекомендация OWASP, ~64 MiB).</summary>
public sealed record ScryptOptions(int CostFactor = 65536, int BlockSize = 8, int Parallelization = 2);

public sealed record HasherSettings
{
    public Argon2Options Argon2 { get; init; } = new();
    public int BCryptWorkFactor { get; init; } = 12;
    public int Pbkdf2Iterations { get; init; } = 600_000;
    public HashAlgorithmName Pbkdf2Algorithm { get; init; } = HashAlgorithmName.SHA256;
    public ScryptOptions Scrypt { get; init; } = new();
    public bool LegacyUseSalt { get; init; } = true;
    public PasswordOutputFormat OutputFormat { get; init; } = PasswordOutputFormat.Phc;
}