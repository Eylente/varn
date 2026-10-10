using System.Security.Cryptography;
using System.Text;
using Varn.Core.Security.Interfaces;
using Varn.Core.Security.Models;

namespace Varn.Core.Security.Services;

/// <summary>Устаревшие быстрые хэши (SHA256/MD5/SHA1) — только для эмуляции старых систем.</summary>
public sealed class LegacyHasher : IPasswordHasher
{
    private const int SaltSize = 16;

    private readonly string _hashName;
    private readonly bool _useSalt;

    public LegacyHasher(PasswordAlgorithm algorithm, bool useSalt = true)
    {
        _hashName = algorithm switch
        {
            PasswordAlgorithm.Sha256Legacy => "SHA256",
            PasswordAlgorithm.Md5Legacy => "MD5",
            PasswordAlgorithm.Sha1Legacy => "SHA1",
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, "Not a legacy algorithm.")
        };

        Algorithm = algorithm;
        _useSalt = useSalt;
    }

    public PasswordAlgorithm Algorithm { get; }
    public string AlgorithmName => $"{_hashName} (Legacy{(_useSalt ? "" : ", no salt")})";

    public PasswordHashResult Hash(string password)
    {
        ArgumentException.ThrowIfNullOrEmpty(password);

        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
        byte[]? salt = _useSalt ? RandomNumberGenerator.GetBytes(SaltSize) : null;
        byte[] input = salt is null ? passwordBytes : [.. salt, .. passwordBytes];

        try
        {
            byte[] hash = _hashName switch
            {
                "MD5" => MD5.HashData(input),
                "SHA1" => SHA1.HashData(input),
                _ => SHA256.HashData(input)
            };

            return new PasswordHashResult(
                Hash: Convert.ToBase64String(hash),
                Salt: salt is null ? null : Convert.ToBase64String(salt),
                Algorithm: AlgorithmName,
                SaltEmbeddedInHash: false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
            if (!ReferenceEquals(input, passwordBytes))
                CryptographicOperations.ZeroMemory(input);
        }
    }
}