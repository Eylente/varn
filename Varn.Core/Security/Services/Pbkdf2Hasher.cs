using System.Security.Cryptography;
using System.Text;
using Varn.Core.Security.Interfaces;
using Varn.Core.Security.Models;

namespace Varn.Core.Security.Services;

public sealed class Pbkdf2Hasher : IPasswordHasher
{
    private const int SaltSize = 16;
    private const int HashSize = 32;

    private readonly int _iterations;
    private readonly HashAlgorithmName _algorithm;
    private readonly PasswordOutputFormat _format;

    public Pbkdf2Hasher(
        int iterations = 600_000,
        HashAlgorithmName? algorithm = null,
        PasswordOutputFormat format = PasswordOutputFormat.Phc)
    {
        if (iterations < 1)
            throw new ArgumentOutOfRangeException(nameof(iterations), "Iterations must be at least 1.");

        _algorithm = algorithm ?? HashAlgorithmName.SHA256;
        if (_algorithm.Name is not ("SHA1" or "SHA256" or "SHA384" or "SHA512"))
            throw new ArgumentException("Supported algorithms: SHA1, SHA256, SHA384, SHA512.", nameof(algorithm));

        _iterations = iterations;
        _format = format;
    }

    public PasswordAlgorithm Algorithm => PasswordAlgorithm.Pbkdf2;
    public string AlgorithmName => $"PBKDF2 ({_algorithm.Name})";

    public PasswordHashResult Hash(string password) =>
        HashWithSalt(password, RandomNumberGenerator.GetBytes(SaltSize));

    internal PasswordHashResult HashWithSalt(string password, byte[] salt)
    {
        ArgumentException.ThrowIfNullOrEmpty(password);

        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
        try
        {
            byte[] hash = Rfc2898DeriveBytes.Pbkdf2(passwordBytes, salt, _iterations, _algorithm, HashSize);

            string phc = $"$pbkdf2-{_algorithm.Name!.ToLowerInvariant()}$i={_iterations}" +
                         $"${HashFormatting.ToUnpaddedBase64(salt)}${HashFormatting.ToUnpaddedBase64(hash)}";

            return HashFormatting.Build(
                _format, AlgorithmName, phc, hash, salt,
                new { i = _iterations, alg = _algorithm.Name });
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
        }
    }
}