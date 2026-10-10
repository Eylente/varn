using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;
using Varn.Core.Security.Interfaces;
using Varn.Core.Security.Models;


namespace Varn.Core.Security.Services;

public sealed class Argon2Hasher : IPasswordHasher
{
    private const int SaltSize = 16;
    private const int HashSize = 32;

    private readonly Argon2Options _options;
    private readonly PasswordOutputFormat _format;

    public Argon2Hasher(Argon2Options? options = null, PasswordOutputFormat format = PasswordOutputFormat.Phc)
    {
        _options = options ?? new Argon2Options();

        if (_options.Iterations < 1)
            throw new ArgumentOutOfRangeException(nameof(options), "Iterations must be at least 1.");
        if (_options.Parallelism < 1)
            throw new ArgumentOutOfRangeException(nameof(options), "Parallelism must be at least 1.");
        if (_options.MemoryKb < 8 * _options.Parallelism)
            throw new ArgumentOutOfRangeException(nameof(options), "MemoryKb must be at least 8 * Parallelism.");

        _format = format;
    }

    public PasswordAlgorithm Algorithm => PasswordAlgorithm.Argon2id;
    public string AlgorithmName => "Argon2id";

    public PasswordHashResult Hash(string password) =>
        HashWithSalt(password, RandomNumberGenerator.GetBytes(SaltSize));

    internal PasswordHashResult HashWithSalt(string password, byte[] salt)
    {
        ArgumentException.ThrowIfNullOrEmpty(password);

        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
        try
        {
            using var argon2 = new Argon2id(passwordBytes)
            {
                Salt = salt,
                DegreeOfParallelism = _options.Parallelism,
                Iterations = _options.Iterations,
                MemorySize = _options.MemoryKb
            };

            byte[] hash = argon2.GetBytes(HashSize);

            string phc = $"$argon2id$v=19$m={_options.MemoryKb},t={_options.Iterations},p={_options.Parallelism}" +
                         $"${HashFormatting.ToUnpaddedBase64(salt)}${HashFormatting.ToUnpaddedBase64(hash)}";

            return HashFormatting.Build(
                _format, AlgorithmName, phc, hash, salt,
                new { m = _options.MemoryKb, t = _options.Iterations, p = _options.Parallelism });
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
        }
    }
}