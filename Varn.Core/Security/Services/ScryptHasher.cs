using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Generators;
using Varn.Core.Security.Interfaces;
using Varn.Core.Security.Models;


namespace Varn.Core.Security.Services;

public sealed class ScryptHasher : IPasswordHasher
{
    private const int SaltSize = 16;
    private const int HashSize = 32;

    private readonly ScryptOptions _options;
    private readonly PasswordOutputFormat _format;

    public ScryptHasher(ScryptOptions? options = null, PasswordOutputFormat format = PasswordOutputFormat.Phc)
    {
        _options = options ?? new ScryptOptions();

        if (_options.CostFactor < 2 || !BitOperations.IsPow2(_options.CostFactor))
            throw new ArgumentOutOfRangeException(nameof(options), "CostFactor (N) must be a power of two, e.g. 16384, 65536.");
        if (_options.BlockSize < 1)
            throw new ArgumentOutOfRangeException(nameof(options), "BlockSize (r) must be at least 1.");
        if (_options.Parallelization < 1)
            throw new ArgumentOutOfRangeException(nameof(options), "Parallelization (p) must be at least 1.");

        _format = format;
    }

    public PasswordAlgorithm Algorithm => PasswordAlgorithm.Scrypt;
    public string AlgorithmName => "scrypt";

    public PasswordHashResult Hash(string password) =>
        HashWithSalt(password, RandomNumberGenerator.GetBytes(SaltSize));

    internal PasswordHashResult HashWithSalt(string password, byte[] salt)
    {
        ArgumentException.ThrowIfNullOrEmpty(password);

        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
        try
        {
            byte[] hash = SCrypt.Generate(
                passwordBytes, salt,
                _options.CostFactor, _options.BlockSize, _options.Parallelization,
                HashSize);

            int logN = BitOperations.Log2((uint)_options.CostFactor);
            string phc = $"$scrypt$ln={logN},r={_options.BlockSize},p={_options.Parallelization}" +
                         $"${HashFormatting.ToUnpaddedBase64(salt)}${HashFormatting.ToUnpaddedBase64(hash)}";

            return HashFormatting.Build(
                _format, AlgorithmName, phc, hash, salt,
                new { n = _options.CostFactor, r = _options.BlockSize, p = _options.Parallelization });
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
        }
    }
}