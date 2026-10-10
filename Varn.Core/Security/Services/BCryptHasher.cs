using System.Text;
using Varn.Core.Security.Interfaces;
using Varn.Core.Security.Models;

namespace Varn.Core.Security.Services;

public sealed class BCryptHasher : IPasswordHasher
{
    private const int MaxPasswordBytes = 72;

    public BCryptHasher(int workFactor = 12)
    {
        if (workFactor is < 4 or > 31)
            throw new ArgumentOutOfRangeException(nameof(workFactor), "Work factor must be between 4 and 31.");

        WorkFactor = workFactor;
    }

    public int WorkFactor { get; }
    public PasswordAlgorithm Algorithm => PasswordAlgorithm.BCrypt;
    public string AlgorithmName => "BCrypt";

    public PasswordHashResult Hash(string password)
    {
        ArgumentException.ThrowIfNullOrEmpty(password);

        string? warning = Encoding.UTF8.GetByteCount(password) > MaxPasswordBytes
            ? "Password is longer than 72 bytes: bcrypt only uses the first 72 bytes."
            : null;

        string hash = BCrypt.Net.BCrypt.HashPassword(password, WorkFactor);

        return new PasswordHashResult(
            Hash: hash,
            Salt: null,
            Algorithm: AlgorithmName,
            SaltEmbeddedInHash: true,
            ParametersJson: null,
            Warning: warning);
    }
}