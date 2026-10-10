using Varn.Core.Security.Models;

namespace Varn.Core.Security.Interfaces;

public interface IPasswordHasher
{
    PasswordAlgorithm Algorithm { get; }
    string AlgorithmName { get; }
    PasswordHashResult Hash(string password);
}