using Varn.Core.Security.Interfaces;
using Varn.Core.Security.Models;

namespace Varn.Core.Security.Services;

public static class PasswordHasherFactory
{
    public static IPasswordHasher Create(PasswordAlgorithm algorithm, HasherSettings? settings = null)
    {
        settings ??= new HasherSettings();

        return algorithm switch
        {
            PasswordAlgorithm.Argon2id => new Argon2Hasher(settings.Argon2, settings.OutputFormat),
            PasswordAlgorithm.BCrypt => new BCryptHasher(settings.BCryptWorkFactor),
            PasswordAlgorithm.Pbkdf2 => new Pbkdf2Hasher(settings.Pbkdf2Iterations, settings.Pbkdf2Algorithm, settings.OutputFormat),
            PasswordAlgorithm.Scrypt => new ScryptHasher(settings.Scrypt, settings.OutputFormat),
            PasswordAlgorithm.Sha256Legacy or PasswordAlgorithm.Md5Legacy or PasswordAlgorithm.Sha1Legacy
                => new LegacyHasher(algorithm, settings.LegacyUseSalt),
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, "Unknown algorithm.")
        };
    }
}