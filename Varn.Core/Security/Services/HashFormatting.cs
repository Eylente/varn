using System.Text.Json;
using Varn.Core.Security.Models;

namespace Varn.Core.Security.Services;

internal static class HashFormatting
{
    public static string ToUnpaddedBase64(byte[] data) =>
        Convert.ToBase64String(data).TrimEnd('=');

    public static PasswordHashResult Build(
        PasswordOutputFormat format,
        string algorithmName,
        string phc,
        byte[] hash,
        byte[] salt,
        object parameters)
    {
        if (format == PasswordOutputFormat.Phc)
        {
            return new PasswordHashResult(phc, null, algorithmName, SaltEmbeddedInHash: true);
        }

        return new PasswordHashResult(
            Hash: Convert.ToBase64String(hash),
            Salt: Convert.ToBase64String(salt),
            Algorithm: algorithmName,
            SaltEmbeddedInHash: false,
            ParametersJson: JsonSerializer.Serialize(parameters));
    }
}