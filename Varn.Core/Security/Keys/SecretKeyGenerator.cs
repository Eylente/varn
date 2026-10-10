using System.Security.Cryptography;
using OtpNet;

namespace Varn.Core.Security.Keys;

public static class SecretKeyGenerator
{
    /// <summary>Случайный ключ из CSPRNG. Вызывающий обязан затереть массив (ZeroMemory) после использования.</summary>
    public static byte[] Generate(int bits)
    {
        if (bits <= 0 || bits % 8 != 0)
            throw new ArgumentException("The bit length must be positive and a multiple of 8.", nameof(bits));

        return RandomNumberGenerator.GetBytes(bits / 8);
    }

    public static string ToBase64(byte[] key) => Convert.ToBase64String(key);

    public static string ToHex(byte[] key) => Convert.ToHexString(key);

    public static string ToBase32(byte[] key) => Base32Encoding.ToString(key).TrimEnd('=');
}