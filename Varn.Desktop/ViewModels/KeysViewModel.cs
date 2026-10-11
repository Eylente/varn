using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Varn.Core.Security.Keys;

namespace Varn.Desktop.ViewModels;

public partial class KeysViewModel : PageViewModel
{
    private static readonly int[] SecretBits = [128, 256, 512];
    private static readonly int[] RsaSizes = [2048, 3072, 4096];

    public KeysViewModel() : base("Nav_Keys", "IconKeys")
    {
    }

    // Секретный ключ

    [ObservableProperty]
    public partial int SecretBitsIndex { get; set; } = 1; // 256 бит

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasSecret))]
    public partial string SecretBase64 { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string SecretHex { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string SecretBase32 { get; set; } = string.Empty;

    public bool HasSecret => SecretBase64.Length > 0;

    [RelayCommand]
    private void GenerateSecret()
    {
        int bits = SecretBits[Math.Clamp(SecretBitsIndex, 0, SecretBits.Length - 1)];
        byte[] bytes = SecretKeyGenerator.Generate(bits);
        try
        {
            SecretBase64 = SecretKeyGenerator.ToBase64(bytes);
            SecretHex = SecretKeyGenerator.ToHex(bytes);
            SecretBase32 = SecretKeyGenerator.ToBase32(bytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    [RelayCommand]
    private void ClearSecret()
    {
        SecretBase64 = string.Empty;
        SecretHex = string.Empty;
        SecretBase32 = string.Empty;
    }

    // Пара ключей

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsRsa))]
    public partial int KeyTypeIndex { get; set; } // 0 = RSA, 1 = ECDSA

    [ObservableProperty]
    public partial int RsaSizeIndex { get; set; } = 1; // 3072

    [ObservableProperty]
    public partial int EcCurveIndex { get; set; }

    [ObservableProperty]
    public partial string KeyPassword { get; set; } = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(KeyPasswordChar))]
    public partial bool RevealKeyPassword { get; set; }

    public bool IsRsa => KeyTypeIndex == 0;
    public char KeyPasswordChar => RevealKeyPassword ? '\0' : '•';

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasPair))]
    public partial string PrivateKeyPem { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string PublicKeyPem { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string PublicJwk { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string PairDescription { get; set; } = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(PrivateUnencrypted))]
    public partial bool PrivateEncrypted { get; set; }

    [ObservableProperty]
    public partial bool IsBusy { get; set; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasError))]
    public partial string ErrorMessage { get; set; } = string.Empty;

    public bool HasPair => PrivateKeyPem.Length > 0;
    public bool PrivateUnencrypted => HasPair && !PrivateEncrypted;
    public bool HasError => ErrorMessage.Length > 0;

    [RelayCommand]
    private async Task GeneratePairAsync()
    {
        ErrorMessage = string.Empty;
        IsBusy = true;

        try
        {
            bool rsa = IsRsa;
            int rsaBits = RsaSizes[Math.Clamp(RsaSizeIndex, 0, RsaSizes.Length - 1)];
            EcCurveName curve = EcCurveIndex switch
            {
                1 => EcCurveName.P384,
                2 => EcCurveName.P521,
                _ => EcCurveName.P256
            };
            string? password = string.IsNullOrEmpty(KeyPassword) ? null : KeyPassword;

            KeyPairResult pair = await Task.Run(() => rsa
                ? KeyPairGenerator.GenerateRsa(rsaBits, password)
                : KeyPairGenerator.GenerateEc(curve, password));

            PrivateKeyPem = pair.PrivateKeyPem;
            PublicKeyPem = pair.PublicKeyPem;
            PublicJwk = pair.PublicJwk;
            PairDescription = pair.Description;
            PrivateEncrypted = password is not null;
        }
        catch (Exception ex)
        {
            ClearPair();
            ErrorMessage = ex.Message;
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private void ClearPairAndPassword()
    {
        ClearPair();
        KeyPassword = string.Empty;
        ErrorMessage = string.Empty;
    }

    private void ClearPair()
    {
        PrivateKeyPem = string.Empty;
        PublicKeyPem = string.Empty;
        PublicJwk = string.Empty;
        PairDescription = string.Empty;
        PrivateEncrypted = false;
    }
}