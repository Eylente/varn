using System;
using System.Security.Cryptography;
using CommunityToolkit.Mvvm.ComponentModel;
using Varn.Desktop.Localization;
using Varn.Core.Security.Models;

namespace Varn.Desktop.ViewModels;

public partial class HashSettingsViewModel : ViewModelBase
{
    
    // Порядок совпадает с порядком элементов в ComboBox
    private static readonly PasswordAlgorithm[] Algorithms =
    [
        PasswordAlgorithm.Argon2id,
        PasswordAlgorithm.BCrypt,
        PasswordAlgorithm.Pbkdf2,
        PasswordAlgorithm.Scrypt,
        PasswordAlgorithm.Sha256Legacy,
        PasswordAlgorithm.Md5Legacy,
        PasswordAlgorithm.Sha1Legacy
    ];

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(SelectedAlgorithm), nameof(IsArgon2), nameof(IsBCrypt), nameof(IsPbkdf2),
        nameof(IsScrypt), nameof(IsLegacy), nameof(HasFormatChoice))]
    public partial int AlgorithmIndex { get; set; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(UsePhc), nameof(UseRaw))]
    public partial int OutputFormatIndex { get; set; }

    public bool UsePhc
    {
        get => OutputFormatIndex == 0;
        set { if (value) OutputFormatIndex = 0; }
    }

    public bool UseRaw
    {
        get => OutputFormatIndex == 1;
        set { if (value) OutputFormatIndex = 1; }
    }

    public PasswordAlgorithm SelectedAlgorithm => Algorithms[Math.Clamp(AlgorithmIndex, 0, Algorithms.Length - 1)];
    public bool IsArgon2 => SelectedAlgorithm == PasswordAlgorithm.Argon2id;
    public bool IsBCrypt => SelectedAlgorithm == PasswordAlgorithm.BCrypt;
    public bool IsPbkdf2 => SelectedAlgorithm == PasswordAlgorithm.Pbkdf2;
    public bool IsScrypt => SelectedAlgorithm == PasswordAlgorithm.Scrypt;

    public bool IsLegacy => SelectedAlgorithm is PasswordAlgorithm.Sha256Legacy
        or PasswordAlgorithm.Md5Legacy or PasswordAlgorithm.Sha1Legacy;

    public bool HasFormatChoice => IsArgon2 || IsPbkdf2 || IsScrypt;

    [ObservableProperty] public partial double ArgonIterations { get; set; } = 3;
    [ObservableProperty] public partial double ArgonMemoryMb { get; set; } = 64;
    [ObservableProperty] public partial double ArgonParallelism { get; set; } = 4;

    [ObservableProperty] public partial double BcryptWorkFactor { get; set; } = 12;

    [ObservableProperty] public partial double Pbkdf2Iterations { get; set; } = 600_000;
    [ObservableProperty] public partial int Pbkdf2HashIndex { get; set; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ScryptCostDisplay))]
    public partial double ScryptLogN { get; set; } = 16;

    [ObservableProperty] public partial double ScryptBlockSize { get; set; } = 8;
    [ObservableProperty] public partial double ScryptParallelism { get; set; } = 2;

    [ObservableProperty] public partial bool LegacyUseSalt { get; set; } = true;

    public string ScryptCostDisplay => $"N = {(1L << (int)ScryptLogN):N0} (2^{(int)ScryptLogN})";

    public HasherSettings BuildSettings() => new()
    {
        Argon2 = new Argon2Options(
            Iterations: (int)ArgonIterations,
            MemoryKb: (int)ArgonMemoryMb * 1024,
            Parallelism: (int)ArgonParallelism),
        BCryptWorkFactor = (int)BcryptWorkFactor,
        Pbkdf2Iterations = (int)Pbkdf2Iterations,
        Pbkdf2Algorithm = Pbkdf2HashIndex == 1 ? HashAlgorithmName.SHA512 : HashAlgorithmName.SHA256,
        Scrypt = new ScryptOptions(1 << (int)ScryptLogN, (int)ScryptBlockSize, (int)ScryptParallelism),
        LegacyUseSalt = LegacyUseSalt,
        OutputFormat = OutputFormatIndex == 1 ? PasswordOutputFormat.RawFields : PasswordOutputFormat.Phc
    };
}