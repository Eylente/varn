using System;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Varn.Core.Security.Models;
using Varn.Core.Security.Services;
using Varn.Desktop.Localization;

namespace Varn.Desktop.ViewModels;

public partial class HashViewModel : PageViewModel
{
    public HashViewModel() : this(new HashSettingsViewModel())
    {
    }

    public HashViewModel(HashSettingsViewModel settings) : base("Nav_Hash", "IconHash")
    {
        Settings = settings;
    }

    public HashSettingsViewModel Settings { get; }

    // Ввод

    [ObservableProperty]
    public partial string Password { get; set; } = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(PasswordChar))]
    public partial bool RevealPassword { get; set; }

    public char PasswordChar => RevealPassword ? '\0' : '•';

    // Результат

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasResult))]
    public partial string ResultHash { get; set; } = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasSalt))]
    public partial string ResultSalt { get; set; } = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasParameters))]
    public partial string ResultParameters { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string ResultAlgorithm { get; set; } = string.Empty;

    [ObservableProperty]
    public partial bool SaltEmbedded { get; set; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasWarning))]
    public partial string Warning { get; set; } = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasError))]
    public partial string ErrorMessage { get; set; } = string.Empty;

    [ObservableProperty]
    public partial bool IsBusy { get; set; }

    public bool HasResult => ResultHash.Length > 0;
    public bool HasSalt => ResultSalt.Length > 0;
    public bool HasParameters => ResultParameters.Length > 0;
    public bool HasWarning => Warning.Length > 0;
    public bool HasError => ErrorMessage.Length > 0;

    // Команды

    [RelayCommand]
    private async Task GenerateAsync()
    {
        ErrorMessage = string.Empty;

        if (string.IsNullOrEmpty(Password))
        {
            ErrorMessage = Loc.Instance["Hash_ErrEmpty"];
            return;
        }

        IsBusy = true;
        try
        {
            PasswordAlgorithm algorithm = Settings.SelectedAlgorithm;
            HasherSettings settings = Settings.BuildSettings();
            string password = Password;

            PasswordHashResult result = await Task.Run(
                () => PasswordHasherFactory.Create(algorithm, settings).Hash(password));

            ResultHash = result.Hash;
            ResultSalt = result.Salt ?? string.Empty;
            ResultParameters = result.ParametersJson ?? string.Empty;
            ResultAlgorithm = result.Algorithm;
            SaltEmbedded = result.SaltEmbeddedInHash;
            Warning = result.Warning ?? string.Empty;
        }
        catch (Exception ex)
        {
            ClearResult();
            ErrorMessage = ex.Message;
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private void Clear()
    {
        Password = string.Empty;
        ErrorMessage = string.Empty;
        ClearResult();
    }

    private void ClearResult()
    {
        ResultHash = string.Empty;
        ResultSalt = string.Empty;
        ResultParameters = string.Empty;
        ResultAlgorithm = string.Empty;
        SaltEmbedded = false;
        Warning = string.Empty;
    }
}