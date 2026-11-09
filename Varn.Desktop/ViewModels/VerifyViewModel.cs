using System;
using System.Text;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Varn.Core.Security.Verification;
using Varn.Desktop.Localization;

namespace Varn.Desktop.ViewModels;

public partial class VerifyViewModel : PageViewModel
{
    private HashVerificationResult? _result;
    private bool _bcryptTruncated;

    public VerifyViewModel() : base("Nav_Verify", "IconVerify")
    {
        Loc.Instance.PropertyChanged += (_, _) => NotifyResult();
    }

    [ObservableProperty]
    public partial string Hash { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string Password { get; set; } = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(PasswordChar))]
    public partial bool RevealPassword { get; set; }

    public char PasswordChar => RevealPassword ? '\0' : '•';

    [ObservableProperty]
    public partial bool IsBusy { get; set; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasError))]
    public partial string ErrorMessage { get; set; } = string.Empty;

    public bool HasError => ErrorMessage.Length > 0;

    partial void OnHashChanged(string value) => SetResult(null);
    partial void OnPasswordChanged(string value) => SetResult(null);

    public bool HasResult => _result is not null;
    public bool ResultOk => _result?.Status == HashVerificationStatus.Match;
    public bool ResultBad => _result?.Status == HashVerificationStatus.NoMatch;

    public bool ResultWarn => _result is { } r &&
                              r.Status is not (HashVerificationStatus.Match or HashVerificationStatus.NoMatch);

    public string ResultHeadline => _result?.Status switch
    {
        HashVerificationStatus.Match => L("Verify_Match"),
        HashVerificationStatus.NoMatch => L("Verify_NoMatch"),
        HashVerificationStatus.UnrecognizedFormat => L("Verify_Unrecognized"),
        HashVerificationStatus.Malformed => L("Verify_Malformed"),
        HashVerificationStatus.UnsupportedParameters => L("Verify_Unsupported"),
        HashVerificationStatus.ParametersTooLarge => L("Verify_TooLarge"),
        _ => string.Empty
    };

    public string ResultDetail
    {
        get
        {
            if (_result?.Algorithm is null) return string.Empty;

            var text = new StringBuilder(string.Format(L("Verify_Algorithm"), _result.Algorithm));
            if (!string.IsNullOrEmpty(_result.Parameters))
            {
                text.Append("  ·  ").Append(string.Format(L("Verify_Parameters"), _result.Parameters));
            }

            return text.ToString();
        }
    }

    public bool HasDetail => ResultDetail.Length > 0;
    public bool ShowBcryptNote => _bcryptTruncated;

    [RelayCommand]
    private async Task VerifyAsync()
    {
        ErrorMessage = string.Empty;

        if (string.IsNullOrWhiteSpace(Hash))
        {
            SetResult(null);
            ErrorMessage = L("Verify_EmptyHash");
            return;
        }

        IsBusy = true;
        try
        {
            string hash = Hash;
            string password = Password;

            HashVerificationResult result = await Task.Run(() => PasswordVerifier.Verify(password, hash));

            _bcryptTruncated = result.Algorithm == "bcrypt" && Encoding.UTF8.GetByteCount(password) > 72;
            SetResult(result);
        }
        catch (Exception ex)
        {
            SetResult(null);
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
        Hash = string.Empty;
        Password = string.Empty;
        ErrorMessage = string.Empty;
        SetResult(null);
    }

    private void SetResult(HashVerificationResult? result)
    {
        _result = result;
        if (result is null) _bcryptTruncated = false;
        NotifyResult();
    }

    private void NotifyResult()
    {
        OnPropertyChanged(nameof(HasResult));
        OnPropertyChanged(nameof(ResultOk));
        OnPropertyChanged(nameof(ResultBad));
        OnPropertyChanged(nameof(ResultWarn));
        OnPropertyChanged(nameof(ResultHeadline));
        OnPropertyChanged(nameof(ResultDetail));
        OnPropertyChanged(nameof(HasDetail));
        OnPropertyChanged(nameof(ShowBcryptNote));
    }

    private static string L(string key) => Loc.Instance[key];
}