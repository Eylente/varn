using System;
using System.IO;
using Avalonia.Media.Imaging;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using QRCoder;
using Varn.Core.Security.Otp;
using Varn.Desktop.Localization;

namespace Varn.Desktop.ViewModels;

public partial class TotpViewModel : PageViewModel
{
    private static readonly int[] DigitsOptions = [6, 7, 8];
    private static readonly int[] PeriodOptions = [15, 30, 60];

    private static readonly TotpHashAlgorithm[] AlgorithmOptions =
        [TotpHashAlgorithm.Sha1, TotpHashAlgorithm.Sha256, TotpHashAlgorithm.Sha512];

    private enum VerifyState { None, Match, NoMatch }

    private readonly DispatcherTimer _timer;
    private bool _secretValid;
    private VerifyState _verify = VerifyState.None;

    public TotpViewModel() : base("Nav_Totp", "IconTotp")
    {
        _timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(500) };
        _timer.Tick += (_, _) => Refresh();

        Loc.Instance.PropertyChanged += (_, _) =>
        {
            Refresh();
            OnPropertyChanged(nameof(VerifyHeadline));
        };
    }

    public void StartTimer()
    {
        Refresh();
        _timer.Start();
    }

    public void StopTimer() => _timer.Stop();

    // Секрет и параметры

    [ObservableProperty]
    public partial string Secret { get; set; } = string.Empty;

    [ObservableProperty]
    public partial int DigitsIndex { get; set; } // 6

    [ObservableProperty]
    public partial int PeriodIndex { get; set; } = 1; // 30 секунд

    [ObservableProperty]
    public partial int AlgorithmIndex { get; set; } // SHA-1

    partial void OnSecretChanged(string value) => RecomputeAll();
    partial void OnDigitsIndexChanged(int value) => RecomputeAll();
    partial void OnPeriodIndexChanged(int value) => RecomputeAll();
    partial void OnAlgorithmIndexChanged(int value) => RecomputeAll();

    public bool IsSecretValid => _secretValid;
    public bool HasSecretError => Secret.Trim().Length > 0 && !_secretValid;

    private TotpOptions Options => new(
        DigitsOptions[Math.Clamp(DigitsIndex, 0, DigitsOptions.Length - 1)],
        PeriodOptions[Math.Clamp(PeriodIndex, 0, PeriodOptions.Length - 1)],
        AlgorithmOptions[Math.Clamp(AlgorithmIndex, 0, AlgorithmOptions.Length - 1)]);

    [RelayCommand]
    private void GenerateSecret() => Secret = TotpService.GenerateSecret();

    // Текущий код

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasCode), nameof(CurrentCodeRaw))]
    public partial string CurrentCode { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string PreviousCode { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string NextCode { get; set; } = string.Empty;

    [ObservableProperty]
    public partial double RemainingSeconds { get; set; }

    [ObservableProperty]
    public partial double PeriodSeconds { get; set; } = 30;

    [ObservableProperty]
    public partial string RemainingText { get; set; } = string.Empty;

    public bool HasCode => CurrentCode.Length > 0;
    public string CurrentCodeRaw => CurrentCode.Replace(" ", string.Empty);

    // Проверка кода

    [ObservableProperty]
    public partial string VerifyCode { get; set; } = string.Empty;

    [ObservableProperty]
    public partial int WindowIndex { get; set; } = 1; // ±1 период

    partial void OnVerifyCodeChanged(string value) => RecomputeVerify();
    partial void OnWindowIndexChanged(int value) => RecomputeVerify();

    public bool HasVerify => _verify != VerifyState.None;
    public bool VerifyOk => _verify == VerifyState.Match;
    public bool VerifyBad => _verify == VerifyState.NoMatch;

    public string VerifyHeadline => _verify switch
    {
        VerifyState.Match => L("Totp_VerifyOk"),
        VerifyState.NoMatch => L("Totp_VerifyBad"),
        _ => string.Empty
    };

    // otpauth и QR

    [ObservableProperty]
    public partial string Issuer { get; set; } = "Varn";

    [ObservableProperty]
    public partial string Account { get; set; } = "user@example.com";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasQr))]
    public partial Bitmap? QrImage { get; set; }

    partial void OnIssuerChanged(string value) => RebuildUri();
    partial void OnAccountChanged(string value) => RebuildUri();

    public bool HasQr => QrImage is not null;

    public string OtpUri => _secretValid && !string.IsNullOrWhiteSpace(Account)
        ? TotpService.BuildOtpAuthUri(Issuer, Account.Trim(), Secret, Options)
        : string.Empty;

    public bool HasUri => OtpUri.Length > 0;

    // Пересчёт

    private void RecomputeAll()
    {
        _secretValid = TotpService.IsValidSecret(Secret);
        OnPropertyChanged(nameof(IsSecretValid));
        OnPropertyChanged(nameof(HasSecretError));

        RebuildUri();
        Refresh();
    }

    private void Refresh()
    {
        if (!_secretValid)
        {
            CurrentCode = PreviousCode = NextCode = RemainingText = string.Empty;
            RemainingSeconds = 0;
            RecomputeVerify();
            return;
        }

        TotpOptions options = Options;
        DateTime now = DateTime.UtcNow;
        TimeSpan period = TimeSpan.FromSeconds(options.PeriodSeconds);

        TotpSnapshot current = TotpService.GetSnapshot(Secret, options, now);

        CurrentCode = Group(current.Code);
        PreviousCode = Group(TotpService.GetSnapshot(Secret, options, now - period).Code);
        NextCode = Group(TotpService.GetSnapshot(Secret, options, now + period).Code);
        PeriodSeconds = current.PeriodSeconds;
        RemainingSeconds = current.RemainingSeconds;
        RemainingText = string.Format(L("Totp_Remaining"), current.RemainingSeconds);

        RecomputeVerify();
    }

    private void RecomputeVerify()
    {
        VerifyState state = VerifyState.None;
        string code = VerifyCode.Replace(" ", string.Empty);

        if (_secretValid && code.Length > 0)
        {
            TotpOptions options = Options;

            // Пока код вводится не до конца, ничего не отмечаем
            if (code.Length >= options.Digits)
            {
                int window = Math.Clamp(WindowIndex, 0, 2);
                state = TotpService.Verify(Secret, code, options, window)
                    ? VerifyState.Match
                    : VerifyState.NoMatch;
            }
        }

        if (state == _verify) return;

        _verify = state;
        OnPropertyChanged(nameof(HasVerify));
        OnPropertyChanged(nameof(VerifyOk));
        OnPropertyChanged(nameof(VerifyBad));
        OnPropertyChanged(nameof(VerifyHeadline));
    }

    private void RebuildUri()
    {
        OnPropertyChanged(nameof(OtpUri));
        OnPropertyChanged(nameof(HasUri));

        Bitmap? old = QrImage;
        QrImage = HasUri ? CreateQr(OtpUri) : null;
        old?.Dispose();
    }

    private static Bitmap CreateQr(string text)
    {
        using var generator = new QRCodeGenerator();
        using QRCodeData data = generator.CreateQrCode(text, QRCodeGenerator.ECCLevel.M);
        using var png = new PngByteQRCode(data);
        byte[] bytes = png.GetGraphic(8);

        using var stream = new MemoryStream(bytes);
        return new Bitmap(stream);
    }

    private static string Group(string code)
    {
        int half = code.Length / 2;
        return $"{code[..half]} {code[half..]}";
    }

    private static string L(string key) => Loc.Instance[key];
}