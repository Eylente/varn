using System;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Varn.Core.Security.Jwt;
using Varn.Desktop.Localization;
using Varn.Core.Security.Keys;

namespace Varn.Desktop.ViewModels;

public partial class JwtViewModel : PageViewModel
{
    private static readonly JwtAlgorithm[] Algorithms = Enum.GetValues<JwtAlgorithm>();

    private enum SigLevel { None, Ok, Bad, Warn }

    private JwtDecodeResult _decoded = new();
    private SigLevel _sigLevel = SigLevel.None;

    public JwtViewModel() : base("Nav_Jwt", "IconJwt")
    {
        Loc.Instance.PropertyChanged += (_, _) => RefreshLocalized();
        RecomputeInspection();
    }

    [ObservableProperty]
    public partial int SelectedTabIndex { get; set; }

    // Просмотр и проверка

    [ObservableProperty]
    public partial string Token { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string VerifyKey { get; set; } = string.Empty;

    [ObservableProperty]
    public partial bool SecretIsBase64 { get; set; }

    partial void OnTokenChanged(string value) => RecomputeInspection();
    partial void OnVerifyKeyChanged(string value) => RecomputeInspection();
    partial void OnSecretIsBase64Changed(bool value) => RecomputeInspection();

    [ObservableProperty]
    public partial string HeaderJson { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string PayloadJson { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string AlgorithmText { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string SigHeadline { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string SigDetail { get; set; } = string.Empty;

    public bool HasSig => _sigLevel != SigLevel.None;
    public bool SigOk => _sigLevel == SigLevel.Ok;
    public bool SigBad => _sigLevel == SigLevel.Bad;
    public bool SigWarn => _sigLevel == SigLevel.Warn;
    public bool HasSigDetail => SigDetail.Length > 0;
    public bool HasDecoded => HeaderJson.Length > 0;

    public string IatLine => TimeLine("Jwt_Iat", _decoded.IssuedAt, null);

    public string NbfLine => TimeLine("Jwt_Nbf", _decoded.NotBefore,
        t => t > DateTime.Now ? "Jwt_NotYet" : "Jwt_Active");

    public string ExpLine => TimeLine("Jwt_Exp", _decoded.ExpirationTime,
        t => t < DateTime.Now ? "Jwt_Expired" : "Jwt_NotExpired");

    public bool HasIat => IatLine.Length > 0;
    public bool HasNbf => NbfLine.Length > 0;
    public bool HasExp => ExpLine.Length > 0;

    private void RecomputeInspection()
    {
        _decoded = JwtDecoder.Decode(Token);

        if (string.IsNullOrWhiteSpace(Token))
        {
            SetSignature(SigLevel.None, string.Empty, string.Empty);
        }
        else if (!_decoded.IsValidStructure)
        {
            SetSignature(SigLevel.Bad, L("Jwt_Malformed"), string.Empty);
        }
        else
        {
            ApplyVerification(JwtVerifier.Verify(Token, VerifyKey, SecretIsBase64));
        }

        bool ok = _decoded.IsValidStructure;
        HeaderJson = ok ? _decoded.HeaderJson : string.Empty;
        PayloadJson = ok ? _decoded.PayloadJson : string.Empty;
        AlgorithmText = ok ? _decoded.Algorithm : string.Empty;

        NotifyDerived();
    }

    private void ApplyVerification(JwtVerificationResult result)
    {
        switch (result.Status)
        {
            case JwtVerificationStatus.Valid:
                SetSignature(SigLevel.Ok, L("Jwt_SigValid"), string.Empty);
                break;
            case JwtVerificationStatus.InvalidSignature:
                SetSignature(SigLevel.Bad, L("Jwt_SigInvalid"), string.Empty);
                break;
            case JwtVerificationStatus.KeyMissing:
                SetSignature(SigLevel.Warn, L("Jwt_SigKeyMissing"), string.Empty);
                break;
            case JwtVerificationStatus.AlgorithmNone:
                SetSignature(SigLevel.Bad, L("Jwt_SigNone"), string.Empty);
                break;
            case JwtVerificationStatus.UnsupportedAlgorithm:
                SetSignature(SigLevel.Warn, L("Jwt_SigUnsupported"), result.Message ?? string.Empty);
                break;
            case JwtVerificationStatus.KeyInvalid:
                SetSignature(SigLevel.Warn, L("Jwt_SigKeyInvalid"), result.Message ?? string.Empty);
                break;
            default:
                SetSignature(SigLevel.Bad, L("Jwt_Malformed"), result.Message ?? string.Empty);
                break;
        }
    }

    private void SetSignature(SigLevel level, string headline, string detail)
    {
        _sigLevel = level;
        SigHeadline = headline;
        SigDetail = detail;
    }

    private void NotifyDerived()
    {
        OnPropertyChanged(nameof(HasSig));
        OnPropertyChanged(nameof(SigOk));
        OnPropertyChanged(nameof(SigBad));
        OnPropertyChanged(nameof(SigWarn));
        OnPropertyChanged(nameof(HasSigDetail));
        OnPropertyChanged(nameof(HasDecoded));
        OnPropertyChanged(nameof(IatLine));
        OnPropertyChanged(nameof(NbfLine));
        OnPropertyChanged(nameof(ExpLine));
        OnPropertyChanged(nameof(HasIat));
        OnPropertyChanged(nameof(HasNbf));
        OnPropertyChanged(nameof(HasExp));
    }

    private static string TimeLine(string labelKey, DateTime? time, Func<DateTime, string>? statusKey)
    {
        if (time is not { } t) return string.Empty;

        string line = $"{L(labelKey)}: {t:yyyy-MM-dd HH:mm:ss}";
        return statusKey is null ? line : $"{line} ({L(statusKey(t))})";
    }

    // Создание

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsGenHmac), nameof(GenKeyLabel))]
    public partial int GenAlgorithmIndex { get; set; }

    [ObservableProperty]
    public partial string GenKey { get; set; } = string.Empty;

    [ObservableProperty]
    public partial bool GenSecretIsBase64 { get; set; }

    [ObservableProperty]
    public partial string GenKeyPassword { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string GenKeyId { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string GenPayload { get; set; } =
        "{\n  \"sub\": \"1234567890\",\n  \"name\": \"Test User\"\n}";

    [ObservableProperty]
    public partial bool AddIssuedAt { get; set; } = true;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ExpiresText))]
    public partial double ExpiresInMinutes { get; set; } = 60;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasGeneratedToken))]
    public partial string GeneratedToken { get; set; } = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasGenWarning))]
    public partial string GenWarning { get; set; } = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasGenError))]
    public partial string GenError { get; set; } = string.Empty;

    public bool IsGenHmac => Algorithms[Math.Clamp(GenAlgorithmIndex, 0, Algorithms.Length - 1)].IsHmac();
    public string GenKeyLabel => IsGenHmac ? L("Jwt_GenKeySecret") : L("Jwt_GenKeyPrivate");

    public string ExpiresText => ExpiresInMinutes <= 0
        ? L("Jwt_NoExp")
        : $"{(int)ExpiresInMinutes} {L("Jwt_Min")}";

    public bool HasGeneratedToken => GeneratedToken.Length > 0;
    public bool HasGenWarning => GenWarning.Length > 0;
    public bool HasGenError => GenError.Length > 0;

    [RelayCommand]
    private void GenerateToken()
    {
        GenError = string.Empty;
        GenWarning = string.Empty;

        if (string.IsNullOrEmpty(GenKey))
        {
            GenError = L("Jwt_ErrNoKey");
            return;
        }

        try
        {
            JwtAlgorithm algorithm = Algorithms[Math.Clamp(GenAlgorithmIndex, 0, Algorithms.Length - 1)];
            string payload = BuildPayload();
            string? password = algorithm.IsHmac() || string.IsNullOrEmpty(GenKeyPassword) ? null : GenKeyPassword;
            string? keyId = string.IsNullOrWhiteSpace(GenKeyId) ? null : GenKeyId.Trim();

            JwtGenerationResult result = JwtGenerator.Generate(
                algorithm, GenKey, payload, keyId, GenSecretIsBase64, password);

            GeneratedToken = result.Token;
            GenWarning = result.Warning ?? string.Empty;
        }
        catch (Exception ex) when (ex is ArgumentException or FormatException or CryptographicException)
        {
            GeneratedToken = string.Empty;
            GenError = ex.Message;
        }
    }

    [RelayCommand]
    private void OpenInInspector()
    {
        if (GeneratedToken.Length == 0) return;

        Token = GeneratedToken;

        if (IsGenHmac)
        {
            VerifyKey = GenKey;
            SecretIsBase64 = GenSecretIsBase64;
        }
        else
        {
            // Для проверки нужен публичный ключ: восстанавливаем его из приватного
            string? password = string.IsNullOrEmpty(GenKeyPassword) ? null : GenKeyPassword;
            VerifyKey = KeyPairGenerator.TryDerivePublicPem(GenKey, password) ?? string.Empty;
            SecretIsBase64 = false;
        }

        SelectedTabIndex = 0;
    }

    private string BuildPayload()
    {
        JsonNode? node;
        try
        {
            node = JsonNode.Parse(GenPayload);
        }
        catch (JsonException ex)
        {
            throw new ArgumentException(L("Jwt_ErrPayload") + ex.Message);
        }

        if (node is not JsonObject obj)
            throw new ArgumentException(L("Jwt_ErrPayloadNotObject"));

        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (AddIssuedAt) obj["iat"] = now;
        if (ExpiresInMinutes > 0) obj["exp"] = now + (long)ExpiresInMinutes * 60;

        return obj.ToJsonString();
    }

    // Общее

    private void RefreshLocalized()
    {
        RecomputeInspection();
        OnPropertyChanged(nameof(GenKeyLabel));
        OnPropertyChanged(nameof(ExpiresText));
    }

    private static string L(string key) => Loc.Instance[key];
}