using Varn.Core.Security.Interfaces;
using Varn.Core.Security.Models;
using Varn.Core.Security.Services;
using BCrypt.Net;
using MaterialDesignThemes.Wpf;
using Microsoft.Win32;
using OtpNet;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using MaterialDesignThemes.Wpf;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Threading;
using Varn.Core.Security.Jwt;
using Varn.Core.Security.Keys;
using Varn.Core.Security.Otp;
using Varn.Core.Services;
using TotpService = Varn.Core.Security.Otp.TotpService;

namespace Varn.UI
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private readonly ExcelService _excelService = new();
        private string? _selectedFile;
        private readonly BatchHasher _batchHasher = new();

        private DispatcherTimer _totpTimer;
        private string _currentBase32Secret = string.Empty;

        public MainWindow()
        {
            InitializeComponent();
            InitTotpTimer();
            this.MaxHeight = SystemParameters.MaximizedPrimaryScreenHeight;
            string currentLang = Varn.UI.Properties.Settings.Default.UserLanguage;
            _isRussian = (currentLang == "ru");
            string pattern = GetLocalizedText("m_ArgonDetails", "{0} MB, {1} Iterations, {2} Threads");
            ActiveDetailsTxt.Text = string.Format(pattern, MemorySlider.Value, IterSlider.Value, ThreadSlider.Value);
            ActiveDetailsTxt.Visibility = Visibility.Visible;
        }

        private void InitTotpTimer()
        {
            _totpTimer = new DispatcherTimer();
            _totpTimer.Interval = TimeSpan.FromSeconds(1);
            _totpTimer.Tick += TotpTimer_Tick;
        }

        private void TitleBar_MouseDown(object sender, MouseButtonEventArgs e)
        {
            if (e.ChangedButton == MouseButton.Left)
                this.DragMove();
        }

        private void CloseBtn_Click(object sender, RoutedEventArgs e)
        {
            Application.Current.Shutdown();
        }

        private void MinimizeBtn_Click(object sender, RoutedEventArgs e)
        {
            this.WindowState = WindowState.Minimized;
        }

        private void MaximizeBtn_Click(object sender, RoutedEventArgs e)
        {
            if (this.WindowState == WindowState.Maximized)
            {
                this.WindowState = WindowState.Normal;
            }
            else
            {
                this.WindowState = WindowState.Maximized;
            }
        }

        private void SelectFile_Click(object sender, RoutedEventArgs e)
        {
            var openPicker = new OpenFileDialog { Filter = "Excel Files|*.xlsx" };
            if (openPicker.ShowDialog() == true)
            {
                if (_excelService.IsTemplateValid(openPicker.FileName))
                {
                    _selectedFile = openPicker.FileName;
                    FilePathTxt.Text = Path.GetFileName(_selectedFile);
                    FilePathTxt.BorderBrush = System.Windows.Media.Brushes.Cyan;
                    StartBtn.IsEnabled = true;
                }
                else
                {
                    string errorMsg = GetLocalizedText("m_InvalidTemplateMessage", "Invalid Template!");
                    string errorTitle = GetLocalizedText("m_InvalidTemplateTitle", "Format Error");
                    string errorFile = GetLocalizedText("m_InvalidFile", "Invalid file selected");

                    MessageBox.Show(errorMsg, errorTitle, MessageBoxButton.OK, MessageBoxImage.Warning);
                    FilePathTxt.Text = errorFile;
                    FilePathTxt.BorderBrush = System.Windows.Media.Brushes.Red;
                    StartBtn.IsEnabled = false;
                }
            }
        }

        private void CreateTemplate_Click(object sender, RoutedEventArgs e)
        {
            var savePicker = new SaveFileDialog { Filter = "Excel Files|*.xlsx", FileName = "Varn_Template.xlsx" };
            if (savePicker.ShowDialog() == true)
            {
                _excelService.CreateTemplate(savePicker.FileName);
            }
        }

        private void AlgoSelector_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (Argon2Settings == null || LegacySettings == null || BCryptSettings == null ||
                PBKDF2Settings == null) return;

            Argon2Settings.Visibility = Visibility.Collapsed;
            LegacySettings.Visibility = Visibility.Collapsed;
            BCryptSettings.Visibility = Visibility.Collapsed;
            PBKDF2Settings.Visibility = Visibility.Collapsed;

            switch (AlgoSelector.SelectedIndex)
            {
                case 0:
                    Argon2Settings.Visibility = Visibility.Visible;
                    break;
                case 1:
                    BCryptSettings.Visibility = Visibility.Visible;
                    break;
                case 2:
                    PBKDF2Settings.Visibility = Visibility.Visible;
                    break;
                case 3:
                    LegacySettings.Visibility = Visibility.Visible;
                    break;
            }

            UpdateActiveSettingsInfo();
        }

        private (PasswordAlgorithm Algorithm, HasherSettings Settings) ReadHashingSettings()
        {
            var algorithm = AlgoSelector.SelectedIndex switch
            {
                0 => PasswordAlgorithm.Argon2id,
                1 => PasswordAlgorithm.BCrypt,
                2 => PasswordAlgorithm.Pbkdf2,
                _ => PasswordAlgorithm.Sha256Legacy
            };

            var settings = new HasherSettings
            {
                Argon2 = new Argon2Options(
                    Iterations: (int)IterSlider.Value,
                    MemoryKb: (int)MemorySlider.Value * 1024,
                    Parallelism: (int)ThreadSlider.Value),
                BCryptWorkFactor = (int)WorkFactorSlider.Value,
                Pbkdf2Iterations = (int)Pbkdf2IterSlider.Value,
                Pbkdf2Algorithm = Pbkdf2AlgoSelector.SelectedIndex == 1
                    ? HashAlgorithmName.SHA512
                    : HashAlgorithmName.SHA256,
                LegacyUseSalt = UseSaltLegacy.IsChecked ?? false,
                // Временно: в старом интерфейсе хэш и соль показываются раздельно.
                // Переключатель PHC / Hash+Salt появится в новом UI.
                OutputFormat = PasswordOutputFormat.RawFields
            };

            return (algorithm, settings);
        }

        private async void StartHashing_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(_selectedFile)) return;

            string filePath = _selectedFile;
            var (algorithm, settings) = ReadHashingSettings();

            try
            {
                ProgressArea.Visibility = Visibility.Visible;
                StartBtn.IsEnabled = false;
                StatusTxt.Text = GetLocalizedText("m_StatusReading", "Reading Excel...");
                HashProgress.Value = 0;

                IPasswordHasher hasher = PasswordHasherFactory.Create(algorithm, settings);
                int parallelism = BatchHasher.RecommendedParallelism(
                    BatchHasher.EstimateMemoryPerHashBytes(algorithm, settings));

                var users = await Task.Run(() => _excelService.ReadEmployees(filePath));

                var progress = new Progress<int>(percent => HashProgress.Value = percent);
                var results = await Task.Run(() => _batchHasher.HashAll(users, hasher, parallelism, progress));

                StatusTxt.Text = GetLocalizedText("m_StatusSaving", "Saving...");
                var savePicker = new SaveFileDialog { Filter = "Excel Files|*.xlsx", FileName = "Results.xlsx" };
                if (savePicker.ShowDialog() == true)
                {
                    await Task.Run(() => _excelService.SaveResults(savePicker.FileName, results));

                    string successMsg = GetLocalizedText("m_SuccessMessage", "Success!");
                    string successTitle = GetLocalizedText("m_SuccessTitle", "Hashing Complete");
                    int withNotes = results.Count(r => !string.IsNullOrEmpty(r.Note));
                    if (withNotes > 0)
                        successMsg += $"\n\nRows with notes: {withNotes} (see the Note column).";

                    MessageBox.Show(successMsg, successTitle);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error: {ex.Message}");
            }
            finally
            {
                ProgressArea.Visibility = Visibility.Collapsed;
                StartBtn.IsEnabled = true;
            }
        }

        private void GenerateSingleHash_Click(object sender, RoutedEventArgs e)
        {
            string password = SinglePasswordBox.Password;
            if (string.IsNullOrEmpty(password)) return;

            try
            {
                var (algorithm, settings) = ReadHashingSettings();
                var result = PasswordHasherFactory.Create(algorithm, settings).Hash(password);

                ResultHashTxt.Text = result.Hash;
                ResultSaltTxt.Text = result.Salt ?? (result.SaltEmbeddedInHash
                    ? GetLocalizedText("m_SaltEmbedded", "Embedded in hash")
                    : GetLocalizedText("m_NoSaltUsed", "No salt used"));
                AlgoInfoTxt.Text = $"Algorithm: {result.Algorithm}" +
                                   (result.Warning is null ? "" : $"  ⚠ {result.Warning}");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error: {ex.Message}");
            }
        }

        private string GetLocalizedText(string resourceKey, string defaultValue = "")
        {
            return Application.Current.TryFindResource(resourceKey) as string ?? defaultValue;
        }

        private void UpdateActiveSettingsInfo()
        {
            if (ActiveMethodTxt == null) return;

            var selectedItem = (AlgoSelector.SelectedItem as ComboBoxItem)?.Content.ToString();
            ActiveMethodTxt.Text = selectedItem ?? GetLocalizedText("m_NotSelected", "Not Selected");
            ;

            if (AlgoSelector.SelectedIndex == 0)
            {
                string pattern = GetLocalizedText("m_ArgonDetails", "{0} MB, {1} Iterations, {2} Threads");
                ActiveDetailsTxt.Text =
                    string.Format(pattern, MemorySlider.Value, IterSlider.Value, ThreadSlider.Value);
                ActiveDetailsTxt.Visibility = Visibility.Visible;
            }
            else if (AlgoSelector.SelectedIndex == 1)
            {
                ActiveDetailsTxt.Text = $"WorkFactor {WorkFactorSlider.Value}";
                ActiveDetailsTxt.Visibility = Visibility.Visible;
            }
            else if (AlgoSelector.SelectedIndex == 2)
            {
                string hashAlgorithm = Pbkdf2AlgoSelector.SelectedIndex == 0 ? "SHA256" : "SHA512";
                string pattern = GetLocalizedText("m_Pbkdf2Details", "Iterations {0}, HashAlgorithm {1}");
                ActiveDetailsTxt.Text = string.Format(pattern, Pbkdf2IterSlider.Value, hashAlgorithm);
                ActiveDetailsTxt.Visibility = Visibility.Visible;
            }
            else if (AlgoSelector.SelectedIndex == 3)
            {
                ActiveDetailsTxt.Text = UseSaltLegacy.IsChecked == true
                    ? GetLocalizedText("m_LegacyWithSalt", "With Salt")
                    : GetLocalizedText("m_LegacyNoSalt", "No Salt (Unsafe)");
                ActiveDetailsTxt.Visibility = Visibility.Visible;
            }
            else
            {
                ActiveDetailsTxt.Visibility = Visibility.Collapsed;
            }
        }

        private void CopyHash_Click(object sender, RoutedEventArgs e) => Clipboard.SetText(ResultHashTxt.Text);
        private void CopySalt_Click(object sender, RoutedEventArgs e) => Clipboard.SetText(ResultSaltTxt.Text);

        private void GenerateKey_Click(object sender, RoutedEventArgs e)
        {
            int bits = 256;
            if (Rb128.IsChecked == true) bits = 128;
            if (Rb512.IsChecked == true) bits = 512;

            byte[] keyBytes = SecretKeyGenerator.Generate(bits);
            try
            {
                GeneratedKeyBase64Txt.Text = SecretKeyGenerator.ToBase64(keyBytes);
                GeneratedKeyHexTxt.Text = SecretKeyGenerator.ToHex(keyBytes);
                GeneratedKeyTotpTxt.Text = SecretKeyGenerator.ToBase32(keyBytes);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(keyBytes);
            }
        }

        private void CopyBase64_Click(object sender, RoutedEventArgs e)
        {
            if (!string.IsNullOrEmpty(GeneratedKeyBase64Txt.Text))
                Clipboard.SetText(GeneratedKeyBase64Txt.Text);
        }

        private void CopyHex_Click(object sender, RoutedEventArgs e)
        {
            if (!string.IsNullOrEmpty(GeneratedKeyHexTxt.Text))
                Clipboard.SetText(GeneratedKeyHexTxt.Text);
        }

        private void CopyTotpSecret_Click(object sender, RoutedEventArgs e)
        {
            if (!string.IsNullOrEmpty(GeneratedKeyTotpTxt.Text))
                Clipboard.SetText(GeneratedKeyTotpTxt.Text);
        }

        private void UseSaltLegacy_Unchecked(object sender, RoutedEventArgs e)
        {
            UpdateActiveSettingsInfo();
        }

        private void UseSaltLegacy_Checked(object sender, RoutedEventArgs e)
        {
            UpdateActiveSettingsInfo();
        }

        private bool _isRussian = false;

        private void ChangeLanguage_Click(object sender, RoutedEventArgs e)
        {
            _isRussian = !_isRussian;

            string targetLangCode = _isRussian ? "ru" : "en";

            string langPath = $"Localization/Lang.{targetLangCode}.xaml";

            try
            {
                ResourceDictionary newLangDict = new ResourceDictionary
                {
                    Source = new Uri(langPath, UriKind.Relative)
                };

                var appResources = Application.Current.Resources.MergedDictionaries;
                bool isReplaced = false;

                for (int i = 0; i < appResources.Count; i++)
                {
                    var dict = appResources[i];

                    if (dict.Source != null && dict.Source.OriginalString.Contains("Localization/Lang."))
                    {
                        appResources.RemoveAt(i);
                        appResources.Insert(i, newLangDict);
                        isReplaced = true;
                        break;
                    }
                }

                if (!isReplaced)
                {
                    appResources.Add(newLangDict);
                }

                Varn.UI.Properties.Settings.Default.UserLanguage = targetLangCode;
                Varn.UI.Properties.Settings.Default.Save();
                UpdateActiveSettingsInfo();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error switching language: {ex.Message}", "Localization Error", MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }

        private void MemorySlider_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
        {
            UpdateActiveSettingsInfo();
        }

        private void IterSlider_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
        {
            UpdateActiveSettingsInfo();
        }

        private void ThreadSlider_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
        {
            UpdateActiveSettingsInfo();
        }

        private void WorkFactorSlider_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
        {
            UpdateActiveSettingsInfo();
        }

        private void Pbkdf2IterSlider_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
        {
            UpdateActiveSettingsInfo();
        }

        private void Pbkdf2AlgoSelector_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            UpdateActiveSettingsInfo();
        }

        private void TotpSecretInput_TextChanged(object sender, TextChangedEventArgs e)
        {
            if (TotpDisplayCard != null && TotpDisplayCard.Visibility == Visibility.Visible)
            {
                TotpDisplayCard.Visibility = Visibility.Collapsed;
                _totpTimer?.Stop();
            }
        }

        private void ActivateTotp_Click(object sender, RoutedEventArgs e)
        {
            string input = TotpSecretInput.Text ?? string.Empty;

            if (string.IsNullOrWhiteSpace(input))
            {
                _totpTimer.Stop();
                TotpDisplayCard.Visibility = Visibility.Collapsed;
                return;
            }

            if (!TotpService.IsValidSecret(input))
            {
                _totpTimer.Stop();
                TotpDisplayCard.Visibility = Visibility.Collapsed;

                string errorMsg = Application.Current.FindResource("m_TotpInvalidKey") as string ?? "Invalid Base32 secret.";
                string errorTitle = Application.Current.FindResource("m_ErrorTitle") as string ?? "Error";
                MessageBox.Show(errorMsg, errorTitle, MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            _currentBase32Secret = TotpService.NormalizeSecret(input);
            TotpDisplayCard.Visibility = Visibility.Visible;
            UpdateTotpUI();
            _totpTimer.Start();
        }

        private void TotpTimer_Tick(object sender, EventArgs e)
        {
            UpdateTotpUI();
        }

        private void UpdateTotpUI()
        {
            if (string.IsNullOrEmpty(_currentBase32Secret)) return;

            try
            {
                var snapshot = TotpService.GetSnapshot(_currentBase32Secret);
                string code = snapshot.Code;

                TotpCodeTxt.Text = code.Length == 6 ? $"{code[..3]} {code[3..]}" : code;
                TotpTimeProgress.Value = snapshot.RemainingSeconds;

                string template = Application.Current.FindResource("m_TotpCountdownFormat") as string ?? "{0}s";
                TotpCountdownTxt.Text = string.Format(template, snapshot.RemainingSeconds);
            }
            catch
            {
                _totpTimer.Stop();
                TotpDisplayCard.Visibility = Visibility.Collapsed;
            }
        }

        private void CopyTotpCode_Click(object sender, RoutedEventArgs e)
        {
            string codeToCopy = TotpCodeTxt.Text.Replace(" ", "");
            if (!string.IsNullOrEmpty(codeToCopy) && codeToCopy != "000000")
            {
                Clipboard.SetText(codeToCopy);
            }
        }

        private void TxtJwtInput_TextChanged(object sender, TextChangedEventArgs e)
        {
            ProcessJwt();
        }

        private void TxtJwtSecret_TextChanged(object sender, TextChangedEventArgs e)
        {
            ProcessJwt();
        }

        private void ProcessJwt()
        {
            // Защита от раннего вызова до инициализации компонентов
            if (TxtJwtInput == null || TxtJwtHeader == null || TxtJwtPayload == null) return;

            string token = TxtJwtInput.Text;
            if (string.IsNullOrWhiteSpace(token))
            {
                ResetJwtView();
                return;
            }

            var decodeResult = JwtDecoder.Decode(token);

            if (decodeResult.IsValidStructure)
            {
                TxtJwtHeader.Text = decodeResult.HeaderJson;
                TxtJwtPayload.Text = decodeResult.PayloadJson;
                TxtJwtAlgorithm.Text = $"Algorithm: {decodeResult.Algorithm}";

                // Обработка времени жизни токена (exp)
                if (decodeResult.ExpirationTime.HasValue)
                {
                    string expStr = decodeResult.ExpirationTime.Value.ToString("yyyy-MM-dd HH:mm:ss");
                    if (decodeResult.ExpirationTime.Value < DateTime.Now)
                    {
                        TxtJwtExp.Text = $"Expired at: {expStr} (Token Expired)";
                        TxtJwtExp.Foreground = new SolidColorBrush(Colors.Tomato);
                    }
                    else
                    {
                        TxtJwtExp.Text = $"Expires at: {expStr}";
                        TxtJwtExp.Foreground = new SolidColorBrush(Colors.LightGreen);
                    }
                }
                else
                {
                    TxtJwtExp.Text = "Expiration: No 'exp' claim found";
                    TxtJwtExp.Foreground = new SolidColorBrush(Colors.Gray);
                }

                // Проверка криптографической подписи
                string secret = TxtJwtSecret.Text;
                if (string.IsNullOrEmpty(secret))
                {
                    BorderSigStatus.Background =
                        new SolidColorBrush((Color)ColorConverter.ConvertFromString("#332A15")); // Темно-желтый
                    IconSigStatus.Kind = MaterialDesignThemes.Wpf.PackIconKind.KeyAlertOutline;
                    IconSigStatus.Foreground = new SolidColorBrush(Colors.Orange);
                    TxtSigStatus.Text = Application.Current.FindResource("m_JwtStatusNoSecret") as string ??
                                        "Structure Valid. Provide secret to check signature.";
                    TxtSigStatus.Foreground = new SolidColorBrush(Colors.Orange);
                }
                else
                {
                    var verification = JwtVerifier.Verify(token, TxtJwtSecret.Text);
                    switch (verification.Status)
                    {
                        case JwtVerificationStatus.Valid:
                            SetSignatureStatus("#14321A", PackIconKind.ShieldCheckOutline, Colors.LightGreen,
                                Application.Current.FindResource("m_JwtStatusValid") as string ?? "Signature verified.");
                            break;

                        case JwtVerificationStatus.InvalidSignature:
                            SetSignatureStatus("#3A1919", PackIconKind.ShieldAlertOutline, Colors.Tomato,
                                Application.Current.FindResource("m_JwtStatusInvalid") as string ?? "Invalid signature.");
                            break;

                        case JwtVerificationStatus.KeyMissing:
                            SetSignatureStatus("#332A15", PackIconKind.KeyAlertOutline, Colors.Orange,
                                Application.Current.FindResource("m_JwtStatusNoSecret") as string ?? "Provide a secret to check the signature.");
                            break;

                        case JwtVerificationStatus.AlgorithmNone:
                            SetSignatureStatus("#3A1919", PackIconKind.ShieldAlertOutline, Colors.Tomato,
                                verification.Message ?? "alg is 'none'.");
                            break;

                        default: // UnsupportedAlgorithm, KeyInvalid, MalformedToken
                            SetSignatureStatus("#332A15", PackIconKind.KeyAlertOutline, Colors.Orange,
                                verification.Message ?? verification.Status.ToString());
                            break;
                    }
                }
            }
            else
            {
                ResetJwtView();
                BorderSigStatus.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#3A1919"));
                IconSigStatus.Kind = MaterialDesignThemes.Wpf.PackIconKind.CloseCircleOutline;
                IconSigStatus.Foreground = new SolidColorBrush(Colors.Tomato);
                TxtSigStatus.Text = Application.Current.FindResource("m_JwtStatusInvalidStructure") as string ??
                                    "Invalid JWT token structure!";
                TxtSigStatus.Foreground = new SolidColorBrush(Colors.Tomato);
            }
        }
        
        private void SetSignatureStatus(string backgroundHex, PackIconKind icon, Color foreground, string text)
        {
            BorderSigStatus.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString(backgroundHex));
            IconSigStatus.Kind = icon;
            IconSigStatus.Foreground = new SolidColorBrush(foreground);
            TxtSigStatus.Text = text;
            TxtSigStatus.Foreground = new SolidColorBrush(foreground);
        }

        private void ResetJwtView()
        {
            TxtJwtHeader.Text = string.Empty;
            TxtJwtPayload.Text = string.Empty;
            TxtJwtAlgorithm.Text = "Algorithm: —";
            TxtJwtExp.Text = "Expiration: —";
            TxtJwtExp.Foreground = new SolidColorBrush(Colors.Gray);

            BorderSigStatus.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2D2D2D"));
            IconSigStatus.Kind = MaterialDesignThemes.Wpf.PackIconKind.HelpCircleOutline;
            IconSigStatus.Foreground = new SolidColorBrush(Colors.Gray);
            TxtSigStatus.Text = Application.Current.FindResource("m_JwtStatusWaiting") as string ??
                                "Awaiting JWT token input...";
            TxtSigStatus.Foreground = new SolidColorBrush(Colors.Gray);
        }

        private void AboutBtn_Click(object sender, RoutedEventArgs e)
        {
            ModalDialogHost.IsOpen = true;
        }

        private void Hyperlink_RequestNavigate(object sender, System.Windows.Navigation.RequestNavigateEventArgs e)
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(e.Uri.AbsoluteUri)
                { UseShellExecute = true });
            e.Handled = true;
        }
    }
}