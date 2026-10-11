using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Varn.Core.Security.Models;
using Varn.Core.Security.Services;
using Varn.Core.Services;
using Varn.Desktop.Localization;

namespace Varn.Desktop.ViewModels;

public enum ExcelInputState { None, Valid, Invalid }

public partial class ExcelViewModel : PageViewModel
{
    private readonly ExcelService _excel = new();
    private readonly BatchHasher _batch = new();
    private CancellationTokenSource? _cts;
    private (int Count, int Notes, int Threads)? _lastRun;

    public ExcelViewModel() : this(new HashSettingsViewModel())
    {
    }

    public ExcelViewModel(HashSettingsViewModel settings) : base("Nav_Excel", "IconExcel")
    {
        Settings = settings;

        Loc.Instance.PropertyChanged += (_, _) =>
        {
            OnPropertyChanged(nameof(InputStatus));
            OnPropertyChanged(nameof(SummaryText));
        };
    }

    public HashSettingsViewModel Settings { get; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasInput))]
    public partial string InputPath { get; set; } = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(InputStatus), nameof(IsInputValid), nameof(IsInputInvalid), nameof(CanRun))]
    public partial ExcelInputState InputState { get; set; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanRun))]
    public partial bool IsBusy { get; set; }

    [ObservableProperty]
    public partial double ProgressValue { get; set; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasError))]
    public partial string ErrorMessage { get; set; } = string.Empty;

    public bool HasInput => InputPath.Length > 0;
    public bool IsInputValid => InputState == ExcelInputState.Valid;
    public bool IsInputInvalid => InputState == ExcelInputState.Invalid;
    public bool CanRun => InputState == ExcelInputState.Valid && !IsBusy;
    public bool HasError => ErrorMessage.Length > 0;

    public string InputStatus => InputState switch
    {
        ExcelInputState.Valid => Loc.Instance["Excel_InputValid"],
        ExcelInputState.Invalid => Loc.Instance["Excel_InputInvalid"],
        _ => Loc.Instance["Excel_InputNone"]
    };

    public bool HasSummary => _lastRun is not null;

    public string SummaryText => _lastRun is { } r
        ? string.Format(Loc.Instance["Excel_Summary"], r.Count, r.Notes, r.Threads)
        : string.Empty;

    public void SetInputFile(string path)
    {
        InputPath = path;
        ErrorMessage = string.Empty;
        SetSummary(null);
        InputState = _excel.IsTemplateValid(path) ? ExcelInputState.Valid : ExcelInputState.Invalid;
    }

    public void CreateTemplate(string path)
    {
        try
        {
            ErrorMessage = string.Empty;
            _excel.CreateTemplate(path);
        }
        catch (Exception ex)
        {
            ErrorMessage = ex.Message;
        }
    }

    public async Task RunAsync(string outputPath)
    {
        if (!CanRun) return;

        ErrorMessage = string.Empty;
        SetSummary(null);
        ProgressValue = 0;
        IsBusy = true;
        _cts = new CancellationTokenSource();

        try
        {
            PasswordAlgorithm algorithm = Settings.SelectedAlgorithm;
            HasherSettings settings = Settings.BuildSettings();
            string input = InputPath;
            CancellationToken token = _cts.Token;
            var progress = new Progress<int>(percent => ProgressValue = percent);

            var outcome = await Task.Run(() =>
            {
                var users = _excel.ReadEmployees(input);
                var hasher = PasswordHasherFactory.Create(algorithm, settings);
                int threads = BatchHasher.RecommendedParallelism(
                    BatchHasher.EstimateMemoryPerHashBytes(algorithm, settings));

                var results = _batch.HashAll(users, hasher, threads, progress, token);
                _excel.SaveResults(outputPath, results);

                return (Count: results.Count,
                        Notes: results.Count(x => !string.IsNullOrEmpty(x.Note)),
                        Threads: threads);
            }, token);

            ProgressValue = 100;
            SetSummary(outcome);
        }
        catch (OperationCanceledException)
        {
            ErrorMessage = Loc.Instance["Excel_Cancelled"];
        }
        catch (Exception ex)
        {
            ErrorMessage = ex.Message;
        }
        finally
        {
            IsBusy = false;
            _cts?.Dispose();
            _cts = null;
        }
    }

    [RelayCommand]
    private void Cancel() => _cts?.Cancel();

    private void SetSummary((int Count, int Notes, int Threads)? value)
    {
        _lastRun = value;
        OnPropertyChanged(nameof(HasSummary));
        OnPropertyChanged(nameof(SummaryText));
    }
}