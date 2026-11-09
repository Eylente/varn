using System;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Varn.Core.Services;
using Varn.Desktop.Localization;
using Varn.Desktop.Services;

namespace Varn.Desktop.ViewModels;

public partial class SettingsViewModel : PageViewModel
{
    private readonly int _processors = Environment.ProcessorCount;
    private bool _loading;

    public SettingsViewModel() : base("Nav_Settings", "IconSettings")
    {
        ResourceLimits limits = SettingsService.GetResourceLimits();

        _loading = true;
        MaxThreads = limits.MaxThreads;
        MemoryPercent = Math.Round(limits.MemoryFraction * 100);
        _loading = false;

        Loc.Instance.PropertyChanged += (_, _) =>
        {
            OnPropertyChanged(nameof(IsRussian));
            OnPropertyChanged(nameof(IsEnglish));
            OnPropertyChanged(nameof(ThreadsText));
            OnPropertyChanged(nameof(ThreadsHint));
            OnPropertyChanged(nameof(MemoryText));
        };
    }

    public bool IsRussian
    {
        get => Loc.Instance.Language == "ru";
        set { if (value) Loc.Instance.SetLanguage("ru"); }
    }

    public bool IsEnglish
    {
        get => Loc.Instance.Language == "en";
        set { if (value) Loc.Instance.SetLanguage("en"); }
    }

    public double MaxThreadsLimit => _processors;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ThreadsText))]
    public partial double MaxThreads { get; set; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(MemoryText))]
    public partial double MemoryPercent { get; set; }

    partial void OnMaxThreadsChanged(double value)
    {
        if (_loading) return;

        SettingsService.Current.MaxThreads = (int)value;
        SettingsService.Save();
    }

    partial void OnMemoryPercentChanged(double value)
    {
        if (_loading) return;

        SettingsService.Current.MemoryPercent = (int)value;
        SettingsService.Save();
    }

    public string ThreadsText => string.Format(L("Settings_ThreadsValue"), (int)MaxThreads, _processors);

    public string ThreadsHint => string.Format(L("Settings_ThreadsHint"), _processors);

    public string MemoryText
    {
        get
        {
            double totalMb = BatchHasher.AvailableMemoryBytes() / (1024.0 * 1024.0);
            return string.Format(L("Settings_MemoryValue"), (int)MemoryPercent, totalMb * MemoryPercent / 100.0, totalMb);
        }
    }

    [RelayCommand]
    private void ResetLimits()
    {
        ResourceLimits defaults = ResourceLimits.Default;
        MaxThreads = defaults.MaxThreads;
        MemoryPercent = Math.Round(defaults.MemoryFraction * 100);

        SettingsService.Current.MaxThreads = null;
        SettingsService.Current.MemoryPercent = null;
        SettingsService.Save();
    }

    private static string L(string key) => Loc.Instance[key];
}