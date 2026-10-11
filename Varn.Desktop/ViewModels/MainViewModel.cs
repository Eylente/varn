using System.Collections.Generic;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Varn.Desktop.Localization;

namespace Varn.Desktop.ViewModels;

public partial class MainViewModel : ViewModelBase
{
    public MainViewModel()
    {
        var hashSettings = new HashSettingsViewModel();
        Pages =
        [
            new HashViewModel(hashSettings),
            new ExcelViewModel(hashSettings),
            new KeysViewModel(),
            new JwtViewModel(),
            new TotpViewModel(),
            new AboutViewModel()
        ];
        SelectedPage = Pages[0];

        Loc.Instance.PropertyChanged += (_, _) => OnPropertyChanged(nameof(LanguageButtonText));
    }

    public IReadOnlyList<PageViewModel> Pages { get; }

    [ObservableProperty]
    public partial PageViewModel? SelectedPage { get; set; }

    /// <summary>Показывает язык, на который переключит кнопка.</summary>
    public string LanguageButtonText => Loc.Instance.Language == "ru" ? "English" : "Русский";

    [RelayCommand]
    private void ToggleLanguage() =>
        Loc.Instance.SetLanguage(Loc.Instance.Language == "ru" ? "en" : "ru");
}