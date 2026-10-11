using Avalonia;
using Avalonia.Media;
using Varn.Desktop.Localization;

namespace Varn.Desktop.ViewModels;

public abstract class PageViewModel : ViewModelBase
{
    private readonly string _iconKey;
    private Geometry? _icon;

    protected PageViewModel(string titleKey, string iconKey)
    {
        TitleKey = titleKey;
        _iconKey = iconKey;
        Loc.Instance.PropertyChanged += (_, _) => OnPropertyChanged(nameof(Title));
    }

    public string TitleKey { get; }

    public string Title => Loc.Instance[TitleKey];

    /// <summary>Иконка пункта меню, берётся из ресурсов приложения (Styles/Icons.axaml).</summary>
    public Geometry? Icon
    {
        get
        {
            if (_icon is null &&
                Application.Current is { } app &&
                app.Resources.TryGetResource(_iconKey, null, out object? resource))
            {
                _icon = resource as Geometry;
            }

            return _icon;
        }
    }
}