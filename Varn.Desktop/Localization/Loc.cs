using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using Varn.Desktop.Services;

namespace Varn.Desktop.Localization;

public sealed class Loc : INotifyPropertyChanged
{
    public static Loc Instance { get; } = new();

    private readonly Dictionary<string, LocalizedString> _entries = new();
    private Dictionary<string, string> _current;

    private Loc()
    {
        string? saved = SettingsService.Current.Language;

        bool ru = saved is "ru" or "en"
            ? saved == "ru"
            : CultureInfo.CurrentUICulture.TwoLetterISOLanguageName == "ru";

        Language = ru ? "ru" : "en";
        _current = ru ? Strings.Ru : Strings.En;
    }

    public string Language { get; private set; }

    public string this[string key] => _current.TryGetValue(key, out var value) ? value : key;

    public event PropertyChangedEventHandler? PropertyChanged;

    /// <summary>Объект, который сам оповещает привязки при смене языка.</summary>
    public LocalizedString Entry(string key)
    {
        if (!_entries.TryGetValue(key, out var entry))
        {
            entry = new LocalizedString(key);
            _entries[key] = entry;
        }

        return entry;
    }

    public void SetLanguage(string code)
    {
        bool ru = code == "ru";
        Language = ru ? "ru" : "en";
        _current = ru ? Strings.Ru : Strings.En;

        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Language)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs("Item[]"));

        foreach (var entry in _entries.Values)
        {
            entry.Refresh();
        }

        SettingsService.Current.Language = Language;
        SettingsService.Save();
    }
}

public sealed class LocalizedString : INotifyPropertyChanged
{
    private readonly string _key;

    internal LocalizedString(string key) => _key = key;

    public string Value => Loc.Instance[_key];

    public event PropertyChangedEventHandler? PropertyChanged;

    internal void Refresh() =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Value)));
}