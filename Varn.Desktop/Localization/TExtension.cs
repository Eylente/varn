using System;
using Avalonia.Data;
using Avalonia.Markup.Xaml;

namespace Varn.Desktop.Localization;

/// <summary>Использование в XAML: Text="{loc:T Hash_Title}". Обновляется сразу при смене языка.</summary>
public sealed class TExtension : MarkupExtension
{
    public TExtension(string key) => Key = key;

    public string Key { get; set; }

    public override object ProvideValue(IServiceProvider serviceProvider) =>
        new ReflectionBinding("Value")
        {
            Source = Loc.Instance.Entry(Key),
            Mode = BindingMode.OneWay
        };
}