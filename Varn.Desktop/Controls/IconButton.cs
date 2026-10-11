using System;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;

namespace Varn.Desktop.Controls;

/// <summary>Кнопка с иконкой и подписью. Выглядит и стилизуется как обычная Button.</summary>
public class IconButton : Button
{
    public static readonly StyledProperty<Geometry?> IconProperty =
        AvaloniaProperty.Register<IconButton, Geometry?>(nameof(Icon));

    public static readonly StyledProperty<string?> TextProperty =
        AvaloniaProperty.Register<IconButton, string?>(nameof(Text));

    private readonly PathIcon _icon = new()
    {
        Width = 16,
        Height = 16,
        VerticalAlignment = VerticalAlignment.Center,
        IsVisible = false
    };

    private readonly TextBlock _text = new()
    {
        VerticalAlignment = VerticalAlignment.Center,
        IsVisible = false
    };

    public IconButton()
    {
        Content = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            Spacing = 8,
            HorizontalAlignment = HorizontalAlignment.Center,
            Children = { _icon, _text }
        };
    }

    // Чтобы подхватывались стили и шаблон обычной кнопки (Button.primary, Button.ghost и т. д.)
    protected override Type StyleKeyOverride => typeof(Button);

    public Geometry? Icon
    {
        get => GetValue(IconProperty);
        set => SetValue(IconProperty, value);
    }

    public string? Text
    {
        get => GetValue(TextProperty);
        set => SetValue(TextProperty, value);
    }

    protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
    {
        base.OnPropertyChanged(change);

        if (change.Property == IconProperty)
        {
            _icon.Data = Icon;
            _icon.IsVisible = Icon is not null;
        }
        else if (change.Property == TextProperty)
        {
            _text.Text = Text;
            _text.IsVisible = !string.IsNullOrEmpty(Text);
        }
    }
}