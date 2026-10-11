using Avalonia.Controls;
using Avalonia.Interactivity;
using Varn.Desktop.Services;

namespace Varn.Desktop.Views;

public partial class JwtView : UserControl
{
    public JwtView()
    {
        InitializeComponent();
    }

    private async void Copy_Click(object? sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string text } && text.Length > 0)
        {
            await ClipboardHelper.CopyWithAutoClearAsync(TopLevel.GetTopLevel(this)?.Clipboard, text);
        }
    }
}