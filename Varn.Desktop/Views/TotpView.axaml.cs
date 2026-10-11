using Avalonia.Controls;
using Avalonia.Interactivity;
using Varn.Desktop.Services;
using Varn.Desktop.ViewModels;

namespace Varn.Desktop.Views;

public partial class TotpView : UserControl
{
    public TotpView()
    {
        InitializeComponent();

        // Таймер идёт только пока вкладка на экране
        AttachedToVisualTree += (_, _) => (DataContext as TotpViewModel)?.StartTimer();
        DetachedFromVisualTree += (_, _) => (DataContext as TotpViewModel)?.StopTimer();
    }

    private async void Copy_Click(object? sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string text } && text.Length > 0)
        {
            await ClipboardHelper.CopyWithAutoClearAsync(TopLevel.GetTopLevel(this)?.Clipboard, text);
        }
    }
}