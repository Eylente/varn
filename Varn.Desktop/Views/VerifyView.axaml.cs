using Avalonia.Controls;
using Avalonia.Input.Platform;
using Avalonia.Interactivity;
using Varn.Desktop.ViewModels;

namespace Varn.Desktop.Views;

public partial class VerifyView : UserControl
{
    public VerifyView()
    {
        InitializeComponent();
    }
    
    private async void Paste_Click(object? sender, RoutedEventArgs e)
    {
        if (DataContext is not VerifyViewModel vm) return;

        IClipboard? clipboard = TopLevel.GetTopLevel(this)?.Clipboard;
        if (clipboard is null) return;

        string? text = await clipboard.TryGetTextAsync();
        if (!string.IsNullOrWhiteSpace(text))
        {
            vm.Hash = text.Trim();
        }
    }
}