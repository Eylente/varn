using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;
using Varn.Desktop.Services;
using Varn.Desktop.ViewModels;

namespace Varn.Desktop.Views;

public partial class HashView : UserControl
{
    public HashView()
    {
        InitializeComponent();
    }
    
    private async void CopyHash_Click(object? sender, RoutedEventArgs e) =>
        await CopyAsync((DataContext as HashViewModel)?.ResultHash);

    private async void CopySalt_Click(object? sender, RoutedEventArgs e) =>
        await CopyAsync((DataContext as HashViewModel)?.ResultSalt);

    private async Task CopyAsync(string? text)
    {
        if (string.IsNullOrEmpty(text)) return;

        await ClipboardHelper.CopyWithAutoClearAsync(TopLevel.GetTopLevel(this)?.Clipboard, text);
    }
}