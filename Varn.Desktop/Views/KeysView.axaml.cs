using Avalonia;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;
using Avalonia.Platform.Storage;
using System.IO;
using System.Threading.Tasks;
using Varn.Desktop.Services;
using Varn.Desktop.ViewModels;

namespace Varn.Desktop.Views;

public partial class KeysView : UserControl
{
    public KeysView()
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

    private async void SavePrivate_Click(object? sender, RoutedEventArgs e) =>
        await SaveTextAsync("private-key", "pem", (DataContext as KeysViewModel)?.PrivateKeyPem);

    private async void SavePublic_Click(object? sender, RoutedEventArgs e) =>
        await SaveTextAsync("public-key", "pem", (DataContext as KeysViewModel)?.PublicKeyPem);

    private async void SaveJwk_Click(object? sender, RoutedEventArgs e) =>
        await SaveTextAsync("public-key", "json", (DataContext as KeysViewModel)?.PublicJwk);

    private async Task SaveTextAsync(string name, string extension, string? text)
    {
        if (string.IsNullOrEmpty(text) || TopLevel.GetTopLevel(this) is not { } top) return;

        var file = await top.StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            SuggestedFileName = $"{name}.{extension}",
            DefaultExtension = extension,
            FileTypeChoices =
            [
                new FilePickerFileType(extension.ToUpperInvariant()) { Patterns = [$"*.{extension}"] }
            ]
        });

        if (file is null) return;

        await using var stream = await file.OpenWriteAsync();
        if (stream.CanSeek) stream.SetLength(0); // перезапись существующего файла без остатков
        await using var writer = new StreamWriter(stream);
        await writer.WriteAsync(text);
    }
}