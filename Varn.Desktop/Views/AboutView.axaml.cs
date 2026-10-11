using System;
using Avalonia.Controls;
using Avalonia.Interactivity;

namespace Varn.Desktop.Views;

public partial class AboutView : UserControl
{
    public AboutView()
    {
        InitializeComponent();
    }

    private async void Link_Click(object? sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string url } &&
            Uri.TryCreate(url, UriKind.Absolute, out Uri? uri) &&
            TopLevel.GetTopLevel(this) is { } top)
        {
            await top.Launcher.LaunchUriAsync(uri);
        }
    }
}