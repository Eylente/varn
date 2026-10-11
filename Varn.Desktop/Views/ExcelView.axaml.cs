using Avalonia;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;
using Avalonia.Platform.Storage;
using System.Threading.Tasks;
using Varn.Desktop.ViewModels;

namespace Varn.Desktop.Views;

public partial class ExcelView : UserControl
{
    private static readonly FilePickerFileType ExcelFiles = new("Excel (*.xlsx)") { Patterns = ["*.xlsx"] };

    public ExcelView()
    {
        InitializeComponent();
    }

    private async void Template_Click(object? sender, RoutedEventArgs e)
    {
        if (DataContext is not ExcelViewModel vm) return;

        string? path = await PickSavePathAsync("users-template.xlsx");
        if (path is not null) vm.CreateTemplate(path);
    }

    private async void PickInput_Click(object? sender, RoutedEventArgs e)
    {
        if (DataContext is not ExcelViewModel vm) return;
        if (TopLevel.GetTopLevel(this) is not { } top) return;

        var files = await top.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            AllowMultiple = false,
            FileTypeFilter = [ExcelFiles]
        });

        string? path = files.Count > 0 ? files[0].TryGetLocalPath() : null;
        if (path is not null) vm.SetInputFile(path);
    }

    private async void Run_Click(object? sender, RoutedEventArgs e)
    {
        if (DataContext is not ExcelViewModel vm || !vm.CanRun) return;

        string? path = await PickSavePathAsync("Results.xlsx");
        if (path is not null) await vm.RunAsync(path);
    }

    private async Task<string?> PickSavePathAsync(string suggestedName)
    {
        if (TopLevel.GetTopLevel(this) is not { } top) return null;

        var file = await top.StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            SuggestedFileName = suggestedName,
            DefaultExtension = "xlsx",
            FileTypeChoices = [ExcelFiles]
        });

        return file?.TryGetLocalPath();
    }
}