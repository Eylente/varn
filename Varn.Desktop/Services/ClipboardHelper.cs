using System;
using System.Threading.Tasks;
using Avalonia.Input.Platform;
using Avalonia.Threading;

namespace Varn.Desktop.Services;

public static class ClipboardHelper
{
    /// <summary>Копирует текст и через указанное время очищает буфер, если там всё ещё этот текст.</summary>
    public static async Task CopyWithAutoClearAsync(IClipboard? clipboard, string text, int clearAfterSeconds = 30)
    {
        if (clipboard is null) return;

        await clipboard.SetTextAsync(text);
        _ = ClearLaterAsync(clipboard, text, clearAfterSeconds);
    }

    private static async Task ClearLaterAsync(IClipboard clipboard, string expected, int seconds)
    {
        await Task.Delay(TimeSpan.FromSeconds(seconds));

        try
        {
            await Dispatcher.UIThread.InvokeAsync(async () =>
            {
                string? current = await clipboard.TryGetTextAsync();
                if (current == expected) await clipboard.ClearAsync();
            });
        }
        catch
        {
            // Буфер обмена может быть недоступен (например, окно закрыто), это не критично.
        }
    }
}