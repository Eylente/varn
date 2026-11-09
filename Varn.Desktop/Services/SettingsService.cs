using System;
using System.IO;
using System.Text.Json;
using Varn.Core.Services;

namespace Varn.Desktop.Services;

public sealed class AppSettings
{
    /// <summary>"ru" или "en"; null означает язык системы.</summary>
    public string? Language { get; set; }

    /// <summary>Максимум потоков для пакетной обработки; null означает значение по умолчанию.</summary>
    public int? MaxThreads { get; set; }

    /// <summary>Доля памяти в процентах; null означает значение по умолчанию.</summary>
    public int? MemoryPercent { get; set; }
}

public static class SettingsService
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private static readonly string SettingsDirectory = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Varn");

    private static readonly string FilePath = Path.Combine(SettingsDirectory, "settings.json");

    public static AppSettings Current { get; } = Load();

    public static void Save()
    {
        try
        {
            Directory.CreateDirectory(SettingsDirectory);

            string temp = FilePath + ".tmp";
            File.WriteAllText(temp, JsonSerializer.Serialize(Current, JsonOptions));
            File.Move(temp, FilePath, overwrite: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            
        }
    }
    
    public static ResourceLimits GetResourceLimits()
    {
        int threads = Current.MaxThreads ?? ResourceLimits.DefaultThreads();
        double fraction = (Current.MemoryPercent ?? (int)(ResourceLimits.DefaultMemoryFraction * 100)) / 100.0;

        return new ResourceLimits(threads, fraction).Normalized();
    }

    private static AppSettings Load()
    {
        try
        {
            if (File.Exists(FilePath))
            {
                return JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(FilePath)) ?? new AppSettings();
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            
        }

        return new AppSettings();
    }
}