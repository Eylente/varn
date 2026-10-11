using System;
using System.IO;
using System.Text.Json;

namespace Varn.Desktop.Services;

public sealed class AppSettings
{
    /// <summary>"ru" или "en"; null означает язык системы.</summary>
    public string? Language { get; set; }
}

public static class SettingsService
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private static readonly string SettingsDirectory = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Varn");

    private static readonly string FilePath = Path.Combine(SettingsDirectory, "settings.json");

    // Объявлено после путей: статические поля инициализируются по порядку
    public static AppSettings Current { get; } = Load();

    public static void Save()
    {
        try
        {
            Directory.CreateDirectory(SettingsDirectory);

            // Пишем во временный файл и подменяем, чтобы сбой не оставил обрезанный файл настроек
            string temp = FilePath + ".tmp";
            File.WriteAllText(temp, JsonSerializer.Serialize(Current, JsonOptions));
            File.Move(temp, FilePath, overwrite: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Не удалось сохранить настройки: приложению это не мешает
        }
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
            // Повреждённый или недоступный файл не должен мешать запуску
        }

        return new AppSettings();
    }
}