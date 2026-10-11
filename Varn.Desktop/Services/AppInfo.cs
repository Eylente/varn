using System.Reflection;

namespace Varn.Desktop.Services;

public static class AppInfo
{
    public const string GitHubUrl = "https://github.com/Eylente/varn";

    public static string Version { get; } = ReadVersion();

    private static string ReadVersion()
    {
        Assembly assembly = typeof(AppInfo).Assembly;

        string? informational = assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;

        if (!string.IsNullOrEmpty(informational))
        {
            return informational.Split('+')[0];
        }

        return assembly.GetName().Version?.ToString(3) ?? "0.0.0";
    }
}