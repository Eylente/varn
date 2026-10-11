using Varn.Desktop.Services;

namespace Varn.Desktop.ViewModels;

public sealed class AboutViewModel : PageViewModel
{
    public AboutViewModel() : base("Nav_About", "IconAbout")
    {
    }

    public string Version => $"v{AppInfo.Version}";
}