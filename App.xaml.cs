using System.Windows;
using HueThemeKit;
using RepoLegibility.Core;

namespace RepoLegibility;

public partial class App : Application
{
    // Before anything builds a pattern, App.xaml's parsing included: code from a stranger's zip can't stall a scan.
    static App() => Analyzer.LimitPatternTime();

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        HueContrast.Follow(this);

        DispatcherUnhandledException += (_, args) =>
        {
            // A main window that failed while loading can't own a dialog.
            HueMessage.Show(Current.MainWindow is { IsLoaded: true } owner ? owner : null, "Something went wrong",
                "RepoLegibility carried on, but the last action didn't finish." + Environment.NewLine + Environment.NewLine + args.Exception.Message);
            args.Handled = true;
        };
    }
}
