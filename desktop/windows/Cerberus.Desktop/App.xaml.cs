using System.Threading;
using System.Windows;

namespace Cerberus.Desktop;

public partial class App : Application
{
    private Mutex? _singleInstance;

    protected override void OnStartup(StartupEventArgs e)
    {
        _singleInstance = new Mutex(true, "CerberusDesktop-3CB2470D-1E81-4456-82D3-74349D2D490A", out var created);
        if (!created)
        {
            MessageBox.Show("Cerberus is already running.", "Cerberus", MessageBoxButton.OK, MessageBoxImage.Information);
            Shutdown();
            return;
        }

        base.OnStartup(e);
        var window = new MainWindow();
        MainWindow = window;
        window.Show();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _singleInstance?.ReleaseMutex();
        _singleInstance?.Dispose();
        base.OnExit(e);
    }
}
