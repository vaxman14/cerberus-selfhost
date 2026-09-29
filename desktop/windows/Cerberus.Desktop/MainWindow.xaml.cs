using System.Diagnostics;
using System.IO;
using System.Windows;
using Microsoft.Web.WebView2.Core;
using Microsoft.Win32;

namespace Cerberus.Desktop;

public partial class MainWindow : Window
{
    private readonly RuntimeSupervisor _runtime = new();
    private CoreWebView2Environment? _webViewEnvironment;

    public MainWindow()
    {
        InitializeComponent();
        Loaded += OnLoaded;
        Closed += (_, _) => _runtime.Dispose();
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        try
        {
            _runtime.StatusChanged += message => Dispatcher.Invoke(() => StatusText.Text = message);
            var address = await _runtime.StartAsync();
            _webViewEnvironment = await CoreWebView2Environment.CreateAsync(
                userDataFolder: Path.Combine(_runtime.DataRoot, "WebView2"));
            await Browser.EnsureCoreWebView2Async(_webViewEnvironment);
            Browser.CoreWebView2.Settings.AreDevToolsEnabled = false;
            Browser.CoreWebView2.Settings.IsStatusBarEnabled = false;
            Browser.CoreWebView2.NewWindowRequested += OnNewWindowRequested;
            Browser.Source = address;
            Browser.Visibility = Visibility.Visible;
            LoadingPanel.Visibility = Visibility.Collapsed;
        }
        catch (Exception ex)
        {
            Progress.IsIndeterminate = false;
            Progress.Visibility = Visibility.Collapsed;
            StatusText.Text = $"Cerberus could not start.\n\n{ex.Message}";
            OpenLogsButton.Visibility = Visibility.Visible;
        }
    }

    private async void OnNewWindowRequested(object? sender, CoreWebView2NewWindowRequestedEventArgs args)
    {
        if (Uri.TryCreate(args.Uri, UriKind.Absolute, out var uri) &&
            uri.Scheme is "http" or "https")
        {
            args.Handled = true;
            Process.Start(new ProcessStartInfo(uri.AbsoluteUri) { UseShellExecute = true });
            return;
        }

        var deferral = args.GetDeferral();
        try
        {
            var popup = new ReportWindow();
            await popup.InitializeAsync(_webViewEnvironment!);
            args.NewWindow = popup.CoreWebView;
            popup.Show();
        }
        finally
        {
            deferral.Complete();
        }
    }

    private void OpenLogsButton_Click(object sender, RoutedEventArgs e)
    {
        Directory.CreateDirectory(_runtime.LogRoot);
        Process.Start(new ProcessStartInfo(_runtime.LogRoot) { UseShellExecute = true });
    }

    private void OpenDataFolder_Click(object sender, RoutedEventArgs e)
    {
        Directory.CreateDirectory(_runtime.DataRoot);
        Process.Start(new ProcessStartInfo(_runtime.DataRoot) { UseShellExecute = true });
    }

    private async void Backup_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new SaveFileDialog
        {
            Title = "Back up Cerberus",
            Filter = "Cerberus backup (*.tar.gz)|*.tar.gz",
            FileName = $"cerberus-backup-{DateTime.Now:yyyy-MM-dd-HHmm}.tar.gz",
            AddExtension = true,
        };
        if (dialog.ShowDialog(this) != true) return;
        try
        {
            await _runtime.ExportBackupAsync(dialog.FileName);
            MessageBox.Show(this, "Backup created and verified.", "Cerberus",
                MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Backup failed", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private async void ResetPassword_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new PasswordResetWindow { Owner = this };
        if (dialog.ShowDialog() != true) return;
        try
        {
            await _runtime.ResetPasswordAsync(dialog.Username, dialog.Password);
            Browser.CoreWebView2?.Reload();
            MessageBox.Show(this, "Password reset. Existing sessions were revoked.", "Cerberus",
                MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Password reset failed",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void Exit_Click(object sender, RoutedEventArgs e) => Close();
}
