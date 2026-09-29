using System.Windows;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.Wpf;

namespace Cerberus.Desktop;

internal sealed class ReportWindow : Window
{
    private readonly WebView2 _browser = new();
    public CoreWebView2 CoreWebView => _browser.CoreWebView2;

    public ReportWindow()
    {
        Title = "Cerberus report";
        Width = 1100;
        Height = 800;
        MinWidth = 720;
        MinHeight = 500;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        Content = _browser;
    }

    public async Task InitializeAsync(CoreWebView2Environment environment)
    {
        await _browser.EnsureCoreWebView2Async(environment);
        _browser.CoreWebView2.Settings.AreDevToolsEnabled = false;
        _browser.CoreWebView2.NewWindowRequested += (_, args) =>
        {
            args.Handled = true;
            if (Uri.TryCreate(args.Uri, UriKind.Absolute, out var uri) &&
                uri.Scheme is "http" or "https")
            {
                System.Diagnostics.Process.Start(
                    new System.Diagnostics.ProcessStartInfo(uri.AbsoluteUri) { UseShellExecute = true });
            }
        };
    }
}
