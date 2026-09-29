using System.Windows;
using System.Windows.Controls;

namespace Cerberus.Desktop;

internal sealed class PasswordResetWindow : Window
{
    private readonly TextBox _username = new();
    private readonly PasswordBox _password = new();
    private readonly PasswordBox _confirmation = new();

    public string Username => _username.Text.Trim();
    public string Password => _password.Password;

    public PasswordResetWindow()
    {
        Title = "Reset owner password";
        Width = 420;
        Height = 300;
        ResizeMode = ResizeMode.NoResize;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        var panel = new StackPanel { Margin = new Thickness(24) };
        panel.Children.Add(new TextBlock { Text = "Owner username" });
        _username.Margin = new Thickness(0, 4, 0, 14);
        panel.Children.Add(_username);
        panel.Children.Add(new TextBlock { Text = "New password (12+ characters)" });
        _password.Margin = new Thickness(0, 4, 0, 14);
        panel.Children.Add(_password);
        panel.Children.Add(new TextBlock { Text = "Confirm password" });
        _confirmation.Margin = new Thickness(0, 4, 0, 18);
        panel.Children.Add(_confirmation);
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        var cancel = new Button { Content = "Cancel", Width = 80, Margin = new Thickness(0, 0, 8, 0), IsCancel = true };
        var reset = new Button { Content = "Reset", Width = 80, IsDefault = true };
        reset.Click += (_, _) => Submit();
        buttons.Children.Add(cancel);
        buttons.Children.Add(reset);
        panel.Children.Add(buttons);
        Content = panel;
    }

    private void Submit()
    {
        if (Username.Length < 3)
        {
            MessageBox.Show(this, "Enter the owner username.", "Cerberus");
            return;
        }
        if (Password.Length < 12)
        {
            MessageBox.Show(this, "The password must contain at least 12 characters.", "Cerberus");
            return;
        }
        if (Password != _confirmation.Password)
        {
            MessageBox.Show(this, "The passwords do not match.", "Cerberus");
            return;
        }
        DialogResult = true;
    }
}
