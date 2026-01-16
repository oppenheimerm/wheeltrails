using WT.Maui.Views;
using WT.Maui.Views.Auth;

namespace WT.Maui
{
    public partial class AppShell : Shell
    {
        public AppShell()
        {
            InitializeComponent();

            // Register navigable routes
            Routing.RegisterRoute("settings", typeof(SettingsPage));
            Routing.RegisterRoute("login", typeof(LoginPage));
            Routing.RegisterRoute("home", typeof(HomePage));
        }
    }
}
