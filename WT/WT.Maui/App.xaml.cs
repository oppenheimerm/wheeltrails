using System;
using Microsoft.Maui;
using Microsoft.Maui.Controls;
using Microsoft.Extensions.DependencyInjection;
using WT.Maui.Services;
using WT.Maui.Views.Auth;

namespace WT.Maui
{
    public partial class App : global::Microsoft.Maui.Controls.Application
    {
        private readonly AuthService _auth;
        private readonly IServiceProvider _services;

        public App(AuthService auth, IServiceProvider services)
        {
            InitializeComponent();

            _auth = auth ?? throw new ArgumentNullException(nameof(auth));
            _services = services ?? throw new ArgumentNullException(nameof(services));
        }

        // Create a Window whose root Page is either a Login NavigationPage or the AppShell.
        protected override Window CreateWindow(IActivationState? activationState)
        {
            Page rootPage;

            if (_auth.IsLoggedIn)
            {
                // Resolve AppShell through DI (ensures constructor injection)
                rootPage = _services.GetService<AppShell>() ?? ActivatorUtilities.CreateInstance<AppShell>(_services);
            }
            else
            {
                // Resolve LoginPage through DI so it receives its LoginViewModel (no direct 'new' here)
                var loginPage = _services.GetService<LoginPage>() ?? ActivatorUtilities.CreateInstance<LoginPage>(_services);
                rootPage = new NavigationPage(loginPage);
            }

            return new Window(rootPage);
        }
    }
}