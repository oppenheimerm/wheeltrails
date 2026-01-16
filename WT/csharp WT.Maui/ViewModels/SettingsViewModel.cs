using System;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.Input;
using WT.Maui.Services;
using Microsoft.Maui.ApplicationModel; // for MainThread
using Microsoft.Extensions.DependencyInjection;

namespace WT.Maui.ViewModels
{
    public partial class SettingsViewModel : BaseViewModel
    {
        private readonly AuthService _auth;

        public SettingsViewModel(AuthService auth)
        {
            _auth = auth ?? throw new ArgumentNullException(nameof(auth));
        }

        [RelayCommand]
        public async Task LogoutAsync()
        {
            if (IsBusy) return;
            IsBusy = true;

            try
            {
                // stop background services as needed...
                await _auth.LogoutAsync().ConfigureAwait(false);

                // Resolve LoginPage from DI (use the global service provider as ViewModel doesn't have IServiceProvider)
                var loginPage = MauiProgram.ServiceProvider?.GetService<WT.Maui.Views.Auth.LoginPage>()
                                ?? ActivatorUtilities.CreateInstance<WT.Maui.Views.Auth.LoginPage>(MauiProgram.ServiceProvider!);

                await MainThread.InvokeOnMainThreadAsync(() =>
                {
                    // Clear navigation and show login
                    Application.Current!.MainPage = new NavigationPage(loginPage);
                }).ConfigureAwait(false);
            }
            finally
            {
                IsBusy = false;
            }
        }
    }
}