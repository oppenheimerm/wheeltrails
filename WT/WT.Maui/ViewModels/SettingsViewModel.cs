using System;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Maui.ApplicationModel;
using Microsoft.Extensions.DependencyInjection;
using WT.Maui.Services;
using WT.Maui.Views.Auth;

namespace WT.Maui.ViewModels
{
    public partial class SettingsViewModel : BaseViewModel
    {
        private readonly AuthService _auth;
        private readonly IServiceProvider _services;

        public SettingsViewModel(AuthService auth, IServiceProvider services)
        {
            _auth = auth ?? throw new ArgumentNullException(nameof(auth));
            _services = services ?? throw new ArgumentNullException(nameof(services));
        }

        /// <summary>
        /// Logout command executed from the Settings page.
        /// - Calls AuthService.LogoutAsync()
        /// - Stops background recorder (if registered)
        /// - Resets UI to the LoginPage on success
        /// </summary>
        [RelayCommand]
        public async Task LogoutAsync()
        {
            if (IsBusy) return;

            IsBusy = true;
            try
            {
                // Best-effort: stop any recorder or background services
                try
                {

                    // Leave for now, but comment out as we have not implemented background recording yet.
                    // var recorder = MauiProgram.ServiceProvider?.GetService(typeof(TrailRecorderService)) as TrailRecorderService;
                    // if (recorder != null)
                    // {
                    //     await recorder.StopAsync().ConfigureAwait(false);
                    // }
                }
                catch
                {
                    // ignore recorder stop failures (logout should continue)
                }

                // Call auth service to logout and clear tokens
                await _auth.LogoutAsync().ConfigureAwait(false);

                // after clearing tokens, replace Application.Current.MainPage assignment with:
                await Microsoft.Maui.ApplicationModel.MainThread.InvokeOnMainThreadAsync(() =>
                {
                    // Absolute route to login clears any back stack
                    var loginPage = _services.GetRequiredService<LoginPage>();
                    Microsoft.Maui.Controls.Application.Current!.Windows[0].Page = new NavigationPage(loginPage);
                }).ConfigureAwait(false);
            }
            finally
            {
                IsBusy = false;
            }
        }
    }
}
