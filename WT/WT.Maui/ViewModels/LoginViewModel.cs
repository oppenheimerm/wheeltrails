using System;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Maui.ApplicationModel;
using Microsoft.Extensions.DependencyInjection;
using WT.Application.DTO.Request.Account;
using WT.Maui.Services;

namespace WT.Maui.ViewModels
{
    public partial class LoginViewModel : BaseViewModel
    {
        private readonly IAuthService _auth;
        private readonly IServiceProvider _services;

        // Use generator-backed fields so bindings update automatically.
        // If the generator is not available yet, see the "Quick fallback" note below.
        [ObservableProperty]
        private string email = string.Empty;

        [ObservableProperty]
        private string password = string.Empty;

        public LoginViewModel(IAuthService auth, IServiceProvider services)
        {
            _auth = auth ?? throw new ArgumentNullException(nameof(auth));
            _services = services ?? throw new ArgumentNullException(nameof(services));
        }

        [RelayCommand]
        private async Task LoginAsync()
            {
            ErrorMessage = string.Empty;
            IsBusy = true;
            try
            {
                var dto = new LoginDTO { Email = Email, Password = Password };
                var ok = await _auth.LoginAsync(dto);
                if (!ok)
                {
                    ErrorMessage = "Login failed. Check credentials.";
                    return;
                }

                // Replace the Window's root with AppShell (clears the login stack)
                await MainThread.InvokeOnMainThreadAsync(() =>
                {
                    var shell = _services.GetRequiredService<AppShell>();
                    Microsoft.Maui.Controls.Application.Current!.Windows[0].Page = shell;
                });
            }
            finally
            {
                IsBusy = false;
            }
        }
    }
}
