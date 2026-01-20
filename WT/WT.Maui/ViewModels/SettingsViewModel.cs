using System;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Maui.ApplicationModel;
using Microsoft.Maui.Storage;
using Microsoft.Extensions.DependencyInjection;
using WT.Maui.Services;

namespace WT.Maui.ViewModels
{
    public partial class SettingsViewModel : BaseViewModel
    {
        private readonly IAuthService _auth;

        public SettingsViewModel(IAuthService auth)
        {
            _auth = auth ?? throw new ArgumentNullException(nameof(auth));

            // Load persisted theme and recording prefs
            LoadPreferences();
        }

        // ---- Simple account/profile properties (used by the UI) ----
        [ObservableProperty] private string firstName = string.Empty;
        [ObservableProperty] private string profileUsername = string.Empty;
        [ObservableProperty] private string email = string.Empty;
        [ObservableProperty] private DateTime? memberSince;
        [ObservableProperty] private string bio = string.Empty;
        [ObservableProperty] private string countryCode = string.Empty;

        // ---- Recorder preferences ----
        [ObservableProperty]
        private int gpsAccuracy = 0; // bind to a picker (0 = Default)

        [ObservableProperty]
        private bool showRecordingWarning = true;

        // ---- Theme toggle ----
        [ObservableProperty]
        [NotifyPropertyChangedFor(nameof(ThemeDescription))]
        private bool isDarkMode;

        public string ThemeDescription => IsDarkMode ? "Dark" : "Light";

        // Messages
        [ObservableProperty] private string errorMessage = string.Empty;
        [ObservableProperty] private string successMessage = string.Empty;

        public void LoadPreferences()
        {
            try
            {
                // Theme (persisted as "Light" / "Dark" / "Unspecified")
                var theme = Preferences.Get("AppTheme", "Unspecified");
                if (theme == "Dark")
                {
                    // Use AppTheme from Microsoft.Maui.ApplicationModel
                    Microsoft.Maui.Controls.Application.Current.UserAppTheme = Microsoft.Maui.ApplicationModel.AppTheme.Dark;
                    IsDarkMode = true;
                }
                else if (theme == "Light")
                {
                    Microsoft.Maui.Controls.Application.Current.UserAppTheme = Microsoft.Maui.ApplicationModel.AppTheme.Light;
                    IsDarkMode = false;
                }
                else
                {
                    Microsoft.Maui.Controls.Application.Current.UserAppTheme = Microsoft.Maui.ApplicationModel.AppTheme.Unspecified;
                    IsDarkMode = Microsoft.Maui.Controls.Application.Current.RequestedTheme == Microsoft.Maui.ApplicationModel.AppTheme.Dark;
                }

                // Recorder prefs (simple local fallback)
                GpsAccuracy = Preferences.Get("RecordingPrefs_GpsAccuracy", 0);
                ShowRecordingWarning = Preferences.Get("RecordingPrefs_ShowRecordingWarning", true);
            }
            catch
            {
                // ignore preference read errors
            }
        }

        [RelayCommand]
        private Task ToggleThemeAsync()
        {
            try
            {
                if (IsDarkMode)
                {
                    Microsoft.Maui.Controls.Application.Current.UserAppTheme = Microsoft.Maui.ApplicationModel.AppTheme.Dark;
                    Preferences.Set("AppTheme", "Dark");
                }
                else
                {
                    Microsoft.Maui.Controls.Application.Current.UserAppTheme = Microsoft.Maui.ApplicationModel.AppTheme.Light;
                    Preferences.Set("AppTheme", "Light");
                }

                SuccessMessage = $"Theme set to {ThemeDescription}";
                ErrorMessage = string.Empty;
            }
            catch (Exception ex)
            {
                ErrorMessage = $"Failed to set theme: {ex.Message}";
                SuccessMessage = string.Empty;
            }

            return Task.CompletedTask;
        }

        [RelayCommand]
        private Task SavePreferencesAsync()
        {
            try
            {
                Preferences.Set("RecordingPrefs_GpsAccuracy", GpsAccuracy);
                Preferences.Set("RecordingPrefs_ShowRecordingWarning", ShowRecordingWarning);

                SuccessMessage = "Recorder preferences saved.";
                ErrorMessage = string.Empty;
            }
            catch (Exception ex)
            {
                ErrorMessage = $"Failed to save preferences: {ex.Message}";
                SuccessMessage = string.Empty;
            }

            return Task.CompletedTask;
        }

        [RelayCommand]
        private Task ResetPreferencesAsync()
        {
            try
            {
                Preferences.Remove("RecordingPrefs_GpsAccuracy");
                Preferences.Remove("RecordingPrefs_ShowRecordingWarning");

                // Reset local properties
                GpsAccuracy = 0;
                ShowRecordingWarning = true;

                SuccessMessage = "Recording preferences reset.";
                ErrorMessage = string.Empty;
            }
            catch (Exception ex)
            {
                ErrorMessage = $"Failed to reset preferences: {ex.Message}";
                SuccessMessage = string.Empty;
            }

            return Task.CompletedTask;
        }

        [RelayCommand]
        public async Task LogoutAsync()
        {
            if (IsBusy) return;
            IsBusy = true;

            try
            {
                await _auth.LogoutAsync().ConfigureAwait(false);

                // Navigate back to login page (resolve from DI)
                var loginPage = MauiProgram.ServiceProvider?.GetService<WT.Maui.Views.Auth.LoginPage>()
                                ?? ActivatorUtilities.CreateInstance<WT.Maui.Views.Auth.LoginPage>(MauiProgram.ServiceProvider!);

                await MainThread.InvokeOnMainThreadAsync(() =>
                {
                    Microsoft.Maui.Controls.Application.Current!.MainPage = new Microsoft.Maui.Controls.NavigationPage(loginPage);
                }).ConfigureAwait(false);
            }
            finally
            {
                IsBusy = false;
            }
        }
    }
}
