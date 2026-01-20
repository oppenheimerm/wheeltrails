using System;
using System.Threading.Tasks;
using Microsoft.Maui;
using Microsoft.Maui.Controls;
using Microsoft.Maui.ApplicationModel;
using Microsoft.Extensions.DependencyInjection;
using WT.Maui.Services;
using WT.Maui.Views.Auth;

namespace WT.Maui
{
    public partial class App : global::Microsoft.Maui.Controls.Application
    {
        private readonly IAuthService? _auth;
        private readonly IServiceProvider? _services;
        private readonly Exception? _startupException;

        public App(IAuthService? auth, IServiceProvider? services)
        {
            try
            {
                InitializeComponent();

                // Save references resolved by DI; don't throw here so we can show an error page instead of crashing
                _auth = auth;
                _services = services;
            }
            catch (Exception ex)
            {
                // Capture startup exception for diagnostic UI during CreateWindow
                _startupException = ex;
                Console.WriteLine($"⚠️ App startup exception: {ex}");
            }
        }

        // Create a Window whose root Page is either a Login NavigationPage or the AppShell.
        // This version shows a lightweight loading page and attempts a token restore in the background.
        protected override Window CreateWindow(IActivationState? activationState)
        {
            // If constructor failed (resource/XAML/DI problem), show a diagnostic page so app doesn't fail with opaque reflection exceptions.
            if (_startupException is not null)
            {
                var errPage = new ContentPage
                {
                    Title = "Startup Error",
                    Content = new ScrollView
                    {
                        Content = new VerticalStackLayout
                        {
                            Padding = 20,
                            Spacing = 12,
                            Children =
                            {
                                new Label { Text = "The app failed to start cleanly.", FontAttributes = FontAttributes.Bold, FontSize = 18 },
                                new Label { Text = "Open application output / device logcat for full details.", FontSize = 14 },
                                new Label { Text = $"Message: {_startupException.Message}", FontSize = 14, TextColor = Colors.Red },
                                new Label { Text = "StackTrace:", FontAttributes = FontAttributes.Bold, FontSize = 14 },
                                new Label { Text = _startupException.StackTrace ?? string.Empty, FontSize = 12 }
                            }
                        }
                    }
                };

                return new Window(errPage);
            }

            try
            {
                // If we don't have auth/services for some reason, fall back to a simple login path.
                if (_auth is null || _services is null)
                {
                    // Resolve LoginPage through DI so it receives its LoginViewModel (no direct 'new' here)
                    var loginPage = _services?.GetService<LoginPage>() ?? ActivatorUtilities.CreateInstance<LoginPage>(_services!);
                    var nav = new NavigationPage(loginPage);
                    return new Window(nav);
                }

                // Show a small loading page while attempting to restore session asynchronously.
                var loadingPage = new ContentPage
                {
                    Title = "Starting…",
                    Content = new Grid
                    {
                        Padding = 20,
                        Children =
                        {
                            new VerticalStackLayout
                            {
                                Spacing = 12,
                                HorizontalOptions = LayoutOptions.Center,
                                VerticalOptions = LayoutOptions.Center,
                                Children =
                                {
                                    new ActivityIndicator { IsRunning = true, Color = Colors.Gray, WidthRequest = 48, HeightRequest = 48 },
                                    new Label { Text = "Restoring session...", HorizontalTextAlignment = TextAlignment.Center, FontSize = 14 }
                                }
                            }
                        }
                    }
                };

                var window = new Window(loadingPage);

                // Kick off an async restore attempt. When complete, swap the Window.Page on the main thread.
                _ = Task.Run(async () =>
                {
                    try
                    {
                        // Fast, in-memory check first
                        if (_auth.IsLoggedIn)
                        {
                            await MainThread.InvokeOnMainThreadAsync(() =>
                            {
                                var shell = _services.GetService<AppShell>() ?? ActivatorUtilities.CreateInstance<AppShell>(_services);
                                window.Page = shell;
                            });
                            return;
                        }

                        // Attempt to restore session (refresh token). Implementation should return true if successful.
                        var restored = false;
                        try
                        {
                            restored = await _auth.RestoreSessionAsync();
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"⚠️ RestoreSessionAsync failed: {ex}");
                        }

                        if (restored)
                        {
                            await MainThread.InvokeOnMainThreadAsync(() =>
                            {
                                var shell = _services.GetService<AppShell>() ?? ActivatorUtilities.CreateInstance<AppShell>(_services);
                                window.Page = shell;
                            });
                        }
                        else
                        {
                            // Show login page if restore failed
                            await MainThread.InvokeOnMainThreadAsync(() =>
                            {
                                var loginPage = _services.GetService<LoginPage>() ?? ActivatorUtilities.CreateInstance<LoginPage>(_services);
                                window.Page = new NavigationPage(loginPage);
                            });
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"⚠️ CreateWindow restore task exception: {ex}");
                        await MainThread.InvokeOnMainThreadAsync(() =>
                        {
                            var errPage = new ContentPage
                            {
                                Title = "Startup Error",
                                Content = new ScrollView
                                {
                                    Content = new VerticalStackLayout
                                    {
                                        Padding = 20,
                                        Spacing = 12,
                                        Children =
                                        {
                                            new Label { Text = "The app failed to initialize the main window.", FontAttributes = FontAttributes.Bold, FontSize = 18 },
                                            new Label { Text = "Check device logs (adb logcat) for the full exception.", FontSize = 14 },
                                            new Label { Text = $"Message: {ex.Message}", FontSize = 14, TextColor = Colors.Red },
                                            new Label { Text = "StackTrace:", FontAttributes = FontAttributes.Bold, FontSize = 14 },
                                            new Label { Text = ex.StackTrace ?? string.Empty, FontSize = 12 }
                                        }
                                    }
                                }
                            };

                            window.Page = errPage;
                        });
                    }
                });

                return window;
            }
            catch (Exception ex)
            {
                // If something goes wrong creating the window (DI, page constructors, resources) show a diagnostic page.
                Console.WriteLine($"⚠️ CreateWindow exception: {ex}");
                var errPage = new ContentPage
                {
                    Title = "Startup Error",
                    Content = new ScrollView
                    {
                        Content = new VerticalStackLayout
                        {
                            Padding = 20,
                            Spacing = 12,
                            Children =
                            {
                                new Label { Text = "The app failed to initialize the main window.", FontAttributes = FontAttributes.Bold, FontSize = 18 },
                                new Label { Text = "Check device logs (adb logcat) for the full exception.", FontSize = 14 },
                                new Label { Text = $"Message: {ex.Message}", FontSize = 14, TextColor = Colors.Red },
                                new Label { Text = "StackTrace:", FontAttributes = FontAttributes.Bold, FontSize = 14 },
                                new Label { Text = ex.StackTrace ?? string.Empty, FontSize = 12 }
                            }
                        }
                    }
                };

                return new Window(errPage);
            }
        }
    }
}