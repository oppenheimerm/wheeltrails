using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System;
using WT.Maui.Handlers;
using WT.Maui.Services;
using WT.Maui.ViewModels;
using WT.Maui.Views;
using WT.Maui.Views.Auth;
using WT.Maui.Views.Trails;

namespace WT.Maui
{
    public static class MauiProgram
    {
        // Exposed service provider for DI resolution from non-DI locations (e.g. ViewModels that need to resolve pages)
        // Set once when the MauiApp is built.
        public static IServiceProvider? ServiceProvider { get; private set; }

        public static MauiApp CreateMauiApp()
        {
            var builder = MauiApp.CreateBuilder();
            builder
                .UseMauiApp<App>()
                .ConfigureFonts(fonts =>
                {
                    fonts.AddFont("Figtree-Bold.ttf", "FigtreeBold");
                    fonts.AddFont("Figtree-Medium.ttf", "FigtreeMedium");
                    fonts.AddFont("Figtree-Regular.ttf", "FigtreeRegular");
                    fonts.AddFont("Figtree-SemiBold.ttf", "FigtreeSemiBold");
                    fonts.AddFont("MaterialSymbols-Rounded.ttf", "MaterialSymbolsRounded");
                });

#if DEBUG
            builder.Logging.AddDebug();
#endif
            var apiBase = new Uri("https://api.wheelytrails.com/"); // adjust for dev

            // Token storage (singleton)
            builder.Services.AddSingleton<NativeTokenService>();

            // Refresh-only client (no AuthHandler) used to refresh tokens
            builder.Services.AddHttpClient("ApiRefreshClient", client =>
            {
                client.BaseAddress = apiBase;
                client.Timeout = TimeSpan.FromSeconds(30);
            });

            // Register the AuthHandler (it will use ApiRefreshClient to refresh)
            builder.Services.AddTransient<AuthHandler>();

            // Register AuthService as IAuthService using typed HttpClient so HttpClient + handlers are created lazily.
            // AuthService must have ctor: AuthService(HttpClient http, NativeTokenService tokens)
            builder.Services.AddHttpClient<IAuthService, AuthService>(client =>
            {
                client.BaseAddress = apiBase;
                client.Timeout = TimeSpan.FromSeconds(30);
            })
            .AddHttpMessageHandler<AuthHandler>();

            // Register TrailService as a typed HttpClient so requests benefit from AuthHandler and proper HttpClient lifecycle.
            builder.Services.AddHttpClient<TrailService>(client =>
            {
                client.BaseAddress = apiBase;
                client.Timeout = TimeSpan.FromSeconds(30);
            })
            .AddHttpMessageHandler<AuthHandler>();

            // ViewModels
            builder.Services.AddTransient<SettingsViewModel>();
            builder.Services.AddTransient<LoginViewModel>();
            builder.Services.AddTransient<HomeViewModel>();
            builder.Services.AddTransient<CreateTrailViewModel>();

            // AppShell as singleton (app root)
            builder.Services.AddSingleton<AppShell>();

            // Pages (transient)
            builder.Services.AddTransient<SettingsPage>();
            builder.Services.AddTransient<LoginPage>();
            builder.Services.AddTransient<HomePage>();
            builder.Services.AddTransient<Create>();


            builder.Services.AddSingleton<IConnectivity>(Connectivity.Current);
            builder.Services.AddSingleton<IGeolocation>(Geolocation.Default);
            builder.Services.AddSingleton<IMap>(Map.Default);

            var app = builder.Build();

            // capture the service provider for global access where DI isn't available
            ServiceProvider = app.Services;

            return app;
        }
    }
}
