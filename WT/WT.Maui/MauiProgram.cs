using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System;
using WT.Maui.Handlers;
using WT.Maui.Services;
using WT.Maui.ViewModels;
using WT.Maui.Views;
using WT.Maui.Views.Auth;

namespace WT.Maui
{
    public static class MauiProgram
    {
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

            // Register AuthService as a typed HttpClient so HttpClient + handlers are created lazily.
            // AuthService must have ctor: AuthService(HttpClient http, NativeTokenService tokens)
            builder.Services.AddHttpClient<AuthService>(client =>
            {
                client.BaseAddress = apiBase;
                client.Timeout = TimeSpan.FromSeconds(30);
            })
            .AddHttpMessageHandler<AuthHandler>();

            // ViewModels
            builder.Services.AddTransient<SettingsViewModel>();
            builder.Services.AddTransient<LoginViewModel>();
            builder.Services.AddTransient<HomeViewModel>();

            // AppShell as singleton (app root)
            builder.Services.AddSingleton<AppShell>();

            // Pages (transient)
            builder.Services.AddTransient<SettingsPage>();
            builder.Services.AddTransient<LoginPage>();
            builder.Services.AddTransient<HomePage>();

            return builder.Build();
        }
    }
}
