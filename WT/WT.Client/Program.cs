using Blazored.LocalStorage;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using WT.Application.Extensions;
using WT.Application.Services;
using WT.Client;
using WT.Client.Services;

var builder = WebAssemblyHostBuilder.CreateDefault(args);

builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

// ✅ Verify configuration is loaded
var apiBaseUrl = builder.Configuration["ConnectionStrings:BaseApiUrl"];
var localStorageKey = builder.Configuration["ApplicationSettings:LocalStorageKey"];

Console.WriteLine($"🔧 API Base URL: {apiBaseUrl}");
Console.WriteLine($"🔧 LocalStorageKey: {localStorageKey}");

if (string.IsNullOrEmpty(localStorageKey))
{
    Console.WriteLine("❌ ERROR: LocalStorageKey is not configured!");
}

// Register services
builder.Services.AddBlazoredLocalStorage();

// Register authentication and app services
builder.Services.AddScoped<IAccountService, AccountService>();

// Register authentication
builder.Services.AddAuthorizationCore();
builder.Services.AddScoped<AuthenticationStateProvider, CustomAuthenticationStateProvider>();
// TokenService should be a singleton in WASM so it persists across components
builder.Services.AddSingleton<ITokenService, TokenService>();

// Register FAB service
builder.Services.AddSingleton<IFabService, FabService>();

// Optional: logging
builder.Logging.SetMinimumLevel(LogLevel.Information);

// Configure HttpClient for API calls (simple client). JS fetch helper will be used for cookie operations where needed.
var apiBase = new Uri(apiBaseUrl ?? "https://localhost:5001");
builder.Services.AddScoped(sp => new HttpClient { BaseAddress = apiBase });

await builder.Build().RunAsync();
