using Blazored.LocalStorage;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using WT.Application.Extensions;
using WT.Application.Services;
using WT.Client;

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

builder.Services.AddScoped(sp => new HttpClient
{
    BaseAddress = new Uri(apiBaseUrl ?? "https://localhost:5001")
});

builder.Services.AddScoped<IAccountService, AccountService>();

// Register authentication
builder.Services.AddAuthorizationCore();
builder.Services.AddScoped<AuthenticationStateProvider, CustomAuthenticationStateProvider>();

// Optional: logging
builder.Logging.SetMinimumLevel(LogLevel.Information);

await builder.Build().RunAsync();
