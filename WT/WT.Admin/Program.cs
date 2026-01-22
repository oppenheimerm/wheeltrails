using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Components.Authorization;
using WT.Admin.Components;
using WT.Admin.Services;
using WT.Application.DependencyInjection;
using WT.Application.Services;

var builder = WebApplication.CreateBuilder(args);

// Register identity/authentication services (before builder.Build())
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
       .AddCookie(options =>
       {
           options.LoginPath = "/Account/Login";
           options.LogoutPath = "/Account/Logout";
           // configure cookie options as needed
       });

// Register authorization and other services
builder.Services.AddAuthorization();

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

// Register HttpClient with specific base address for WT.Admin
builder.Services.AddHttpClient("WheelTrailsAPI", client =>
{
    client.BaseAddress = new Uri("https://localhost:5001"); // Your API URL
});

// For scoped HttpClient (alternative)
builder.Services.AddScoped(sp =>
{
    var httpClientFactory = sp.GetRequiredService<IHttpClientFactory>();
    return httpClientFactory.CreateClient("WheelTrailsAPI");
});

// register services in WT.Admin Program.cs (or Startup)
builder.Services.AddScoped<IServerTokenService, ServerTokenService>();
// adapter to satisfy ITokenService consumers (WASM-style providers)
builder.Services.AddScoped<WT.Application.Services.ITokenService, WT.Admin.Services.TokenServiceAdapter>();
builder.Services.AddTransient<BearerTokenHandler>();

// HttpClient used for API calls that need the token
builder.Services.AddHttpClient("ApiClient", client =>
{
    client.BaseAddress = new Uri(builder.Configuration["ApiBaseUrl"]);
}).AddHttpMessageHandler<BearerTokenHandler>();

// HttpClient for auth calls (login) that must not attach token
builder.Services.AddHttpClient("ApiNoAuth", client =>
{
    client.BaseAddress = new Uri(builder.Configuration["ApiBaseUrl"]);
});

builder.Services.AddScoped<AdminAuthenticationStateProvider>();
builder.Services.AddScoped<AuthenticationStateProvider>(sp => sp.GetRequiredService<AdminAuthenticationStateProvider>());

// App-level auth services
builder.Services.AddScoped<AuthService>();

// Register Application Services
builder.Services.AddApplicationServices();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();

app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();
