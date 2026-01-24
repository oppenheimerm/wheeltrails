using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Components.Authorization;
using WT.Admin.Components;
using WT.Admin.Services;
using WT.Application.DependencyInjection;
using WT.Application.Services;
using System.Text.Json;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;

// -----------------------------------------------------------------------------
// WT.Admin Program (entry point)
//
// Purpose:
// - Host the Blazor Server admin UI.
// - Act as a presentation adapter for authentication: the Admin host
//   accepts browser form posts, forwards credentials to the API and then
//   issues a local server cookie (HttpContext.SignInAsync). This keeps
//   refresh tokens HttpOnly and avoids cross-origin cookie/CORS complexity
//   for the admin UI.
//
// Rationale summary (why this layout):
// - Admin is a Blazor Server app (interactive components) and expects
//   server-side cookie authentication for a traditional web UX.
// - The API remains the single source of truth for user credentials and
//   issues JWTs for API clients (WASM/third-party). Admin proxies login to API
//   then creates its own authentication cookie for browser sessions.
// - Razor Pages are used for the login form to leverage built-in
//   antiforgery support and a straightforward POST flow.
//
// Note: Comments in this file document the reason for each registration and
// the mapping order. Keep this file minimal and avoid adding business logic.
// -----------------------------------------------------------------------------
var builder = WebApplication.CreateBuilder(args);

// ----------------------------------------------------------------------------
// Diagnostic: Verify configuration is loaded
// ----------------------------------------------------------------------------
var apiBaseUrl = builder.Configuration["ConnectionStrings:BaseApiUrl"];
Console.WriteLine($"🔧 API Base URL: {apiBaseUrl}");

// ----------------------------------------------------------------------------
// Authentication & Authorization
// ----------------------------------------------------------------------------
// Admin uses cookie authentication for browser sessions. We configure the
// cookie here to be HttpOnly, Secure and with a reasonable expiration. This
// is intentionally different from the API which uses JWT bearer tokens.
// The Admin cookie is intended for the Blazor Server UI only.
// ----------------------------------------------------------------------------
// Register identity/authentication services (before builder.Build())
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
       .AddCookie(options =>
       {
           options.LoginPath = "/Account/Login";
           options.LogoutPath = "/Account/Logout";
           options.Cookie.HttpOnly = true;
           options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
           options.Cookie.SameSite = SameSiteMode.Lax;
           options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
       });

// Register authorization and other services
builder.Services.AddAuthorization();

// ----------------------------------------------------------------------------
// Component hosting and routing
// ----------------------------------------------------------------------------
// We register Razor Components (Blazor Server) and Razor Pages. Razor Pages
// are used for small server-rendered endpoints (login page) where we want the
// framework to handle antiforgery tokens reliably.
// ----------------------------------------------------------------------------
// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

// Register Razor Pages (server-side pages for login etc.). Razor Pages are
// mapped before the interactive components so page routes (e.g. /account/login)
// can take precedence and use server-side antiforgery tokens.
builder.Services.AddRazorPages();

// ----------------------------------------------------------------------------
// Application / Admin services
// ----------------------------------------------------------------------------
// Register admin-specific services and adapters. The Admin app communicates
// with the API via named HttpClients. Use "ApiNoAuth" for login calls (no
// bearer token attached) and "ApiClient" / BearerTokenHandler for requests
// that need a token attached.
// ----------------------------------------------------------------------------
// register services in WT.Admin Program.cs (or Startup)
builder.Services.AddScoped<IServerTokenService, ServerTokenService>();
// adapter to satisfy ITokenService consumers (WASM-style providers)
builder.Services.AddScoped<WT.Application.Services.ITokenService, WT.Admin.Services.TokenServiceAdapter>();
builder.Services.AddTransient<BearerTokenHandler>();

// Register server token service (per-circuit/request scoped)
builder.Services.AddScoped<IServerTokenService, ServerTokenService>();

// Make IHttpContextAccessor available to components/controllers that need access to HttpContext
builder.Services.AddHttpContextAccessor();

// Antiforgery: used by Razor Pages (login form) to render and validate
// __RequestVerificationToken. We configure minimal cookie options to keep
// behavior consistent with the Admin cookie policy.
builder.Services.AddAntiforgery(options =>
{
    // Keep default cookie settings compatible with our cookie policy
    options.Cookie.HttpOnly = true;
    options.Cookie.SameSite = SameSiteMode.Lax;
});

// HttpClient used for API calls that need the token
builder.Services.AddHttpClient("ApiClient", client =>
{
    client.BaseAddress = new Uri(apiBaseUrl ?? "https://localhost:5001");
}).AddHttpMessageHandler<BearerTokenHandler>();

// HttpClient for auth calls (login) that must not attach token
builder.Services.AddHttpClient("ApiNoAuth", client =>
{
    client.BaseAddress = new Uri(apiBaseUrl ?? "https://localhost:5001");
});

builder.Services.AddScoped<AdminAuthenticationStateProvider>();
builder.Services.AddScoped<AuthenticationStateProvider>(sp => sp.GetRequiredService<AdminAuthenticationStateProvider>());

// App-level auth services
builder.Services.AddScoped<AuthService>();
// If you have IAuthService interface registered elsewhere, register it here too
builder.Services.AddScoped<IAuthService, AuthService>();

// Register Application Services
builder.Services.AddApplicationServices();

// Configure HttpClient for API calls (simple client). JS fetch helper will be used for cookie operations where needed.
var apiBase = new Uri(apiBaseUrl ?? "https://localhost:5001");
builder.Services.AddScoped(sp => new HttpClient { BaseAddress = apiBase });

// ✅ Recommended: Typed HttpClient with proper configuration
builder.Services.AddHttpClient<ITrailService, TrailService>(client =>
{
    client.BaseAddress = new Uri(builder.Configuration["ConnectionStrings:BaseApiUrl"] ?? "https://localhost:5001");
    client.DefaultRequestHeaders.Add("Accept", "application/json");
})
.ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
{
    // Optional: Configure cookies, certificates, etc.
    UseCookies = true
});

// Build the app
var app = builder.Build();

// ----------------------------------------------------------------------------
// Middleware pipeline
// ----------------------------------------------------------------------------
// Order matters: HTTPS redirection -> Authentication -> Authorization -> Routing
// Razor Pages are mapped before interactive components so server-rendered
// endpoints (login) behave as expected.
// ----------------------------------------------------------------------------
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
// Antiforgery middleware must be registered when endpoints (Razor Pages) use
// antiforgery metadata (for example, @Html.AntiForgeryToken()). This must
// be placed after UseAuthentication/UseAuthorization and before mapping
// endpoint routes so the antiforgery middleware can validate tokens for
// incoming form POSTs.
app.UseAntiforgery();

app.MapStaticAssets();

// Map Razor Pages first so page routes like /account/login take precedence
app.MapRazorPages();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

// Local sign-in endpoint: forwards credentials to API, then issues a local auth cookie
app.MapPost("/account/local-signin", async (HttpContext http, WT.Application.DTO.Request.Account.LoginDTO model, IHttpClientFactory httpFactory) =>
{
    try
    {
        var client = httpFactory.CreateClient("ApiNoAuth");
        var resp = await client.PostAsJsonAsync("api/account/identity/login", model);
        if (!resp.IsSuccessStatusCode)
            return Results.Unauthorized();

        using var stream = await resp.Content.ReadAsStreamAsync();
        using var doc = await JsonDocument.ParseAsync(stream);
        var root = doc.RootElement;
        var success = root.TryGetProperty("success", out var successEl) && successEl.GetBoolean();
        if (!success)
            return Results.Unauthorized();

        var jwt = root.TryGetProperty("jwtToken", out var jwtEl) ? jwtEl.GetString() : null;
        if (string.IsNullOrEmpty(jwt))
            return Results.Unauthorized();

        // Parse claims from JWT payload (UI-only)
        IEnumerable<Claim> ParseClaimsFromJwt(string jwtToken)
        {
            var parts = jwtToken.Split('.');
            if (parts.Length < 2) yield break;
            var payload = parts[1];
            string s = payload.Replace('-', '+').Replace('_', '/');
            switch (s.Length % 4)
            {
                case 2: s += "=="; break;
                case 3: s += "="; break;
            }
            var bytes = Convert.FromBase64String(s);
            var json = System.Text.Encoding.UTF8.GetString(bytes);
            using var jd = JsonDocument.Parse(json);
            foreach (var prop in jd.RootElement.EnumerateObject())
            {
                if (prop.Name == "exp") continue;
                if (prop.Value.ValueKind == JsonValueKind.Array)
                {
                    foreach (var item in prop.Value.EnumerateArray())
                        yield return new Claim(prop.Name, item.ToString());
                }
                else
                {
                    yield return new Claim(prop.Name, prop.Value.ToString());
                }
            }
        }

        var claims = ParseClaimsFromJwt(jwt).ToList();
        // Map role claim names to ClaimTypes.Role if necessary
        var mappedClaims = claims.Select(c =>
        {
            if (c.Type.EndsWith("/role") || c.Type.EndsWith("/roles") || c.Type.Equals("role", StringComparison.OrdinalIgnoreCase))
                return new Claim(ClaimTypes.Role, c.Value);
            if (c.Type.Equals("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", StringComparison.OrdinalIgnoreCase) || c.Type.Equals("name", StringComparison.OrdinalIgnoreCase))
                return new Claim(ClaimTypes.Name, c.Value);
            if (c.Type.Equals("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier", StringComparison.OrdinalIgnoreCase) || c.Type.Equals("sub", StringComparison.OrdinalIgnoreCase))
                return new Claim(ClaimTypes.NameIdentifier, c.Value);
            return c;
        }).ToList();

        var identity = new ClaimsIdentity(mappedClaims, CookieAuthenticationDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(identity);

        var props = new AuthenticationProperties
        {
            IsPersistent = true,
            ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(30)
        };

        await http.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal, props);

        return Results.Ok();
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Local sign-in error: {ex}");
        return Results.StatusCode(500);
    }
});

app.Run();
