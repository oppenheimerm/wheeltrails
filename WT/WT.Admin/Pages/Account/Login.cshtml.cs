using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Authentication;
using System.Net.Http.Json;
using System.Text.Json;
using WT.Admin.Services;
using WT.Application.DTO.Request.Account;
using WT.Application.DTO.Response;

namespace WT.Admin.Pages.Account
{
    /// <summary>
    /// Razor Page model for the Admin login page.
    ///
    /// Responsibilities:
    /// - Render an antiforgery token on GET so the browser form can include it on POST.
    /// - Forward credentials to the backend API on POST, validate the response and
    ///   establish a local server authentication cookie via <see cref="HttpContext.SignInAsync"/>.
    /// - Store API JWT/refresh tokens in the server-scoped <see cref="IServerTokenService"/>
    ///   so server-side API calls (via <c>ApiClient</c>) can attach the bearer token.
    ///
    /// Note: This PageModel intentionally acts as a small authentication adapter between
    /// the browser and the API. It keeps sensitive tokens server-side and avoids complex
    /// cross-origin cookie handling in the browser.
    /// </summary>
    public class LoginModel : PageModel
    {
        private readonly IHttpClientFactory _httpFactory;
        private readonly ILogger<LoginModel> _logger;
        private readonly Microsoft.AspNetCore.Antiforgery.IAntiforgery _antiforgery;
        private readonly IServerTokenService _serverTokenService;

        /// <summary>
        /// Creates a new instance of <see cref="LoginModel"/>.
        /// Dependencies are injected by DI: an HttpClientFactory to call the API,
        /// a logger for diagnostics, the antiforgery service and the server token service.
        /// </summary>
        public LoginModel(IHttpClientFactory httpFactory, ILogger<LoginModel> logger, Microsoft.AspNetCore.Antiforgery.IAntiforgery antiforgery, IServerTokenService serverTokenService)
        {
            _httpFactory = httpFactory;
            _logger = logger;
            _antiforgery = antiforgery;
            _serverTokenService = serverTokenService;
        }

        [BindProperty]
        public LoginDTO Input { get; set; } = new LoginDTO();

        public string? ErrorMessage { get; set; }

        // Public property to hold the antiforgery request token so the page can
        // render it explicitly if the Html helper doesn't output the hidden input.
        public string? AntiForgeryToken { get; private set; }

        /// <summary>
        /// Handles GET requests to the login page.
        /// Ensures the antiforgery token and cookie are generated and exposes the
        /// request token in <see cref="AntiForgeryToken"/> so the view can render
        /// a hidden input if necessary.
        /// </summary>
        public void OnGet()
        {
            try
            {
                // Generate and store tokens (this sets an antiforgery cookie and
                // returns the request token). We store the request token so the
                // Razor page can emit it explicitly when rendering the form.
                var tokens = _antiforgery.GetAndStoreTokens(HttpContext);
                AntiForgeryToken = tokens.RequestToken;
                _logger.LogDebug("Antiforgery token generated (len={Len})", tokens.RequestToken?.Length ?? 0);
            }
            catch (Exception ex)
            {
                // Avoid failing the GET page render on logging errors — surface as warning only.
                _logger.LogWarning(ex, "Failed to generate antiforgery tokens on GET");
            }
        }

        /// <summary>
        /// Handles POST (form) submissions from the login page.
        /// Flow:
        /// 1. Validate model binding.
        /// 2. Call API login endpoint using a non-authenticated client (ApiNoAuth).
        /// 3. On success, store JWT/refresh tokens server-side and create a local auth cookie
        ///    using <see cref="HttpContext.SignInAsync"/> so the browser is authenticated.
        /// </summary>
        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                // Surface ModelState errors to the page so we can see why binding failed
                var errors = ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage).Where(m => !string.IsNullOrEmpty(m));
                ErrorMessage = string.Join("; ", errors);
                _logger.LogWarning("Login POST modelstate invalid: {Errors}", ErrorMessage);
                return Page();
            }

            try
            {
                var client = _httpFactory.CreateClient("ApiNoAuth");
                var resp = await client.PostAsJsonAsync("api/account/identity/login", Input);
                if (!resp.IsSuccessStatusCode)
                {
                    var err = await resp.Content.ReadFromJsonAsync<APIResponseAuthentication>();
                    ErrorMessage = err?.Message ?? "Login failed";
                    return Page();
                }

                var authResult = await resp.Content.ReadFromJsonAsync<APIResponseAuthentication>();
                if (authResult == null || !authResult.Success || string.IsNullOrEmpty(authResult.JwtToken))
                {
                    ErrorMessage = authResult?.Message ?? "Invalid credentials";
                    return Page();
                }

                // Store tokens server-side so the Admin host can attach them to API calls.
                try
                {
                    var expiresAt = GetExpiryFromJwt(authResult.JwtToken) ?? DateTime.UtcNow.AddMinutes(30);
                    _serverTokenService.SetTokens(authResult.JwtToken, authResult.RefreshToken, expiresAt);
                }
                catch (Exception ex)
                {
                    // Non-fatal: if token storage fails we still create the auth cookie,
                    // but subsequent API calls that rely on server tokens may fail.
                    _logger.LogWarning(ex, "Failed to set server tokens after login");
                }

                // Create claims and sign in (mirror AccountController behavior)
                var claims = new List<System.Security.Claims.Claim>
                {
                    new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.NameIdentifier, authResult.User!.Id.ToString()),
                    new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.Name, authResult.User.FirstName ?? string.Empty),
                    new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.Email, authResult.User.Email ?? string.Empty)
                };

                if (authResult.User.Roles != null)
                {
                    foreach (var r in authResult.User.Roles)
                        claims.Add(new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.Role, r.RoleName));
                }

                var identity = new System.Security.Claims.ClaimsIdentity(claims, Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationDefaults.AuthenticationScheme);
                var principal = new System.Security.Claims.ClaimsPrincipal(identity);

                var props = new Microsoft.AspNetCore.Authentication.AuthenticationProperties
                {
                    // This cookie controls the browser session for the Blazor Server circuit.
                    IsPersistent = false,
                    ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(30)
                };

                await HttpContext.SignInAsync(Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationDefaults.AuthenticationScheme, principal, props);

                // The Admin app uses Blazor components for the root page, not a Razor Page named Index.
                // Redirect to the site root so the Blazor host can handle the route.
                return Redirect("/");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Login failed");
                ErrorMessage = "An unexpected error occurred";
                return Page();
            }
        }

        private static DateTime? GetExpiryFromJwt(string jwtToken)
        {
            try
            {
                var parts = jwtToken.Split('.');
                if (parts.Length < 2) return null;
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
                if (jd.RootElement.TryGetProperty("exp", out var expEl) && expEl.ValueKind == JsonValueKind.Number && expEl.TryGetInt64(out var exp))
                {
                    return DateTimeOffset.FromUnixTimeSeconds(exp).UtcDateTime;
                }
            }
            catch { }
            return null;
        }
    }
}
