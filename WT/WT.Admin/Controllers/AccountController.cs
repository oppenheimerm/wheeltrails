using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using WT.Application.DTO.Request.Account;
using WT.Application.DTO.Response;
using System.Net.Http.Json;
using Microsoft.Extensions.Logging;

namespace WT.Admin.Controllers
{
    [ApiController]
    [Route("account")]
    public class AccountController : ControllerBase
    {
        private readonly IHttpClientFactory _httpFactory;
        private readonly ILogger<AccountController> _logger;
        private readonly WT.Admin.Services.IServerTokenService _serverTokenService;

        public AccountController(IHttpClientFactory httpFactory, ILogger<AccountController> logger, WT.Admin.Services.IServerTokenService serverTokenService)
        {
            _httpFactory = httpFactory ?? throw new ArgumentNullException(nameof(httpFactory));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _serverTokenService = serverTokenService ?? throw new ArgumentNullException(nameof(serverTokenService));
        }

        [HttpPost("login-old")]
        [Obsolete("Use the Razor Page /Pages/Account/Login.cshtml instead.")]
        public async Task<IActionResult> Login([FromForm] LoginDTO model)
        {
            // For plain HTML form posts we will redirect on error so the browser can render the login page.
            var isFormPost = Request.HasFormContentType;
            if (!ModelState.IsValid)
            {
                if (isFormPost)
                    return Redirect($"/account/login?error=Invalid+form+submission");

                return BadRequest(ModelState);
            }

            try
            {
                // call the API login endpoint (replace with your API address / named client if needed)
                var client = _httpFactory.CreateClient("WheelTrailsAPI"); // or use ApiNoAuth
                var resp = await client.PostAsJsonAsync("api/account/identity/login", model);
                if (!resp.IsSuccessStatusCode)
                {
                    // try to read the API error payload; fall back to a typed error response
                    var error = await resp.Content.ReadFromJsonAsync<APIResponseAuthentication>();
                    var unauthorizedResponse = error ?? new APIResponseAuthentication { Success = false, Message = "Login failed" };
                    if (isFormPost)
                        return Redirect($"/account/login?error={Uri.EscapeDataString(unauthorizedResponse.Message ?? "Login failed")}");

                    return Unauthorized(unauthorizedResponse);
                }

                var authResult = await resp.Content.ReadFromJsonAsync<APIResponseAuthentication>();
                if (authResult == null || !authResult.Success || string.IsNullOrEmpty(authResult.JwtToken))
                {
                    if (isFormPost)
                        return Redirect($"/account/login?error={Uri.EscapeDataString(authResult?.Message ?? "Invalid credentials")}");

                    return Unauthorized(new { message = authResult?.Message ?? "Invalid credentials" });
                }

                // Create claims from returned user DTO (example)
                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.NameIdentifier, authResult.User!.Id.ToString()),
                    new Claim(ClaimTypes.Name, authResult.User.FirstName ?? string.Empty),
                    new Claim(ClaimTypes.Email, authResult.User.Email ?? string.Empty)
                };

                // add role claims if present
                if (authResult.User.Roles != null)
                {
                    foreach (var r in authResult.User.Roles)
                        claims.Add(new Claim(ClaimTypes.Role, r.RoleName));
                }

                var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                var principal = new ClaimsPrincipal(identity);

                var authProps = new AuthenticationProperties
                {
                    IsPersistent = false, // set true if you want persistent cookies (Remember me)
                    AllowRefresh = false,
                    ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(30) // align with JWT expiry if desired
                };

                await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal, authProps);

                if (isFormPost)
                {
                    // Redirect back to admin UI root after successful signin
                    return Redirect("/");
                }

                return Ok(new { success = true, message = "Signed in" });
            }
            catch (Exception ex)
            {
                // Log the exception
                _logger.LogError(ex, "An error occurred during login");

                if (isFormPost)
                {
                    // Redirect with generic error message on form post
                    return Redirect("/account/login?error=An+unexpected+error+occurred");
                }

                // Return a 500 error response for API calls
                return StatusCode(500, new { success = false, message = "An unexpected error occurred" });
            }
        }

        [HttpPost("logout")]
        public async Task<IActionResult> Logout()
        {
            // Sign out the local authentication cookie so the browser session is terminated
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            // Clear any server-scoped tokens for this user/circuit so subsequent server API calls do not use stale tokens
            try
            {
                _serverTokenService.Clear();
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to clear server tokens during logout");
            }

            return Ok(new { success = true });
        }
    }
}
