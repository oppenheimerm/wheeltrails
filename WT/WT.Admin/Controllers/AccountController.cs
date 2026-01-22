using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using WT.Application.DTO.Request.Account;
using WT.Application.DTO.Response;
using System.Net.Http.Json;

namespace WT.Admin.Controllers
{
    [ApiController]
    [Route("account")]
    public class AccountController : ControllerBase
    {
        private readonly IHttpClientFactory _httpFactory;
        public AccountController(IHttpClientFactory httpFactory)
        {
            _httpFactory = httpFactory;
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDTO model)
        {
            if (!ModelState.IsValid) return BadRequest(ModelState);

            // call the API login endpoint (replace with your API address / named client if needed)
            var client = _httpFactory.CreateClient("WheelTrailsAPI"); // or use ApiNoAuth
            var resp = await client.PostAsJsonAsync("api/account/identity/login", model);
            if (!resp.IsSuccessStatusCode)
            {
                // try to read the API error payload; fall back to a typed error response
                var error = await resp.Content.ReadFromJsonAsync<APIResponseAuthentication>();
                var unauthorizedResponse = error ?? new APIResponseAuthentication { Success = false, Message = "Login failed" };
                return Unauthorized(unauthorizedResponse);
            }

            var authResult = await resp.Content.ReadFromJsonAsync<APIResponseAuthentication>();
            if (authResult == null || !authResult.Success || string.IsNullOrEmpty(authResult.JwtToken))
                return Unauthorized(new { message = authResult?.Message ?? "Invalid credentials" });

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

            return Ok(new { success = true, message = "Signed in" });
        }

        [HttpPost("logout")]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return Ok(new { success = true });
        }
    }
}
