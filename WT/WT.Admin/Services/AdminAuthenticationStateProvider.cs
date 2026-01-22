using Microsoft.AspNetCore.Components.Authorization;
using System.Security.Claims;
using System.Text.Json;
using System.Threading.Tasks;

namespace WT.Admin.Services
{
    /// <summary>
    /// Authentication state provider for Blazor Server.
    /// Builds a <see cref="ClaimsPrincipal"/> from the JWT stored in <see cref="IServerTokenService"/>.
    /// This provider is UI-focused and does not perform cryptographic token validation;
    /// server-side APIs must validate tokens independently.
    /// </summary>
    public class AdminAuthenticationStateProvider : AuthenticationStateProvider
    {
        private readonly IServerTokenService _tokenService;

        /// <summary>
        /// Initializes a new instance of <see cref="AdminAuthenticationStateProvider"/>.
        /// </summary>
        /// <param name="tokenService">Server-scoped token service holding the current JWT.</param>
        public AdminAuthenticationStateProvider(IServerTokenService tokenService)
        {
            _tokenService = tokenService;
        }

        /// <summary>
        /// Gets the current authentication state by reading the JWT from <see cref="IServerTokenService"/>.
        /// Returns an anonymous principal when no valid token is present.
        /// </summary>
        /// <returns>Authentication state representing the current user.</returns>
        public override Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            var token = _tokenService.AccessToken;
            if (string.IsNullOrEmpty(token) || _tokenService.IsExpired())
            {
                var anonymous = new ClaimsPrincipal(new ClaimsIdentity());
                return Task.FromResult(new AuthenticationState(anonymous));
            }

            // Parse JWT payload (UI-only, not cryptographic validation)
            var claims = JwtParser.ParseClaimsFromJwt(token);
            var identity = new ClaimsIdentity(claims, "jwt");
            var user = new ClaimsPrincipal(identity);
            return Task.FromResult(new AuthenticationState(user));
        }

        /// <summary>
        /// Notify Blazor that the authentication state has changed.
        /// Call this after updating/clearing the token in <see cref="IServerTokenService"/>.
        /// </summary>
        public void NotifyAuthenticationStateChanged()
        {
            base.NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
        }
    }

    /// <summary>
    /// Small helper to parse JWT payload claims without validating signature.
    /// Intended for UI claim extraction only.
    /// </summary>
    internal static class JwtParser
    {
        /// <summary>
        /// Parses claims from a JWT payload (base64url-decoded JSON).
        /// </summary>
        /// <param name="jwt">The JWT token string.</param>
        /// <returns>Enumeration of <see cref="Claim"/> instances extracted from the payload.</returns>
        public static IEnumerable<Claim> ParseClaimsFromJwt(string jwt)
        {
            var payload = jwt.Split('.')[1];
            var json = Base64UrlDecode(payload);
            var doc = JsonDocument.Parse(json);
            foreach (var prop in doc.RootElement.EnumerateObject())
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

        /// <summary>
        /// Decodes a base64url string to a UTF8 JSON string.
        /// </summary>
        /// <param name="input">Base64url-encoded string.</param>
        /// <returns>Decoded UTF8 string.</returns>
        private static string Base64UrlDecode(string input)
        {
            string s = input;
            s = s.Replace('-', '+').Replace('_', '/');
            switch (s.Length % 4)
            {
                case 2: s += "=="; break;
                case 3: s += "="; break;
            }
            var bytes = Convert.FromBase64String(s);
            return System.Text.Encoding.UTF8.GetString(bytes);
        }
    }
}
