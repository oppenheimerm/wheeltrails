using Blazored.LocalStorage;
using Microsoft.Extensions.Configuration;
using System.Net.Http.Json;
using System.Text.Json;
using WT.Application.DTO.Request.Account;
using WT.Application.DTO.Response;
using WT.Application.APIServiceLogs;

namespace WT.Application.Extensions
{
    /// <summary>
    /// Base HTTP service used by client-side application services to call the API.
    ///
    /// Responsibilities:
    /// - Holds a configured <see cref="HttpClient"/> instance for making API calls.
    /// - Exposes a helper <see cref="GetRefreshTokenAsync"/> that calls the server refresh endpoint
    /// which reads the HttpOnly refresh cookie and returns a fresh access token and optional
    /// user/session metadata.
    ///
    /// Security note:
    /// - This class intentionally does NOT persist tokens to local storage. The authentication
    /// pattern is: access tokens are kept in-memory on the Blazor WebAssembly client (see
    /// `WT.Client.Services.TokenService`) and refresh tokens are stored server-side in an
    /// HttpOnly cookie which the browser sends automatically when CORS and cookie policies
    /// permit. Avoid persisting tokens in localStorage to reduce XSS exposure.
    /// </summary>
    public class BaseService
    {
        readonly HttpClient _httpClient;
        readonly IConfiguration _configuration;
        readonly ILocalStorageService _localStorageService;
        readonly string? LocalStorageKey;

        /// <summary>
        /// Create a new instance of <see cref="BaseService"/>.
        /// </summary>
        /// <param name="httpClient">Pre-configured <see cref="HttpClient"/> with BaseAddress set to the API.</param>
        /// <param name="configuration">Application configuration for local storage keys and other settings.</param>
        /// <param name="localStorageService">Local storage service (used for non-sensitive UI data only).</param>
        public BaseService(
            HttpClient httpClient,
            IConfiguration configuration,
            ILocalStorageService localStorageService)
        {
            _httpClient = httpClient;
            _configuration = configuration;
            _localStorageService = localStorageService;
            LocalStorageKey = configuration["ApplicationSettings:LocalStorageKey"]!;
        }

        /// <summary>
        /// Calls the API refresh endpoint to exchange the HttpOnly refresh cookie for a new access token
        /// and lightweight session/user metadata.
        /// </summary>
        /// <remarks>
        /// Implementation notes:
        /// - The method issues a POST to "api/account/identity/refresh-token" with an empty body. The
        /// server reads the refresh token from an HttpOnly cookie and returns an <see cref="APIResponseAuthentication"/>.
        /// - On success this method constructs an <see cref="AuthenticatedSessionDTO"/> and returns it.
        /// - The returned DTO is intended for in-memory/session use only and should NOT be persisted to browser storage.
        /// - In the event of failure (no cookie, invalid refresh token, or server error) the method returns <c>null</c>.
        /// - Callers should update in-memory token storage (e.g., `WT.Client.Services.TokenService`) using the returned JWT.
        /// </remarks>
        /// <returns>An <see cref="AuthenticatedSessionDTO"/> on success; otherwise <c>null</c>.</returns>
        public async Task<AuthenticatedSessionDTO?> GetRefreshTokenAsync()
        {
            // This method no longer reads refresh tokens from browser local storage.
            // The authentication flow now uses an HttpOnly refresh cookie that the server
            // sets on successful login. To refresh the access token we call the server
            // refresh endpoint which will read the cookie and return a new access token
            // (and optionally rotate the refresh cookie). The client should store the
            // access token in-memory only (TokenService) and must not persist it to localStorage.

            try
            {
                // Call refresh endpoint; server reads the HttpOnly refresh cookie
                var response = await _httpClient.PostAsync("api/account/identity/refresh-token", null);

                if (!response.IsSuccessStatusCode)
                {
                    Console.WriteLine($"❌ Token refresh failed: {response.StatusCode}");
                    return null;
                }

                var result = await response.Content.ReadFromJsonAsync<APIResponseAuthentication>();
                if (result is null || result.Success != true)
                {
                    Console.WriteLine("❌ Token refresh response invalid or unsuccessful");
                    return null;
                }

                // Build an in-memory session DTO to return to caller. Do NOT persist this to local storage.
                var authSession = new AuthenticatedSessionDTO()
                {
                    JWtToken = result.JwtToken,
                    RefreshToken = result.RefreshToken,
                    TimeStamp = DateTime.UtcNow,
                    Id = result.User?.Id ?? Guid.Empty,
                    FirstName = result.User?.FirstName,
                    ProfileUsername = result.User?.ProfileUsername,
                    Email = result.User?.Email,
                    UserPhoto = result.User?.ProfilePicture,
                    Bio = result.User?.Bio
                };

                Console.WriteLine("✅ Token refreshed successfully (server rotated cookie)");
                return authSession;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"🔥 Exception in GetRefreshTokenAsync: {ex.Message}");
                LogException.LogExceptions(ex);
                return null;
            }
        }

        /// <summary>
        /// Helper to detect an Unauthorized (401) HTTP response.
        /// </summary>
        /// <param name="httpResponseMessage">The HTTP response to examine.</param>
        /// <returns><c>true</c> when the response status is <see cref="System.Net.HttpStatusCode.Unauthorized"/>.</returns>
        public static bool CheckIfUnauthorized(HttpResponseMessage httpResponseMessage)
        {
            return httpResponseMessage.StatusCode == System.Net.HttpStatusCode.Unauthorized;
        }

    }
}
