using System;
using System.Net.Http.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Text.Json;

namespace WT.Admin.Services
{
    /// <summary>
    /// Server-scoped token manager interface.
    ///
    /// Responsibilities:
    /// - Store the current access and refresh tokens for the currently signed-in admin user (server-side, scoped lifetime).
    /// - Expose token metadata (expiration) and provide a mechanism to refresh tokens by calling the API refresh endpoint.
    /// - Notify consumers when tokens change so the application can update Authorization headers or UI state.
    ///
    /// Security note: tokens are stored in-memory by default (scoped). For a multi-node deployment use a distributed
    /// cache or persistent store if you require tokens to survive process restarts or to be shared across nodes.
    /// </summary>
    public interface IServerTokenService
    {
        /// <summary>
        /// Current access token (JWT) or null if none is set.
        /// </summary>
        string? AccessToken { get; }

        /// <summary>
        /// Current refresh token (if available). Keep this secret and do not expose to the browser.
        /// </summary>
        string? RefreshToken { get; }

        /// <summary>
        /// UTC expiration time of the current access token.
        /// </summary>
        DateTime ExpiresAt { get; }

        /// <summary>
        /// Set both access and refresh tokens and the access token expiry time. Implementations should notify
        /// subscribers by raising <see cref="TokenChanged"/>.
        /// </summary>
        void SetTokens(string accessToken, string? refreshToken, DateTime expiresAt);

        /// <summary>
        /// Compatibility helper: set only the access token and expiry. Prefer <see cref="SetTokens"/> when
        /// a refresh token is also available.
        /// </summary>
        void SetAccessToken(string token, DateTime expiresAt);

        /// <summary>
        /// Clear all stored tokens and notify subscribers.
        /// </summary>
        void Clear();

        /// <summary>
        /// Returns true when no access token is present or when the token is expired.
        /// </summary>
        bool IsExpired();

        /// <summary>
        /// Attempts to refresh the access token using the API refresh endpoint. The default implementation
        /// calls the API via the provided <see cref="IHttpClientFactory"/> and updates stored tokens on success.
        /// Returns true when refresh succeeded and tokens were updated.
        /// </summary>
        Task<bool> TryRefreshAsync(IHttpClientFactory httpFactory, CancellationToken cancellationToken = default);

        /// <summary>
        /// Event raised when token values change (set or cleared). Consumers should update Authorization headers
        /// or trigger UI refresh when this event fires.
        /// </summary>
        event Action? TokenChanged;
    }

    /// <summary>
    /// Default in-memory implementation of <see cref="IServerTokenService"/>
    /// Register as scoped so each Blazor Server circuit/request gets its own token storage.
    ///
    /// Notes:
    /// - This class is intentionally simple: tokens are kept in memory and will be lost when the process restarts.
    /// - Use SetTokens(...) after successful login to populate the service (see example in README).
    /// - TryRefreshAsync calls the API refresh endpoint `api/account/identity/refresh-token-native` using the named
    ///   HttpClient `ApiNoAuth`. Adjust the endpoint name to match your API if necessary.
    /// </summary>
    public class ServerTokenService : IServerTokenService
    {
        private string? _accessToken;
        private string? _refreshToken;
        private DateTime _expiresAt;

        /// <inheritdoc />
        public string? AccessToken => _accessToken;

        /// <inheritdoc />
        public string? RefreshToken => _refreshToken;

        /// <inheritdoc />
        public DateTime ExpiresAt => _expiresAt;

        /// <inheritdoc />
        public event Action? TokenChanged;

        /// <summary>
        /// Set access token only (backwards-compatible helper). Prefer SetTokens when refresh token is available.
        /// </summary>
        public void SetAccessToken(string token, DateTime expiresAt)
        {
            _accessToken = token;
            _expiresAt = expiresAt;
            TokenChanged?.Invoke();
        }

        /// <inheritdoc />
        public void SetTokens(string accessToken, string? refreshToken, DateTime expiresAt)
        {
            _accessToken = accessToken;
            _refreshToken = refreshToken;
            _expiresAt = expiresAt;
            TokenChanged?.Invoke();
        }

        /// <inheritdoc />
        public void Clear()
        {
            _accessToken = null;
            _refreshToken = null;
            _expiresAt = default;
            TokenChanged?.Invoke();
        }

        /// <inheritdoc />
        public bool IsExpired() => string.IsNullOrEmpty(_accessToken) || DateTime.UtcNow >= _expiresAt;

        /// <summary>
        /// Calls the API refresh endpoint to rotate the access/refresh tokens. This method expects the API
        /// to return an <see cref="APIResponseAuthentication"/> payload containing the new JWT and optional refresh token.
        /// </summary>
        public async Task<bool> TryRefreshAsync(IHttpClientFactory httpFactory, CancellationToken cancellationToken = default)
        {
            try
            {
                if (string.IsNullOrEmpty(_refreshToken)) return false;

                var client = httpFactory.CreateClient("ApiNoAuth");
                var resp = await client.PostAsJsonAsync("api/account/identity/refresh-token-native", new { refreshToken = _refreshToken }, cancellationToken);
                if (!resp.IsSuccessStatusCode) return false;

                var payload = await resp.Content.ReadFromJsonAsync<WT.Application.DTO.Response.APIResponseAuthentication>(cancellationToken: cancellationToken);
                if (payload == null || string.IsNullOrEmpty(payload.JwtToken)) return false;

                // Compute expiry from token or default to 30 minutes
                var newAccess = payload.JwtToken;
                var expires = GetExpiryFromJwt(newAccess) ?? DateTime.UtcNow.AddMinutes(30);

                SetTokens(newAccess, payload.RefreshToken, expires);
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Extracts the exp claim from a JWT payload and returns the UTC expiry time if present.
        /// </summary>
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
