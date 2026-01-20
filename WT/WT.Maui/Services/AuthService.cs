using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading.Tasks;
using WT.Application.DTO.Request.Account;
using WT.Application.DTO.Response;

namespace WT.Maui.Services
{
    /// <summary>
    /// Authentication helper used by the native MAUI client.
    /// - Performs login and refresh calls against the API.
    /// - Stores access token in <see cref="NativeTokenService"/> memory and persists refresh token securely.
    /// - Exposes quick synchronous <see cref="IsLoggedIn"/> check and asynchronous <see cref="RestoreSessionAsync"/> method.
    /// </summary>
    public class AuthService : IAuthService
    {
        private readonly HttpClient _http;
        private readonly NativeTokenService _tokens;

        /// <summary>
        /// Creates a new instance of the <see cref="AuthService"/>.
        /// </summary>
        /// <param name="http">Configured HttpClient targeting the API.</param>
        /// <param name="tokens">Token service for access/refresh token storage.</param>
        public AuthService(HttpClient http, NativeTokenService tokens)
        {
            _http = http;
            _tokens = tokens;
        }

        /// <summary>
        /// Fast synchronous check indicating whether an access token is currently available and not expired.
        /// Does not attempt to refresh the token.
        /// </summary>
        public bool IsLoggedIn => !string.IsNullOrEmpty(_tokens.AccessToken) && !_tokens.IsAccessTokenExpired();

        /// <summary>
        /// Attempts to restore a user session by using a stored refresh token to obtain a new access token.
        /// Returns true when an access token is available after the call.
        /// </summary>
        /// <returns>True if session restored (access token present); otherwise false.</returns>
        public async Task<bool> RestoreSessionAsync()
        {
            if (IsLoggedIn) return true;

            // Try refresh flow if we have a refresh token
            var refresh = await _tokens.GetRefreshTokenAsync().ConfigureAwait(false);
            if (string.IsNullOrEmpty(refresh)) return false;

            return await TryRefreshAsync().ConfigureAwait(false);
        }

        /// <summary>
        /// Performs login against the API and, on success, stores the access token in memory
        /// and the refresh token in secure storage.
        /// Expects the API to return <see cref="APIResponseAuthentication"/> with <see cref="APIResponseAuthentication.JwtToken"/>
        /// and optionally <see cref="APIResponseAuthentication.RefreshToken"/>.
        /// </summary>
        /// <param name="model">Login DTO containing credentials.</param>
        /// <returns>True when login succeeded and tokens were stored; otherwise false.</returns>
        public async Task<bool> LoginAsync(LoginDTO model)
        {
            var resp = await _http.PostAsJsonAsync("api/account/identity/login", model);
            if (!resp.IsSuccessStatusCode) return false;

            var payload = await resp.Content.ReadFromJsonAsync<APIResponseAuthentication?>();
            if (payload == null || string.IsNullOrEmpty(payload.JwtToken)) return false;

            var accessToken = payload.JwtToken!;
            var expiresAt = GetExpiryFromJwt(accessToken) ?? DateTime.UtcNow.AddMinutes(30);

            _tokens.SetAccessToken(accessToken, expiresAt);

            if (!string.IsNullOrEmpty(payload.RefreshToken))
            {
                await _tokens.SetRefreshTokenAsync(payload.RefreshToken).ConfigureAwait(false);
            }

            return true;
        }

        /// <summary>
        /// Attempts to refresh the access token using the stored refresh token.
        /// Expects the API to return an <see cref="APIResponseAuthentication"/> with a new JWT and optionally a rotated refresh token.
        /// </summary>
        /// <returns>True when refresh succeeded and tokens were updated; otherwise false.</returns>
        public async Task<bool> TryRefreshAsync()
        {
            var refresh = await _tokens.GetRefreshTokenAsync().ConfigureAwait(false);
            if (string.IsNullOrEmpty(refresh)) return false;

            try
            {
                var resp = await _http.PostAsJsonAsync("api/account/identity/refresh-token-native", new { refreshToken = refresh });
                if (!resp.IsSuccessStatusCode) return false;

                var payload = await resp.Content.ReadFromJsonAsync<APIResponseAuthentication?>();
                if (payload == null || string.IsNullOrEmpty(payload.JwtToken)) return false;

                var accessToken = payload.JwtToken!;
                var expiresAt = GetExpiryFromJwt(accessToken) ?? DateTime.UtcNow.AddMinutes(30);

                _tokens.SetAccessToken(accessToken, expiresAt);
                if (!string.IsNullOrEmpty(payload.RefreshToken))
                {
                    await _tokens.SetRefreshTokenAsync(payload.RefreshToken).ConfigureAwait(false);
                }

                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Ensures the supplied HttpClient has an Authorization header with a valid access token.
        /// Uses in-memory token when available; otherwise attempts a refresh via TryRefreshAsync().
        /// Returns true when Authorization header was set.
        /// </summary>
        public async Task<bool> EnsureAuthorizationHeaderAsync(HttpClient client)
        {
            if (client == null) throw new ArgumentNullException(nameof(client));

            try
            {
                // If token present and not expired, set header
                if (!string.IsNullOrEmpty(_tokens.AccessToken) && !_tokens.IsAccessTokenExpired())
                {
                    client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _tokens.AccessToken);
                    return true;
                }

                // Try refreshing using stored refresh token
                var refresh = await _tokens.GetRefreshTokenAsync().ConfigureAwait(false);
                if (string.IsNullOrEmpty(refresh)) return false;

                var refreshed = await TryRefreshAsync().ConfigureAwait(false);
                if (!refreshed) return false;

                if (!string.IsNullOrEmpty(_tokens.AccessToken))
                {
                    client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _tokens.AccessToken);
                    return true;
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Performs logout: calls API logout endpoint (best-effort) and clears stored tokens.
        /// </summary>
        public async Task LogoutAsync()
        {
            try { await _http.PostAsync("api/account/identity/logout", null); } catch { }
            _tokens.ClearAccessToken();
            await _tokens.ClearRefreshTokenAsync().ConfigureAwait(false);
        }

        /// <summary>
        /// Attempts to parse the JWT payload and return the 'exp' (expiry) claim as a UTC DateTime.
        /// Returns null when parsing fails or the claim is missing.
        /// </summary>
        /// <param name="jwt">The JWT token string.</param>
        /// <returns>Expiry as UTC DateTime or null.</returns>
        private static DateTime? GetExpiryFromJwt(string jwt)
        {
            try
            {
                var parts = jwt.Split('.');
                if (parts.Length < 2) return null;

                string payload = parts[1];
                // Pad base64 if necessary
                int pad = 4 - (payload.Length % 4);
                if (pad < 4) payload += new string('=', pad);

                var bytes = Convert.FromBase64String(payload);
                using var doc = JsonDocument.Parse(bytes);
                if (doc.RootElement.TryGetProperty("exp", out var expEl) && expEl.TryGetInt64(out var exp))
                {
                    // exp is seconds since epoch
                    return DateTimeOffset.FromUnixTimeSeconds(exp).UtcDateTime;
                }
            }
            catch
            {
                // ignore parsing errors and fall back
            }

            return null;
        }
    }
}
