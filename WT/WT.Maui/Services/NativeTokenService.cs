using System;
using System.Threading.Tasks;
using Microsoft.Maui.Storage;

namespace WT.Maui.Services
{
    /// <summary>
    /// Simple token manager for native clients.
    /// - Keeps the access token in memory (transient) and tracks its expiry.
    /// - Persists the refresh token securely using <see cref="SecureStorage"/>.
    /// </summary>
    public class NativeTokenService
    {
        private string? _accessToken;
        private DateTime _expiresAt;
        private const string RefreshKey = "wt_refresh_token";

        /// <summary>
        /// Gets the current in-memory access token, or null if none is set.
        /// </summary>
        public string? AccessToken => _accessToken;

        /// <summary>
        /// Sets the current access token and its UTC expiry time.
        /// The token is kept only in memory to reduce risk of long-term exposure.
        /// </summary>
        /// <param name="token">JWT access token string.</param>
        /// <param name="expiresAt">UTC expiry time for the token.</param>
        public void SetAccessToken(string token, DateTime expiresAt)
        {
            _accessToken = token;
            _expiresAt = expiresAt;
        }

        /// <summary>
        /// Clears the in-memory access token immediately.
        /// </summary>
        public void ClearAccessToken()
        {
            _accessToken = null;
            _expiresAt = default;
        }

        /// <summary>
        /// Returns true when there is no access token or the stored token is expired.
        /// </summary>
        public bool IsAccessTokenExpired() => string.IsNullOrEmpty(_accessToken) || DateTime.UtcNow >= _expiresAt;

        /// <summary>
        /// Persist the refresh token securely. Writing an empty or null value clears it.
        /// </summary>
        /// <param name="refreshToken">Refresh token value to store.</param>
        public async Task SetRefreshTokenAsync(string refreshToken)
        {
            if (string.IsNullOrEmpty(refreshToken))
            {
                await SecureStorage.Default.SetAsync(RefreshKey, string.Empty).ConfigureAwait(false);
            }
            else
            {
                await SecureStorage.Default.SetAsync(RefreshKey, refreshToken).ConfigureAwait(false);
            }
        }

        /// <summary>
        /// Retrieves the stored refresh token or null if none exists or an error occurs.
        /// </summary>
        /// <returns>Refresh token string or null.</returns>
        public async Task<string?> GetRefreshTokenAsync()
        {
            try
            {
                var r = await SecureStorage.Default.GetAsync(RefreshKey).ConfigureAwait(false);
                return string.IsNullOrWhiteSpace(r) ? null : r;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Clears the refresh token from secure storage.
        /// </summary>
        public async Task ClearRefreshTokenAsync()
        {
            try
            {
                SecureStorage.Default.Remove(RefreshKey);
            }
            catch { }
            await Task.CompletedTask;
        }
    }
}
