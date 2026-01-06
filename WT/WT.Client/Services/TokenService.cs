using System;
using WT.Application.Services;

namespace WT.Client.Services
{
    /// <summary>
    /// Simple in-memory token storage used by the Blazor WebAssembly client.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The <see cref="TokenService"/> keeps the access token in memory only (not persisted to
    /// localStorage) and exposes a <see cref="TokenChanged"/> event so consumers can react when
    /// the token is set or cleared. This avoids persisting sensitive tokens to disk and
    /// supports the refresh-via-HttpOnly-cookie pattern used by the API.
    /// </para>
    /// </remarks>
    public class TokenService : ITokenService
    {
        private string? _accessToken;
        private DateTime _expiresAt;

        /// <summary>
        /// Gets the current in-memory access token or <c>null</c> if none is set.
        /// </summary>
        public string? AccessToken => _accessToken;

        /// <summary>
        /// Event raised when the access token changes (set or cleared).
        /// Subscribers should react by updating Authorization headers or triggering UI updates.
        /// </summary>
        public event Action? TokenChanged;

        /// <summary>
        /// Sets the current access token and its expiration time.
        /// </summary>
        /// <param name="token">The JWT access token string.</param>
        /// <param name="expiresAt">UTC date/time when the token expires.</param>
        public void SetAccessToken(string token, DateTime expiresAt)
        {
            _accessToken = token;
            _expiresAt = expiresAt;
            TokenChanged?.Invoke();
        }

        /// <summary>
        /// Clears the stored access token and notifies subscribers.
        /// </summary>
        public void Clear()
        {
            _accessToken = null;
            TokenChanged?.Invoke();
        }

        /// <summary>
        /// Returns <c>true</c> when there is no token or the stored token is expired.
        /// </summary>
        /// <returns><c>true</c> if token is missing or expired; otherwise <c>false</c>.</returns>
        public bool IsExpired() => _accessToken == null || DateTime.UtcNow >= _expiresAt;
    }
}
