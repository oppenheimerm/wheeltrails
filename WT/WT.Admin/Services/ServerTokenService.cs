using System;

namespace WT.Admin.Services
{
    /// <summary>
    /// Server-scoped token service interface.
    /// Represents a per-circuit, in-memory access token store used by Blazor Server.
    /// </summary>
    public interface IServerTokenService
    {
        /// <summary>
        /// Gets the current access token or <c>null</c> when none is set.
        /// </summary>
        string? AccessToken { get; }

        /// <summary>
        /// Gets the UTC expiration time for the current token.
        /// </summary>
        DateTime ExpiresAt { get; }

        /// <summary>
        /// Sets the current access token and its expiration time.
        /// Implementations should raise <see cref="TokenChanged"/> after storing the token.
        /// </summary>
        /// <param name="token">JWT access token string.</param>
        /// <param name="expiresAt">UTC expiration time of the token.</param>
        void SetAccessToken(string token, DateTime expiresAt);

        /// <summary>
        /// Clears any stored access token and notifies subscribers.
        /// </summary>
        void Clear();

        /// <summary>
        /// Returns <c>true</c> when there is no token or the stored token is expired.
        /// </summary>
        /// <returns><c>true</c> if token is missing or expired; otherwise <c>false</c>.</returns>
        bool IsExpired();

        /// <summary>
        /// Event raised when the access token changes (set or cleared).
        /// Subscribers should react by updating Authorization headers or triggering UI updates.
        /// </summary>
        event Action? TokenChanged;
    }

    /// <summary>
    /// Default server-scoped implementation of <see cref="IServerTokenService"/>.
    /// Intended to be registered as scoped (per Blazor circuit) and kept in-memory only.
    /// </summary>
    public class ServerTokenService : IServerTokenService
    {
        private string? _accessToken;
        private DateTime _expiresAt;

        /// <inheritdoc />
        public string? AccessToken => _accessToken;

        /// <inheritdoc />
        public DateTime ExpiresAt => _expiresAt;

        /// <inheritdoc />
        public event Action? TokenChanged;

        /// <inheritdoc />
        public void SetAccessToken(string token, DateTime expiresAt)
        {
            _accessToken = token;
            _expiresAt = expiresAt;
            TokenChanged?.Invoke();
        }

        /// <inheritdoc />
        public void Clear()
        {
            _accessToken = null;
            _expiresAt = default;
            TokenChanged?.Invoke();
        }

        /// <inheritdoc />
        public bool IsExpired() => _accessToken == null || DateTime.UtcNow >= _expiresAt;
    }
}
