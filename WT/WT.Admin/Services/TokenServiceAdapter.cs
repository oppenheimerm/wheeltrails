using System;
using WT.Application.Services;

namespace WT.Admin.Services
{
    /// <summary>
    /// Adapter that exposes the server-scoped IServerTokenService as the application ITokenService.
    /// This allows server-side DI to satisfy components that expect ITokenService (WASM-style provider).
    /// </summary>
    public class TokenServiceAdapter : ITokenService
    {
        private readonly IServerTokenService _inner;

        public TokenServiceAdapter(IServerTokenService inner)
        {
            _inner = inner;
        }

        public string? AccessToken => _inner.AccessToken;

        public event Action? TokenChanged
        {
            add
            {
                if (value != null) _inner.TokenChanged += value;
            }
            remove
            {
                if (value != null) _inner.TokenChanged -= value;
            }
        }

        public void Clear() => _inner.Clear();

        public void SetAccessToken(string token, DateTime expiresAt) => _inner.SetAccessToken(token, expiresAt);

        public bool IsExpired() => _inner.IsExpired();
    }
}
