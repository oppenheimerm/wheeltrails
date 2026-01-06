using System;

namespace WT.Application.Services
{
    public interface ITokenService
    {
        string? AccessToken { get; }
        void SetAccessToken(string token, DateTime expiresAt);
        void Clear();
        event Action? TokenChanged;
    }
}
