using System;
using System.Net.Http;
using System.Net.Http.Json;
using System.Threading.Tasks;
using WT.Application.DTO.Request.Account;
using WT.Application.DTO.Response;

namespace WT.Admin.Services
{
    public class AuthService
    {
        private readonly IHttpClientFactory _httpFactory;
        private readonly IServerTokenService _tokenService;
        private readonly AdminAuthenticationStateProvider _authStateProvider;

        public AuthService(IHttpClientFactory httpFactory, IServerTokenService tokenService, AdminAuthenticationStateProvider authStateProvider)
        {
            _httpFactory = httpFactory;
            _tokenService = tokenService;
            _authStateProvider = authStateProvider;
        }

        public async Task<APIResponseAuthentication> LoginAsync(LoginDTO model)
        {
            var client = _httpFactory.CreateClient("ApiNoAuth"); // no bearer handler here
            var resp = await client.PostAsJsonAsync("api/account/identity/login", model);
            if (!resp.IsSuccessStatusCode)
            {
                return new APIResponseAuthentication { Success = false, Message = "Login failed" };
            }

            var result = await resp.Content.ReadFromJsonAsync<APIResponseAuthentication>();
            if (result?.Success == true && !string.IsNullOrEmpty(result.JwtToken))
            {
                // parse expiry from token or use returned expiry if included (example uses 30min)
                var expiresAt = DateTime.UtcNow.AddMinutes(30);
                _tokenService.SetAccessToken(result.JwtToken!, expiresAt);
                _authStateProvider.NotifyAuthenticationStateChanged();
            }

            return result!;
        }

        public Task LogoutAsync()
        {
            _tokenService.Clear();
            _authStateProvider.NotifyAuthenticationStateChanged();
            return Task.CompletedTask;
        }
    }
}
