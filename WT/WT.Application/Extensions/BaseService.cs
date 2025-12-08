using Blazored.LocalStorage;
using Microsoft.Extensions.Configuration;
using System.Net.Http.Json;
using System.Text.Json;
using WT.Application.DTO.Request.Account;
using WT.Application.DTO.Response;

namespace WT.Application.Extensions
{
    public class BaseService
    {
        readonly HttpClient _httpClient;
        readonly IConfiguration _configuration;
        readonly ILocalStorageService _localStorageService;
        readonly string? LocalStorageKey;
        
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
        /// Method to get and refresh the JWT token using the refresh token stored in local storage.
        /// </summary>
        public async Task<AuthenticatedLocalStorageDTO?> GetRefreshTokenAsync()
        {
            var authData = await _localStorageService.GetItemAsStringAsync(LocalStorageKey!);
            if (string.IsNullOrEmpty(authData))
            {
                return null;
            }

            var authLocalStorageDTO = JsonSerializer.Deserialize<AuthenticatedLocalStorageDTO>(authData);
            if (authLocalStorageDTO is null || string.IsNullOrEmpty(authLocalStorageDTO.RefreshToken))
            {
                return null;
            }

            var baseUrl = _configuration["ConnectionStrings:BaseApiUrl"];
            
            // ✅ FIX: Correct endpoint path
            var response = await _httpClient.PostAsJsonAsync(
                $"{baseUrl}/api/account/identity/refresh-token", 
                new RefreshTokenDTO() { Token = authLocalStorageDTO.RefreshToken });
            
            var result = await response.Content.ReadFromJsonAsync<APIResponseAuthentication>();
            
            if (result is not null && result.Success == true)
            {
                var authLocalStorage = new AuthenticatedLocalStorageDTO()
                {
                    JWtToken = result.JwtToken,
                    RefreshToken = result.RefreshToken,
                    TimeStamp = DateTime.UtcNow,
                    Id = result.User!.Id,
                    FirstName = result.User.FirstName,
                    Email = result.User.Email,
                    UserPhoto = result.User.ProfilePicture,
                    Bio = result.User.Bio // ✅ Added missing Bio property
                };
                
                var jsonString = JsonSerializer.Serialize(authLocalStorage);
                await _localStorageService.SetItemAsStringAsync(LocalStorageKey!, jsonString);
                
                return authLocalStorage; // ✅ Return the NEW token data, not old
            }

            return null;
        }

        public static bool CheckIfUnauthorized(HttpResponseMessage httpResponseMessage)
        {
            return httpResponseMessage.StatusCode == System.Net.HttpStatusCode.Unauthorized;
        }
    }
}
