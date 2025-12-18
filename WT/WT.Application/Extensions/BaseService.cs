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

            // ✅ FIX 1: Clear any existing Authorization header before refreshing
            _httpClient.DefaultRequestHeaders.Authorization = null;

            // ✅ FIX 2: Use relative URL (HttpClient.BaseAddress already set)
            var response = await _httpClient.PostAsJsonAsync(
                "api/account/identity/refresh-token",  // ✅ Relative URL
                new RefreshTokenDTO() { Token = authLocalStorageDTO.RefreshToken });
            
            // ✅ FIX 3: Check if response was successful
            if (!response.IsSuccessStatusCode)
            {
                Console.WriteLine($"❌ Token refresh failed: {response.StatusCode}");
                var errorContent = await response.Content.ReadAsStringAsync();
                Console.WriteLine($"Error details: {errorContent}");
                return null;
            }

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
                    ProfileUsername = result.User.ProfileUsername,
                    Email = result.User.Email,
                    UserPhoto = result.User.ProfilePicture,
                    Bio = result.User.Bio
                };
                
                var jsonString = JsonSerializer.Serialize(authLocalStorage);
                await _localStorageService.SetItemAsStringAsync(LocalStorageKey!, jsonString);
                
                Console.WriteLine($"✅ Token refreshed successfully for user: {result.User.Email}");
                return authLocalStorage;
            }

            return null;
        }

        public static bool CheckIfUnauthorized(HttpResponseMessage httpResponseMessage)
        {
            return httpResponseMessage.StatusCode == System.Net.HttpStatusCode.Unauthorized;
        }
    }
}
