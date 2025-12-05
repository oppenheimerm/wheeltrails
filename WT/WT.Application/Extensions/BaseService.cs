
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
        
        public BaseService(HttpClient httpClient, IConfiguration configuration, ILocalStorageService localStorageService)
        {
            _httpClient = httpClient;
            _configuration = configuration;
            _localStorageService = localStorageService;
            LocalStorageKey = configuration["ApplicationSettings:LocalStorageKey"]!;
        }

        public async Task<AuthenticatedLocalStorageDTO?> GetRefreshTokenAsync()
        {
            var authData = await _localStorageService.GetItemAsStringAsync(LocalStorageKey!);
            if (string.IsNullOrEmpty(authData))
            {
                return null!;
            }
            else
            {
                var authLocalStorageDTO = JsonSerializer.Deserialize<AuthenticatedLocalStorageDTO>(authData);
                if (authLocalStorageDTO is not null && !string.IsNullOrEmpty(authLocalStorageDTO.RefreshToken))
                {

                    var baseUrl = _configuration["ConnectionStrings:BaseApiUrl"];
                    //  APIResponseAuthentication
                    var response = await _httpClient.PostAsJsonAsync($"{baseUrl}/refresh-token", new RefreshTokenDTO() { Token = authLocalStorageDTO.RefreshToken });
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
                        };
                        var jsonString = JsonSerializer.Serialize(authLocalStorage);
                        await _localStorageService.SetItemAsStringAsync(LocalStorageKey!, jsonString);
                        return authLocalStorageDTO;
                    }
                    else
                    {
                        //navigationManager.NavigateTo("/Account/Login", true);
                        return null!;
                    }
                }
                else
                {
                    //navigationManager.NavigateTo("/Account/Login", true);
                    return null!;
                }

            }


        }
    }
}
