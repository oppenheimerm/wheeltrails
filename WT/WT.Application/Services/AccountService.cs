using Blazored.LocalStorage;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using System.Net.Http.Json;
using System.Text.Json;
using WT.Application.APIServiceLogs;
using WT.Application.DTO.Request.Account;
using WT.Application.DTO.Response;
using WT.Application.Extensions;
using WT.Domain.Entity;

namespace WT.Application.Services
{
    /// <summary>
    /// HTTP client wrapper service for account management operations in Blazor client applications.
    /// This implementation makes HTTP calls to the API backend and is used by Blazor WebAssembly (WT.Client)
    /// and Blazor Server (WT.Admin) presentation layers.
    /// </summary>
    public class AccountService : BaseService, IAccountService
    {
        private readonly HttpClient _httpClient;
        private readonly IConfiguration _configuration;
        private readonly ILocalStorageService? _localStorageService;

        public AccountService(
            HttpClient httpClient, 
            IConfiguration configuration, 
            ILocalStorageService localStorageService)
            : base(httpClient, configuration, localStorageService)
        {
            _httpClient = httpClient;
            _configuration = configuration;
            _localStorageService = localStorageService;
        }

        public async Task<BaseAPIResponseDTO> RegisterAsync(RegisterDTO model)
        {
            // ✅ Use relative URL - HttpClient.BaseAddress already set
            var response = await _httpClient.PostAsJsonAsync("api/account/identity/create", model);
            return await response.Content.ReadFromJsonAsync<BaseAPIResponseDTO>() 
                   ?? new BaseAPIResponseDTO { Success = false, Message = "Failed to register" };
        }

        public async Task<APIResponseAuthentication> LoginAsync(LoginDTO model)
        {
            try
            {
                // ✅ Use relative URL - HttpClient.BaseAddress already set to https://localhost:5001
                var response = await _httpClient.PostAsJsonAsync("api/account/identity/login", model);
                
                // Check if the response was successful
                if (!response.IsSuccessStatusCode)
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    Console.WriteLine($"❌ Login failed. Status: {response.StatusCode}, Error: {errorContent}");
                    
                    return new APIResponseAuthentication 
                    { 
                        Success = false, 
                        Message = $"Login failed: {response.StatusCode}" 
                    };
                }
                
                var result = await response.Content.ReadFromJsonAsync<APIResponseAuthentication>();
                
                // Log success (but not sensitive data)
                if (result?.Success == true)
                {
                    Console.WriteLine($"✅ Login successful for user: {result.User?.Email}");
                }
                else
                {
                    Console.WriteLine($"❌ Login failed: {result?.Message}");
                }
                
                return result ?? new APIResponseAuthentication 
                { 
                    Success = false, 
                    Message = "Failed to parse login response" 
                };
            }
            catch (Exception ex)
            {
                Console.WriteLine($"🔥 Exception in LoginAsync: {ex.Message}");
                LogException.LogExceptions(ex);
                
                return new APIResponseAuthentication 
                { 
                    Success = false, 
                    Message = $"Login error: {ex.Message}" 
                };
            }
        }

        public async Task<APIResponseAuthentication> RefreshTokenAsync(string token)
        {
            var request = new { Token = token };
            var response = await _httpClient.PostAsJsonAsync("api/account/identity/refresh-token", request);
            return await response.Content.ReadFromJsonAsync<APIResponseAuthentication>() 
                   ?? new APIResponseAuthentication { Success = false, Message = "Token refresh failed" };
        }

        public async Task<BaseAPIResponseDTO> CreateRoleASync(CreateRoleDTO model)
        {
            var response = await _httpClient.PostAsJsonAsync("api/account/create-role", model);
            return await response.Content.ReadFromJsonAsync<BaseAPIResponseDTO>() 
                   ?? new BaseAPIResponseDTO { Success = false, Message = "Failed to create role" };
        }

        public async Task<IEnumerable<RoleDTO>> GetRolesAsync()
        {
            return await _httpClient.GetFromJsonAsync<IEnumerable<RoleDTO>>("api/account/roles") 
                   ?? Enumerable.Empty<RoleDTO>();
        }

        public async Task<BaseAPIResponseDTO> AddUserToRoleAsync(Guid userId, CreateRoleDTO model)
        {
            var response = await _httpClient.PostAsJsonAsync($"api/account/{userId}/add-role", model);
            return await response.Content.ReadFromJsonAsync<BaseAPIResponseDTO>() 
                   ?? new BaseAPIResponseDTO { Success = false, Message = "Failed to add user to role" };
        }

        public async Task<BaseAPIResponseDTO> CreateAdmin()
        {
            var response = await _httpClient.PostAsync("api/account/create-admin", null);
            return await response.Content.ReadFromJsonAsync<BaseAPIResponseDTO>() 
                   ?? new BaseAPIResponseDTO { Success = false, Message = "Failed to create admin" };
        }

        public async Task<BaseAPIResponseDTO> VerifyEmailAsync(string token)
        {
            var response = await _httpClient.GetAsync($"api/account/verify-email?token={token}");
            var result = await response.Content.ReadFromJsonAsync<BaseAPIResponseDTO>();
            return result ?? new BaseAPIResponseDTO { Success = false, Message = "Email verification failed" };
        }

        public async Task<BaseAPIResponseDTO> ForgotPasswordAsync(ForgotPasswordDTO model)
        {
            var response = await _httpClient.PostAsJsonAsync("api/account/forgot-password", model);
            return await response.Content.ReadFromJsonAsync<BaseAPIResponseDTO>() 
                   ?? new BaseAPIResponseDTO { Success = false, Message = "Failed to process password reset request" };
        }

        public async Task<BaseAPIResponseDTO> ResetPasswordAsync(ResetPasswordDTO model)
        {
            var response = await _httpClient.PostAsJsonAsync("api/account/reset-password", model);
            return await response.Content.ReadFromJsonAsync<BaseAPIResponseDTO>() 
                   ?? new BaseAPIResponseDTO { Success = false, Message = "Failed to reset password" };
        }
        // ✅ REMOVED: FindUserByIdAsync (not needed for HTTP client)
        // ✅ REMOVED: FindUserByUserName (not needed for HTTP client)
    }
}
