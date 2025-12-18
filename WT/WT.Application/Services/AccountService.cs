using Blazored.LocalStorage;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using WT.Application.APIServiceLogs;
using WT.Application.DTO.Request.Account;
using WT.Application.DTO.Response;
using WT.Application.DTO.Response.Account;
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
        private readonly ILocalStorageService _localStorage;
        private readonly IConfiguration _configuration;

        public AccountService(HttpClient httpClient, IConfiguration config, ILocalStorageService localStorage) : base(httpClient, config,localStorage)
        {
            _httpClient = httpClient;
            _localStorage = localStorage;
            _configuration = config;
        }
        
        /// <summary>
        /// Gets account settings for the currently authenticated user.
        /// Implements retry logic for transient errors and token refresh for auth failures.
        /// </summary>
        public async Task<APIResponseViewAccountSettings> GetAccountSettingsAsync()
        {
            const int maxRetries = 3; // For transient errors only
            int currentAttempt = 0;
            
            try
            {
                // Get JWT token from local storage
                var authData = await _localStorage.GetItemAsStringAsync(_configuration["ApplicationSettings:LocalStorageKey"]!);

                if (string.IsNullOrEmpty(authData))
                {
                    Console.WriteLine("❌ No authentication data in local storage");
                    return new APIResponseViewAccountSettings
                    {
                        Success = false,
                        Message = "User is not authenticated"
                    };
                }

                var authLocalStorageDTO = JsonSerializer.Deserialize<AuthenticatedLocalStorageDTO>(authData);
                
                if (authLocalStorageDTO == null || string.IsNullOrEmpty(authLocalStorageDTO.JWtToken))
                {
                    Console.WriteLine("❌ Invalid authentication data or missing JWT token");
                    return new APIResponseViewAccountSettings
                    {
                        Success = false,
                        Message = "User is not authenticated"
                    };
                }

                // Set the JWT token in the Authorization header
                _httpClient.DefaultRequestHeaders.Authorization = 
                    new AuthenticationHeaderValue("Bearer", authLocalStorageDTO.JWtToken);

                Console.WriteLine($"🔑 Fetching account settings (Attempt 1/{maxRetries})");

                HttpResponseMessage? response = null;
                bool tokenWasRefreshed = false;

                // Retry loop for transient errors
                while (currentAttempt < maxRetries)
                {
                    currentAttempt++;
                    
                    try
                    {
                        response = await _httpClient.GetAsync("api/account/identity/settings");
                        Console.WriteLine($"📡 Response status (Attempt {currentAttempt}/{maxRetries}): {response.StatusCode}");

                        // ✅ SUCCESS - return immediately
                        if (response.IsSuccessStatusCode)
                        {
                            break;
                        }

                        // ❌ UNAUTHORIZED - Try token refresh (only once)
                        if (CheckIfUnauthorized(response) && !tokenWasRefreshed)
                        {
                            Console.WriteLine("⚠️ Token expired, attempting refresh...");
                            
                            var refreshedToken = await GetRefreshTokenAsync();
                            
                            if (refreshedToken is not null && !string.IsNullOrEmpty(refreshedToken.JWtToken))
                            {
                                Console.WriteLine("✅ Token refreshed, retrying request...");
                                tokenWasRefreshed = true;
                                
                                // Update Authorization header with new token
                                _httpClient.DefaultRequestHeaders.Authorization = 
                                    new AuthenticationHeaderValue("Bearer", refreshedToken.JWtToken);
                                
                                // Don't increment attempt counter for auth retry
                                currentAttempt--;
                                continue; // Retry immediately
                            }
                            else
                            {
                                Console.WriteLine("❌ Token refresh failed - user needs to re-login");
                                return new APIResponseViewAccountSettings
                                {
                                    Success = false,
                                    Message = "Session expired. Please log in again."
                                };
                            }
                        }
                        // ❌ UNAUTHORIZED after token refresh - authentication problem, stop retrying
                        else if (CheckIfUnauthorized(response) && tokenWasRefreshed)
                        {
                            Console.WriteLine("❌ Still unauthorized after token refresh - stopping retries");
                            return new APIResponseViewAccountSettings
                            {
                                Success = false,
                                Message = "Authentication failed. Please log in again."
                            };
                        }
                        // ⚠️ SERVER ERROR (5xx) or other transient error - retry with backoff
                        else if ((int)response.StatusCode >= 500 || response.StatusCode == System.Net.HttpStatusCode.RequestTimeout)
                        {
                            if (currentAttempt < maxRetries)
                            {
                                var delayMs = currentAttempt * 1000; // Progressive backoff: 1s, 2s, 3s
                                Console.WriteLine($"⚠️ Server error {response.StatusCode}, retrying in {delayMs}ms...");
                                await Task.Delay(delayMs);
                                continue; // Retry
                            }
                            else
                            {
                                Console.WriteLine($"❌ Max retries ({maxRetries}) reached for server error");
                                break; // Exit retry loop
                            }
                        }
                        // ❌ CLIENT ERROR (4xx other than 401) - don't retry
                        else
                        {
                            Console.WriteLine($"❌ Client error {response.StatusCode} - not retrying");
                            break; // Exit retry loop
                        }
                    }
                    catch (HttpRequestException ex)
                    {
                        Console.WriteLine($"⚠️ Network error on attempt {currentAttempt}/{maxRetries}: {ex.Message}");
                        
                        if (currentAttempt < maxRetries)
                        {
                            var delayMs = currentAttempt * 1000;
                            Console.WriteLine($"Retrying in {delayMs}ms...");
                            await Task.Delay(delayMs);
                            continue; // Retry
                        }
                        else
                        {
                            Console.WriteLine($"❌ Max retries ({maxRetries}) reached for network error");
                            return new APIResponseViewAccountSettings
                            {
                                Success = false,
                                Message = "Network error. Please check your connection and try again."
                            };
                        }
                    }
                }

                // Check final response status
                if (response == null || !response.IsSuccessStatusCode)
                {
                    var errorContent = response != null 
                        ? await response.Content.ReadAsStringAsync() 
                        : "No response received";
                    
                    Console.WriteLine($"❌ Final response failed: {response?.StatusCode}");
                    Console.WriteLine($"Error details: {errorContent}");
                    
                    return new APIResponseViewAccountSettings
                    {
                        Success = false,
                        Message = $"Unable to retrieve account settings. Status: {response?.StatusCode}"
                    };
                }

                // Deserialize successful response
                var result = await response.Content.ReadFromJsonAsync<APIResponseViewAccountSettings>();
                
                if (result == null)
                {
                    Console.WriteLine("❌ Failed to deserialize response");
                    return new APIResponseViewAccountSettings
                    {
                        Success = false,
                        Message = "Failed to process server response"
                    };
                }

                Console.WriteLine($"✅ Account settings retrieved successfully (took {currentAttempt} attempt(s))");
                return result;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"🔥 Unexpected exception in GetAccountSettingsAsync: {ex.Message}");
                Console.WriteLine($"Stack trace: {ex.StackTrace}");
                
                return new APIResponseViewAccountSettings
                {
                    Success = false,
                    Message = "An unexpected error occurred. Please try again later."
                };
            }
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

        // ✅ IAccountService implementation (client-side, calls API and returns DTO)
        public async Task<ApplicationUserDTO?> FindUserByProfileUsernameAsync(string profileUsername)
        {
            try
            {
                var response = await _httpClient.GetAsync($"/api/account/user/{Uri.EscapeDataString(profileUsername)}");
                
                if (response.IsSuccessStatusCode)
                {
                    var result = await response.Content.ReadFromJsonAsync<UserProfileResponse>();
                    return result?.User;
                }
                
                return null;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error fetching user profile: {ex.Message}");
                return null;
            }
        }

        public async Task<bool> IsProfileUsernameAvailableAsync(string profileUsername)
        {
            try
            {
                var response = await _httpClient.GetAsync($"/api/account/profile-username/check/{Uri.EscapeDataString(profileUsername)}");
                
                if (response.IsSuccessStatusCode)
                {
                    var result = await response.Content.ReadFromJsonAsync<ProfileUsernameCheckResponse>();
                    return result?.IsAvailable ?? false;
                }
                
                return false;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error checking profile username availability: {ex.Message}");
                return false;
            }
        }

        public async Task<UsernameValidationResultDTO> ValidateProfileUsernameAsync(string profileUsername)
        {
            try
            {
                var response = await _httpClient.GetAsync($"/api/account/profile-username/validate/{Uri.EscapeDataString(profileUsername)}");
                
                if (response.IsSuccessStatusCode)
                {
                    return await response.Content.ReadFromJsonAsync<UsernameValidationResultDTO>() 
                        ?? new UsernameValidationResultDTO { IsValid = false, Message = "Validation failed" };
                }
                
                return new UsernameValidationResultDTO { IsValid = false, Message = "Unable to validate username" };
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error validating username: {ex.Message}");
                return new UsernameValidationResultDTO { IsValid = false, Message = "Unable to validate username" };
            }
        }


        // Helper classes for deserialization
        private class ProfileUsernameCheckResponse
        {
            public bool IsAvailable { get; set; }
        }

        private class UserProfileResponse
        {
            public bool Success { get; set; }
            public ApplicationUserDTO? User { get; set; }
        }
    }
}
