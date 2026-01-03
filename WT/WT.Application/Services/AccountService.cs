using Blazored.LocalStorage;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Mime;
using System.Text;
using System.Text.Json;
using WT.Application.APIServiceLogs;
using WT.Application.DTO.Request.Account;
using WT.Application.DTO.Request.Trail;
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
                LogException.LogExceptions(ex);

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
                    // respone is a type of APIResponseAuthentication retured by the API
                    // I want to retun this friendly error message to the caller, not bad request 400 etc.
                    // So we need to convert the response content to a APIResponseAuthentication object
                    var friendlyError = await response.Content.ReadFromJsonAsync<APIResponseAuthentication>();
                    Console.WriteLine($"❌ Login failed. Status: {response.StatusCode}");

                    // check if friendlyError is not null and has a message
                    if (friendlyError != null && !string.IsNullOrEmpty(friendlyError.Message))
                    {
                        return new APIResponseAuthentication 
                        { 
                            Success = false, 
                            Message = friendlyError.Message 
                        };
                    }
                    else { 
                        return new APIResponseAuthentication 
                        { 
                            Success = false, 
                            Message = $"Login failed: {response.StatusCode}" 
                        };
                    }

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
                    Message = "Login failed. Please try again." 
                };
            }
            catch (Exception ex)
            {
                Console.WriteLine($"🔥 Exception in LoginAsync: {ex.Message}");
                LogException.LogExceptions(ex);
                
                return new APIResponseAuthentication 
                { 
                    Success = false,
                    // Never return sensitive exception details to the caller, just a generic message
                    Message = "Login error. Please try again." 
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

        /// <summary>
        /// Method to reset password for an authenticated user. Frontend service implementation. On success
        /// user must login again with the new password.
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        public async Task<BaseAPIResponseDTO> AuthenticatedResetPasswordAsync(AuthenticatedResetPasswordDTO model)
        {
            const int maxRetries = 3; // For transient errors only
            int currentAttempt = 0;

            try {
                // Get JWT token from local storage
                var authData = await _localStorage.GetItemAsStringAsync(_configuration["ApplicationSettings:LocalStorageKey"]!);

                if (string.IsNullOrEmpty(authData))
                {
                    Console.WriteLine("❌ No authentication data in local storage");
                    return new BaseAPIResponseDTO
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

                Console.WriteLine($"🔑 Atempting to reset password for user: (Attempt 1/{maxRetries})");
                LogException.LogToConsole($"🔑 Attempting to reset password in AuthenticatedResetPasswordAsync (Attempt 1/{maxRetries})");

                HttpResponseMessage? response = null;
                bool tokenWasRefreshed = false;

                // Retry loop for transient errors
                while (currentAttempt < maxRetries)
                {
                    currentAttempt++;

                    try
                    {
                        response = await _httpClient.PostAsJsonAsync("api/account/identity/reset-password-authenticated", model);
                        Console.WriteLine($"📡 Response status (Attempt {currentAttempt}/{maxRetries}): {response.StatusCode}");
                        LogException.LogToConsole($"📡 Response status in AuthenticatedResetPasswordAsync (Attempt {currentAttempt}/{maxRetries}): {response.StatusCode}");

                        // ✅ SUCCESS - return immediately
                        if (response.IsSuccessStatusCode)
                        {
                            break;
                        }

                        // ❌ UNAUTHORIZED - Try token refresh (only once)
                        if (CheckIfUnauthorized(response) && !tokenWasRefreshed)
                        {
                            Console.WriteLine("⚠️ Token expired, attempting refresh...");
                            LogException.LogToConsole("⚠️ Token expired in AuthenticatedResetPasswordAsync, attempting refresh...");

                            var refreshedToken = await GetRefreshTokenAsync();

                            if (refreshedToken is not null && !string.IsNullOrEmpty(refreshedToken.JWtToken))
                            {
                                Console.WriteLine("✅ Token refreshed, retrying request...");
                                LogException.LogToConsole("✅ Token refreshed in AuthenticatedResetPasswordAsync, retrying request.");
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
                                LogException.LogToConsole("❌ Token refresh failed in AuthenticatedResetPasswordAsync - user needs to re-login.");
                                return new BaseAPIResponseDTO
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
                            LogException.LogToConsole("❌ Still unauthorized after token refresh in AuthenticatedResetPasswordAsync - stopping retries.");
                            return new BaseAPIResponseDTO
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
                                LogException.LogToConsole($"⚠️ Server error {response.StatusCode} in AuthenticatedResetPasswordAsync, retrying in {delayMs}ms...");
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
                            LogException.LogToConsole($"❌ Client error {response.StatusCode} in AuthenticatedResetPasswordAsync - not retrying.");
                            break; // Exit retry loop
                        }
                    }
                    catch (HttpRequestException ex)
                    {
                        Console.WriteLine($"⚠️ Network error on attempt {currentAttempt}/{maxRetries}: {ex.Message}");
                        LogException.LogToConsole($"⚠️ Network error on attempt {currentAttempt}/{maxRetries} in AuthenticatedResetPasswordAsync: {ex.Message}");

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
                            LogException.LogToConsole($"❌ Max retries ({maxRetries}) reached for network error in AuthenticatedResetPasswordAsync.");
                            return new BaseAPIResponseDTO
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
                    LogException.LogToConsole($"❌ Final response failed: {response?.StatusCode}");
                    Console.WriteLine($"Error details: {errorContent}");
                    LogException.LogToConsole($"Error details: {errorContent}");

                    return new BaseAPIResponseDTO
                    {
                        Success = false,
                        Message = $"Unable to reset passwrod at this time. Status: {response?.StatusCode}"
                    };
                }


                // Deserialize successful response
                var result = await response.Content.ReadFromJsonAsync<BaseAPIResponseDTO>();

                if (result == null)
                {
                    Console.WriteLine("❌ Failed to deserialize response");
                    LogException.LogToConsole("❌ Failed to deserialize response in AuthenticatedResetPasswordAsync.");
                    return new BaseAPIResponseDTO
                    {
                        Success = false,
                        Message = "Failed to process server response"
                    };
                }

                Console.WriteLine($"✅ Password reset successfully, (took {currentAttempt} attempt(s))");
                LogException.LogToConsole("✅ Password reset successfully.");
                return result;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"🔥 Unexpected exception in AuthenticatedResetPasswordAsync: {ex.Message}");
                Console.WriteLine($"Stack trace: {ex.StackTrace}");
                LogException.LogExceptions(ex);
                return new BaseAPIResponseDTO
                {
                    Success = false,
                    Message = "An unexpected error occurred. Please try again later."
                };
            }
        }

        /// <summary>
        /// Method to get navbar authentication data for the currently authenticated user.
        /// </summary>
        /// <returns></returns>
        public async Task SetNavBarAuthDataAsync()
        {
            const int maxRetries = 3; // For transient errors only
            int currentAttempt = 0;
            NavBarSettingsDTO? navBarSettingsDTO;
            Console.WriteLine("✅ AccountService:SetNavBarAuthDataAsync CALLED!");

            try {
                var authData = await _localStorage.GetItemAsStringAsync(_configuration["ApplicationSettings:LocalStorageKey"]!);

                if (string.IsNullOrEmpty(authData))
                {
                    Console.WriteLine("❌ No authentication data in local storage");
                }

                var authLocalStorageDTO = JsonSerializer.Deserialize<AuthenticatedLocalStorageDTO>(authData);

                if (authLocalStorageDTO == null || string.IsNullOrEmpty(authLocalStorageDTO.JWtToken))
                {
                    Console.WriteLine("❌ Invalid authentication data or missing JWT token");
                }

                // Set the JWT token in the Authorization header
                _httpClient.DefaultRequestHeaders.Authorization =
                    new AuthenticationHeaderValue("Bearer", authLocalStorageDTO.JWtToken);

                Console.WriteLine($"🔑 Fetching navbar settings (Attempt 1/{maxRetries})");

                HttpResponseMessage? response = null;
                bool tokenWasRefreshed = false;

                // Retry loop for transient errors
                while (currentAttempt < maxRetries)
                {
                    currentAttempt++;

                    try
                    {
                        response = await _httpClient.GetAsync("api/account/identity/navbar-info");
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
                            }
                        }
                        // ❌ UNAUTHORIZED after token refresh - authentication problem, stop retrying
                        else if (CheckIfUnauthorized(response) && tokenWasRefreshed)
                        {
                            Console.WriteLine("❌ Still unauthorized after token refresh - stopping retries.  Please relogin");
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
                    Console.WriteLine($"Unable to retrieve navbar settings. Status: {response?.StatusCode}");
                }

                // Deserialize successful response
                var result = await response.Content.ReadFromJsonAsync<APIResponseViewAccountSettings>();

                if (result == null)
                {
                    Console.WriteLine("❌ Failed to deserialize response");
                }

                Console.WriteLine($"✅ Account settings retrieved successfully (took {currentAttempt} attempt(s))");
                Console.WriteLine("✅ Successfully updated local storage with account settings.");
                Console.WriteLine($"✅ ProfileUsername: {result.UserSettings.ProfileUsername}.");

                // Update local storage with latest navbar info
                if (result != null)
                {
                    if (result.UserSettings != null)
                    {
                        navBarSettingsDTO = result.UserSettings.ToDto();

                        // At this point navBarSettingsDTO should be initialized with data
                        // Serialize ready to store to local strorage

                        var jsonString = JsonSerializer.Serialize(navBarSettingsDTO);
                        Console.WriteLine($"NavBarSettings:Key {_configuration["ApplicationSettings:NavBarSettings"]}");
                        await _localStorage.SetItemAsStringAsync(_configuration["ApplicationSettings:NavBarSettings"]!, jsonString);


                    }
                }               
                

            }
            catch (HttpRequestException ex)
            {
                Console.WriteLine($"⚠️ Network error in GetNavBarAuthDataAsync: {ex.Message}");
                LogException.LogExceptions(ex);
                
            }
            catch (Exception ex)
            {
                Console.WriteLine($"🔥 Unexpected exception in GetNavBarAuthDataAsync: {ex.Message}");
                Console.WriteLine($"Stack trace: {ex.StackTrace}");
                LogException.LogExceptions(ex);

            }
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

        /// <summary>
        /// Client side method to view public profile by username.
        /// </summary>
        /// <param name="profileUsername"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public async Task<APIResponsePublicViewProfile?> ViewProfileByUsernameAsync(string profileUsername, CancellationToken cancellationToken)
        {
            const int maxRetries = 3; // For transient errors only
            int currentAttempt = 0;
            APIResponsePublicViewProfile? _operationResponse;

            if (string.IsNullOrEmpty(profileUsername))
            {
                Console.WriteLine("❌ Profile username is null or empty in ViewProfileByUsernameAsync");
                return new APIResponsePublicViewProfile
                {
                    Success = false,
                    Message = "Profile username cannot be empty."
                };
            }

            try
            {
                Console.WriteLine($"🔑 Atempting to retrieve profile metadata for user: {profileUsername} (Attempt 1/{maxRetries})");
                LogException.LogToConsole($"🔑 Atempting to retrieve profile metadata for user: {profileUsername} (Attempt 1/{maxRetries})");

                HttpResponseMessage? response = null;

                // Retry loop for transient errors
                while (currentAttempt < maxRetries)
                {
                    currentAttempt++;

                    try
                    {
                        // ✅ Use relative URL - HttpClient.BaseAddress already set
                        response = await _httpClient.GetAsync($"/api/account/user/{Uri.EscapeDataString(profileUsername)}");;
                        Console.WriteLine($"📡 Response status (Attempt {currentAttempt}/{maxRetries}): {response.StatusCode}");
                        LogException.LogToConsole($"📡 Response status in ViewProfileByUsernameAsync (Attempt {currentAttempt}/{maxRetries}): {response.StatusCode}");

                        // ✅ SUCCESS - return immediately
                        if (response.IsSuccessStatusCode)
                        {
                            break;
                        }

                        // ⚠️ SERVER ERROR (5xx) or other transient error - retry with backoff
                        else if ((int)response.StatusCode >= 500 || response.StatusCode == System.Net.HttpStatusCode.RequestTimeout)
                        {
                            if (currentAttempt < maxRetries)
                            {
                                var delayMs = currentAttempt * 1000; // Progressive backoff: 1s, 2s, 3s
                                Console.WriteLine($"⚠️ Server error {response.StatusCode}, retrying in {delayMs}ms...");
                                LogException.LogToConsole($"⚠️ Server error {response.StatusCode} in ViewProfileByUsernameAsync, retrying in {delayMs}ms...");
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
                            LogException.LogToConsole($"❌ Client error {response.StatusCode} in ViewProfileByUsernameAsync - not retrying.");
                            break; // Exit retry loop
                        }

                    }
                    catch (HttpRequestException ex)
                    {
                        Console.WriteLine($"⚠️ Network error on attempt {currentAttempt}/{maxRetries}: {ex.Message}");
                        LogException.LogToConsole($"⚠️ Network error on attempt {currentAttempt}/{maxRetries} in ViewProfileByUsernameAsync: {ex.Message}");

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
                            LogException.LogToConsole($"❌ Max retries ({maxRetries}) reached for network error in ViewProfileByUsernameAsync.");
                            return new APIResponsePublicViewProfile
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
                    LogException.LogToConsole($"❌ Final response failed: {response?.StatusCode}");
                    Console.WriteLine($"Error details: {errorContent}");
                    LogException.LogToConsole($"Error details: {errorContent}");

                    return new APIResponsePublicViewProfile
                    {
                        Success = false,
                        Message = $"Unable to retrieve profile at this time. Status: {response?.StatusCode}"
                    };
                }

                // Deserialize successful response
                //_operationResponse = await response.Content.ReadFromJsonAsync<APIResponseUploadPhoto>();
                var result = await response.Content.ReadFromJsonAsync<APIResponsePublicViewProfile>();

                if (result == null)
                {
                    Console.WriteLine("❌ Failed to deserialize response");
                    LogException.LogToConsole("❌ Failed to deserialize response in ViewProfileByUsernameAsync.");

                    return new APIResponsePublicViewProfile
                    {
                        Success = false,
                        Message = "Failed to process server response"
                    };
                }


                Console.WriteLine($"✅ Profile for user: {profileUsername} retrieved successfully, (took {currentAttempt} attempt(s))");
                LogException.LogToConsole("✅ Profile for user: {profileUsername} retrieved successfully.");
                return result;
            }
            catch (OperationCanceledException)
            {
                // Client disconnected or request was cancelled
                Console.WriteLine("⚠️ Operation cancelled in ViewProfileByUsernameAsync");
                return new APIResponsePublicViewProfile
                {
                    Success = false,
                    Message = "The operation was cancelled."
                };
            }
            catch (Exception ex)
            {
                Console.WriteLine($"🔥 Unexpected exception in ViewProfileByUsernameAsync: {ex.Message}");
                Console.WriteLine($"Stack trace: {ex.StackTrace}");
                LogException.LogExceptions(ex);
                return new APIResponsePublicViewProfile
                {
                    Success = false,
                    Message = "An unexpected error occurred. Please try again later."
                };
            }
        }


        // Our CreateTrailService implementation
        public async Task<APIResponseCreateTrail> CreateTrailAsync(CreateTrailDTO model, CancellationToken cancellationToken)
        {
            const int maxRetries =3; // For transient errors only
            int currentAttempt =0;

            // validate model client-side before sending to API
            var modelValid = IsCreateTrailRequestValid(model);
            if (modelValid.Success == false)
            {
                return new APIResponseCreateTrail
                {
                    Success = false,
                    Message = modelValid.ValidationMessage
                };
            }

            try
            {
                // Get JWT token from local storage and set Authorization header
                var authData = await _localStorage.GetItemAsStringAsync(_configuration["ApplicationSettings:LocalStorageKey"]!);
                if (string.IsNullOrEmpty(authData))
                {
                    return new APIResponseCreateTrail { Success = false, Message = "User is not authenticated" };
                }

                var authLocalStorageDTO = JsonSerializer.Deserialize<AuthenticatedLocalStorageDTO>(authData);
                if (authLocalStorageDTO == null || string.IsNullOrEmpty(authLocalStorageDTO.JWtToken))
                {
                    return new APIResponseCreateTrail { Success = false, Message = "User is not authenticated" };
                }

                _httpClient.DefaultRequestHeaders.Authorization =
                    new AuthenticationHeaderValue("Bearer", authLocalStorageDTO.JWtToken);

                Console.WriteLine($"🔑 Attempting to create a new trail: {model.Title} (Attempt1/{maxRetries})");
                LogException.LogToConsole($"🔑 Attempting to create a new trail: {model.Title} (Attempt1/{maxRetries})");

                HttpResponseMessage? response = null;
                bool tokenWasRefreshed = false;

                // Retry loop for transient errors
                while (currentAttempt < maxRetries)
                {
                    currentAttempt++;

                    try
                    {
                        // POST to the correct endpoint 'api/trails'
                        response = await _httpClient.PostAsJsonAsync("api/trails", model, cancellationToken);
                        Console.WriteLine($"📡 Response status (Attempt {currentAttempt}/{maxRetries}): {response.StatusCode}");
                        LogException.LogToConsole($"📡 Response status in CreateTrailAsync (Attempt {currentAttempt}/{maxRetries}): {response.StatusCode}");

                        if (response.IsSuccessStatusCode)
                        {
                            break;
                        }

                        // Handle 5xx transient errors
                        if ((int)response.StatusCode >=500 || response.StatusCode == System.Net.HttpStatusCode.RequestTimeout)
                        {
                            if (currentAttempt < maxRetries)
                            {
                                var delayMs = currentAttempt *1000;
                                Console.WriteLine($"⚠️ Server error {response.StatusCode}, retrying in {delayMs}ms...");
                                await Task.Delay(delayMs, cancellationToken);
                                continue;
                            }
                            else
                            {
                                Console.WriteLine($"❌ Max retries ({maxRetries}) reached for server error");
                                break;
                            }
                        }

                        // For client errors (4xx), don't retry
                        Console.WriteLine($"❌ Client error {response.StatusCode} - not retrying");
                        break;
                    }
                    catch (OperationCanceledException)
                    {
                        // Cancellation requested
                        Console.WriteLine("⚠️ CreateTrailAsync was cancelled");
                        return new APIResponseCreateTrail { Success = false, Message = "Trail creation was cancelled." };
                    }
                    catch (HttpRequestException ex)
                    {
                        Console.WriteLine($"⚠️ Network error on attempt {currentAttempt}/{maxRetries}: {ex.Message}");
                        LogException.LogToConsole($"⚠️ Network error on attempt {currentAttempt}/{maxRetries} in CreateTrailAsync: {ex.Message}");

                        if (currentAttempt < maxRetries)
                        {
                            var delayMs = currentAttempt *1000;
                            Console.WriteLine($"Retrying in {delayMs}ms...");
                            await Task.Delay(delayMs, cancellationToken);
                            continue; // Retry
                        }
                        else
                        {
                            Console.WriteLine($"❌ Max retries ({maxRetries}) reached for network error");
                            return new APIResponseCreateTrail { Success = false, Message = "Network error. Please check your connection and try again." };
                        }
                    }
                }

                // Final check
                if (response == null || !response.IsSuccessStatusCode)
                {
                    var errorContent = response != null ? await response.Content.ReadAsStringAsync(cancellationToken) : "No response received";
                    Console.WriteLine($"❌ Final response failed: {response?.StatusCode}");
                    Console.WriteLine($"Error details: {errorContent}");
                    return new APIResponseCreateTrail { Success = false, Message = $"Unable to create trail. Status: {response?.StatusCode}" };
                }

                var result = await response.Content.ReadFromJsonAsync<APIResponseCreateTrail>(cancellationToken: cancellationToken);
                return result ?? new APIResponseCreateTrail { Success = false, Message = "Failed to parse server response." };
            }
            catch (OperationCanceledException)
            {
                Console.WriteLine("⚠️ CreateTrailAsync cancelled by caller");
                return new APIResponseCreateTrail { Success = false, Message = "Trail creation was cancelled." };
            }
            catch (Exception ex)
            {
                Console.WriteLine($"🔥 Exception in CreateTrailAsync: {ex.Message}");
                LogException.LogExceptions(ex);
                return new APIResponseCreateTrail { Success = false, Message = "An unexpected error occurred while creating trail." };
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


        /// <summary>
        ///  Client-side method to update the profile picture URL of the currently authenticated user.
        /// </summary>
        /// <param name="updateProfilePhotoDTO"></param>
        /// <returns></returns>
        public async Task<APIResponseUploadPhoto> UpdateProfilePictureUrlAsync(UpdateProfilePhotoDTO updateProfilePhotoDTO, CancellationToken cancellationToken = default)
        {
            const int maxRetries = 3; // For transient errors only
            int currentAttempt = 0;
            APIResponseUploadPhoto? _operationResponse;

            // Make sure a file is provided
            if (updateProfilePhotoDTO.ProfilePhoto == null)
            {
                return new APIResponseUploadPhoto
                {
                    Success = false,
                    Message = "No profile photo provided"
                };
            }

            try
            {
                // Get JWT token from local storage
                var authData = await _localStorage.GetItemAsStringAsync(_configuration["ApplicationSettings:LocalStorageKey"]!);

                if (string.IsNullOrEmpty(authData))
                {
                    Console.WriteLine("❌ No authentication data in local storage");
                    return new APIResponseUploadPhoto
                    {
                        Success = false,
                        Message = "User is not authenticated"
                    };
                }

                var authLocalStorageDTO = JsonSerializer.Deserialize<AuthenticatedLocalStorageDTO>(authData);

                if (authLocalStorageDTO == null || string.IsNullOrEmpty(authLocalStorageDTO.JWtToken))
                {
                    Console.WriteLine("❌ Invalid authentication data or missing JWT token");
                    return new APIResponseUploadPhoto
                    {
                        Success = false,
                        Message = "User is not authenticated"
                    };
                }

                // Set the JWT token in the Authorization header
                _httpClient.DefaultRequestHeaders.Authorization =
                    new AuthenticationHeaderValue("Bearer", authLocalStorageDTO.JWtToken);

                Console.WriteLine($"🔑 Atempting to upload profile photo for user: (Attempt 1/{maxRetries})");
                LogException.LogToConsole($"🔑 Attempting to upload profile photo in UpdateProfilePictureUrlAsync (Attempt 1/{maxRetries})");

                
                // Prepare multipart form data content
                var content = new MultipartFormDataContent();
                var fileContent = new StreamContent(updateProfilePhotoDTO.ProfilePhoto!.OpenReadStream());

                // Set content headers, must match the UpdateProfilePhotoDTO properties!
                //content.Add(new StringContent(dto.ContentType, Encoding.UTF8, MediaTypeNames.Text.Plain), "ContentType");
                content.Add(new StringContent(updateProfilePhotoDTO.ContentType!, Encoding.UTF8, MediaTypeNames.Text.Plain), "ContentType");
                //  Actual file content to match ProfilePhoto property
                content.Add(fileContent, "ProfilePhoto", updateProfilePhotoDTO.ProfilePhoto.FileName);

                HttpResponseMessage? response = null;
                bool tokenWasRefreshed = false;

                // Retry loop for transient errors
                while (currentAttempt < maxRetries)
                {
                    currentAttempt++;

                    try
                    {
                        // ✅ Use relative URL - HttpClient.BaseAddress already set
                        // POST multipart/form-data requires a PostAsync call with MultipartFormDataContent not PostAsJsonAsync
                        response = await _httpClient.PostAsync("api/account/upload-profile-picture", content, cancellationToken);
                        Console.WriteLine($"📡 Response status (Attempt {currentAttempt}/{maxRetries}): {response.StatusCode}");
                        LogException.LogToConsole($"📡 Response status in UpdateProfilePictureUrlAsync (Attempt {currentAttempt}/{maxRetries}): {response.StatusCode}");

                        // ✅ SUCCESS - return immediately
                        if (response.IsSuccessStatusCode)
                        {
                            break;
                        }

                        // ❌ UNAUTHORIZED - Try token refresh (only once)
                        if (CheckIfUnauthorized(response) && !tokenWasRefreshed)
                        {
                            Console.WriteLine("⚠️ Token expired, attempting refresh...");
                            LogException.LogToConsole("⚠️ Token expired in UpdateProfilePictureUrlAsync, attempting refresh...");

                            var refreshedToken = await GetRefreshTokenAsync();

                            if (refreshedToken is not null && !string.IsNullOrEmpty(refreshedToken.JWtToken))
                            {
                                Console.WriteLine("✅ Token refreshed, retrying request...");
                                LogException.LogToConsole("✅ Token refreshed in UpdateProfilePictureUrlAsync, retrying request.");
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
                                LogException.LogToConsole("❌ Token refresh failed in UpdateProfilePictureUrlAsync - user needs to re-login.");
                                return new APIResponseUploadPhoto
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
                            LogException.LogToConsole("❌ Still unauthorized after token refresh in UpdateProfilePictureUrlAsync - stopping retries.");
                            return new APIResponseUploadPhoto
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
                                LogException.LogToConsole($"⚠️ Server error {response.StatusCode} in UpdateProfilePictureUrlAsync, retrying in {delayMs}ms...");
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
                            LogException.LogToConsole($"❌ Client error {response.StatusCode} in UpdateProfilePictureUrlAsync - not retrying.");
                            break; // Exit retry loop
                        }

                    }
                    catch (HttpRequestException ex)
                    {
                        Console.WriteLine($"⚠️ Network error on attempt {currentAttempt}/{maxRetries}: {ex.Message}");
                        LogException.LogToConsole($"⚠️ Network error on attempt {currentAttempt}/{maxRetries} in UpdateProfilePictureUrlAsync: {ex.Message}");

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
                            LogException.LogToConsole($"❌ Max retries ({maxRetries}) reached for network error in UpdateProfilePictureUrlAsync.");
                            return new APIResponseUploadPhoto
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
                    LogException.LogToConsole($"❌ Final response failed: {response?.StatusCode}");
                    Console.WriteLine($"Error details: {errorContent}");
                    LogException.LogToConsole($"Error details: {errorContent}");

                    return new APIResponseUploadPhoto
                    {
                        Success = false,
                        Message = $"Unable to uplaod profile photo at this time. Status: {response?.StatusCode}"
                    };
                }

                // Deserialize successful response
                //_operationResponse = await response.Content.ReadFromJsonAsync<APIResponseUploadPhoto>();
                var result = await response.Content.ReadFromJsonAsync<APIResponseUploadPhoto>();

                if (result == null)
                {
                    Console.WriteLine("❌ Failed to deserialize response");
                    LogException.LogToConsole("❌ Failed to deserialize response in UpdateProfilePictureUrlAsync.");
                    return new APIResponseUploadPhoto   
                    {
                        Success = false,
                        Message = "Failed to process server response"
                    };
                }

                Console.WriteLine($"✅ Updated profile picture for user: {authLocalStorageDTO.ProfileUsername} successfully, (took {currentAttempt} attempt(s))");
                LogException.LogToConsole("✅ Updated profile picture for user: {authLocalStorageDTO.ProfileUsername} successfully, (took {currentAttempt} attempt(s))");
                return result;

            }
            catch (Exception ex)
            {
                Console.WriteLine($"🔥 Unexpected exception in UpdateProfilePictureUrlAsync: {ex.Message}");
                Console.WriteLine($"Stack trace: {ex.StackTrace}");
                LogException.LogExceptions(ex);
                // Return failure response
                return new APIResponseUploadPhoto
                {
                    Success = false,
                    Message = "An unexpected error occurred. Please try again later."
                };
            }
        }

        /// <summary>
        /// Helper method to validate CreateTrailDTO on client side before sending to API.
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        private (bool Success, string ValidationMessage) IsCreateTrailRequestValid(CreateTrailDTO model)
        {
            if (model == null)
            {
                return (false, "Form is null");
            }

            // Additional domain checks not covered by attributes
            if (model.Start == null)
                return(false, "Start coordinate is required.");

            if (model.End == null)
                return(false, "End coordinate is required.");

            if (model.Waypoints == null || model.Waypoints.Count < 2)
                return(false, "Waypoints must contain at least two coordinates (start and end).");

            if (model.LengthMeters <= 0)
                return(false, "LengthMeters must be greater zero.");
            if(model.Title != null && model.Title.Length > 150)
            {
                return (false, "Title exceeds maximum length of 150 characters.");
            }
            if(model.Description != null && model.Description.Length > 600)
            {
                return (false, "Description exceeds maximum length of 600 characters.");
            }
            //test if waypoints are not null
            if(model.Waypoints.Any(wp => wp == null))
            {
                return (false, "Waypoints cannot contain null values.");
            }
            // Waypoint automaticall checks for valid lat/lng in WTLatLng struct
            else
            {
                return (true, "");
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
