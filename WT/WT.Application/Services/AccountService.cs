using Blazored.LocalStorage;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.JSInterop;
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
        private readonly IJSRuntime? _jsRuntime;
        private readonly ITokenService? _tokenService;

        public AccountService(HttpClient httpClient, IConfiguration config, ILocalStorageService localStorage, IJSRuntime? jsRuntime = null, ITokenService? tokenService = null) : base(httpClient, config, localStorage)
        {
            _httpClient = httpClient;
            _localStorage = localStorage;
            _configuration = config;
            _jsRuntime = jsRuntime;
            _tokenService = tokenService;
        }

        /// <summary>
        /// Try to get a fresh access token from the server. Prefer using JS fetch with credentials include when available
        /// (Blazor WASM) so HttpOnly refresh cookie is sent. Falls back to server POST via HttpClient when JS runtime is not available.
        /// </summary>
        private async Task<APIResponseAuthentication?> TryGetRefreshTokenAsync()
        {
            try
            {
                // If running in the browser and IJSRuntime provided, perform fetch with credentials: 'include'
                if (_jsRuntime != null)
                {
                    try
                    {
                        var json = await _jsRuntime.InvokeAsync<string>("wtApi.fetchRefreshToken");
                        if (string.IsNullOrEmpty(json)) return null;
                        var jsResult = JsonSerializer.Deserialize<APIResponseAuthentication>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                        return jsResult;
                    }
                    catch (JSException jsEx)
                    {
                        // Fall through to HttpClient approach if JS fetch fails
                        Console.WriteLine($"⚠️ JS fetch refresh failed: {jsEx.Message}");
                    }
                }

                // Fallback: call API refresh endpoint using HttpClient (may not include cookies in some environments)
                var response = await _httpClient.PostAsync("api/account/identity/refresh-token", null);
                if (!response.IsSuccessStatusCode)
                {
                    if (response.StatusCode == System.Net.HttpStatusCode.NoContent)
                        return null;

                    return null;
                }

                var httpResult = await response.Content.ReadFromJsonAsync<APIResponseAuthentication>();
                return httpResult;
            }
            catch (Exception ex)
            {
                LogException.LogExceptions(ex);
                return null;
            }
        }

        // Backwards-compatible wrapper used by other methods
        private Task<APIResponseAuthentication?> GetRefreshTokenAsync() => TryGetRefreshTokenAsync();

        /// <summary>
        /// Ensure the HttpClient Authorization header is set.
        /// This prefers the in-memory token (TokenService) if available, otherwise attempts refresh via HttpOnly cookie.
        /// </summary>
        private async Task<bool> EnsureAuthorizationHeaderAsync()
        {
            try
            {
                // Prefer in-memory access token stored by TokenService (set during login)
                if (_tokenService != null && !string.IsNullOrEmpty(_tokenService.AccessToken) && !_tokenService.IsExpired())
                {
                    _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _tokenService.AccessToken);
                    return true;
                }

                // Fallback: Try to refresh via server which reads HttpOnly cookie and returns a new access token
                var refreshed = await TryGetRefreshTokenAsync();
                if (refreshed is null || string.IsNullOrEmpty(refreshed.JwtToken))
                {
                    Console.WriteLine("❌ Unable to obtain access token from refresh endpoint");
                    return false;
                }

                _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", refreshed.JwtToken);
                return true;
            }
            catch (Exception ex)
            {
                LogException.LogExceptions(ex);
                return false;
            }
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
                // Ensure Authorization header is set using refresh-token endpoint (server reads HttpOnly cookie)
                if (!await EnsureAuthorizationHeaderAsync())
                {
                    return new APIResponseViewAccountSettings
                    {
                        Success = false,
                        Message = "User is not authenticated"
                    };
                }

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

                            if (refreshedToken is not null && !string.IsNullOrEmpty(refreshedToken.JwtToken))
                            {
                                Console.WriteLine("✅ Token refreshed, retrying request...");
                                tokenWasRefreshed = true;

                                // Update Authorization header with new token
                                _httpClient.DefaultRequestHeaders.Authorization =
                                    new AuthenticationHeaderValue("Bearer", refreshedToken.JwtToken);

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
                // If JS runtime is available (WASM), use fetch with credentials to ensure refresh cookie is set
                if (_jsRuntime != null)
                {
                    try
                    {
                        // Compute absolute API login URL. Prefer HttpClient.BaseAddress, fall back to configured BaseApiUrl.
                        string loginUrl;
                        if (_httpClient.BaseAddress != null)
                        {
                            loginUrl = new Uri(_httpClient.BaseAddress, "api/account/identity/login").ToString();
                        }
                        else
                        {
                            var cfgBase = _configuration["ConnectionStrings:BaseApiUrl"] ?? "";
                            loginUrl = cfgBase.TrimEnd('/') + "/api/account/identity/login";
                        }

                        Console.WriteLine($"🔧 JS login URL: {loginUrl}");

                        var jsResponse = await _jsRuntime.InvokeAsync<string>("wtApi.login", loginUrl, model);
                        if (!string.IsNullOrEmpty(jsResponse))
                        {
                            // jsResponse is a JSON string with { status, body }
                            using var doc = JsonDocument.Parse(jsResponse);
                            var root = doc.RootElement;
                            var status = root.GetProperty("status").GetInt32();
                            var body = root.GetProperty("body").GetString();

                            if (status >=200 && status <300 && !string.IsNullOrEmpty(body))
                            {
                                var apiResult = JsonSerializer.Deserialize<APIResponseAuthentication>(body, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                                if (apiResult != null && apiResult.Success && !string.IsNullOrEmpty(apiResult.JwtToken))
                                {
                                    _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", apiResult.JwtToken);
                                }

                                return apiResult ?? new APIResponseAuthentication { Success = false, Message = "Login failed" };
                            }
                            else
                            {
                                // Attempt to parse friendly error from body
                                if (!string.IsNullOrEmpty(body))
                                {
                                    var friendly = JsonSerializer.Deserialize<APIResponseAuthentication>(body, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                                    if (friendly != null && !string.IsNullOrEmpty(friendly.Message))
                                        return new APIResponseAuthentication { Success = false, Message = friendly.Message };
                                }

                                return new APIResponseAuthentication { Success = false, Message = $"Login failed: status {status}" };
                            }
                        }
                    }
                    catch (JSException jsEx)
                    {
                        Console.WriteLine($"⚠️ JS login failed: {jsEx.Message}");
                        // fallthrough to HttpClient approach
                    }
                }

                // Fallback to HttpClient POST (may not include cookies in some environments)
                var response = await _httpClient.PostAsJsonAsync("api/account/identity/login", model);

                // Check if the response was successful
                if (!response.IsSuccessStatusCode)
                {
                    var friendlyError = await response.Content.ReadFromJsonAsync<APIResponseAuthentication>();
                    Console.WriteLine($"❌ Login failed. Status: {response.StatusCode}");

                    if (friendlyError != null && !string.IsNullOrEmpty(friendlyError.Message))
                    {
                        return new APIResponseAuthentication
                        {
                            Success = false,
                            Message = friendlyError.Message
                        };
                    }
                    else
                    {
                        return new APIResponseAuthentication
                        {
                            Success = false,
                            Message = $"Login failed: {response.StatusCode}"
                        };
                    }

                }

                var result = await response.Content.ReadFromJsonAsync<APIResponseAuthentication>();

                // Set Authorization header with returned access token so subsequent requests work immediately
                if (result?.Success == true && !string.IsNullOrEmpty(result.JwtToken))
                {
                    _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", result.JwtToken);
                    Console.WriteLine("✅ Set HttpClient Authorization header after successful login");

                    // Persist access token to in-memory TokenService if available
                    if (_tokenService != null)
                    {
                        try
                        {
                            var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
                            var jwt = handler.ReadJwtToken(result.JwtToken);
                            _tokenService.SetAccessToken(result.JwtToken, jwt.ValidTo);
                            Console.WriteLine("🔐 TokenService access token set");
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"⚠️ Failed to set TokenService access token: {ex.Message}");
                        }
                    }

                    // Persist small non-sensitive navbar/session info to local storage so UI can render immediately
                    try
                    {
                        var navKey = _configuration["ApplicationSettings:NavBarSettings"] ?? "NavBarSettings";
                        var session = new AuthenticatedSessionDTO
                        {
                            Id = result.User?.Id,
                            FirstName = result.User?.FirstName,
                            ProfileUsername = result.User?.ProfileUsername,
                            UserPhoto = result.User?.ProfilePicture,
                            Email = result.User?.Email,
                            GpsAccuracy = result.User?.GpsAccuracy ?? WT.Domain.Enums.GpsAccuracyLevel.Default,
                            ShowRecordingWarning = result.User?.ShowRecordingWarning ?? true,
                            TimeStamp = DateTime.UtcNow,
                            JWtToken = null // do NOT store JWT in local storage
                        };

                        var json = JsonSerializer.Serialize(session);
                        await _localStorage.SetItemAsStringAsync(navKey, json);
                        Console.WriteLine("💾 NavBar session persisted to local storage (non-sensitive data)");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"⚠️ Failed to persist navbar session to local storage: {ex.Message}");
                    }
                }

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

            try
            {
                // Ensure Authorization header is set using refresh-token endpoint (server reads HttpOnly cookie)
                if (!await EnsureAuthorizationHeaderAsync())
                {
                    return new APIResponseViewAccountSettings
                    {
                        Success = false,
                        Message = "User is not authenticated"
                    };
                }

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

                            if (refreshedToken is not null && !string.IsNullOrEmpty(refreshedToken.JwtToken))
                            {
                                Console.WriteLine("✅ Token refreshed, retrying request...");
                                LogException.LogToConsole("✅ Token refreshed in AuthenticatedResetPasswordAsync, retrying request.");
                                tokenWasRefreshed = true;

                                // Update Authorization header with new token
                                _httpClient.DefaultRequestHeaders.Authorization =
                                    new AuthenticationHeaderValue("Bearer", refreshedToken.JwtToken);

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

            try
            {
                // Ensure Authorization header
                if (!await EnsureAuthorizationHeaderAsync())
                {
                    Console.WriteLine("❌ No authentication available for navbar settings");
                    return;
                }

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

                            if (refreshedToken is not null && !string.IsNullOrEmpty(refreshedToken.JwtToken))
                            {
                                Console.WriteLine("✅ Token refreshed, retrying request...");
                                tokenWasRefreshed = true;

                                // Update Authorization header with new token
                                _httpClient.DefaultRequestHeaders.Authorization =
                                    new AuthenticationHeaderValue("Bearer", refreshedToken.JwtToken);

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
                            Console.WriteLine("❌ Still unauthorized after token refresh - stopping retries. Please relogin");
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
                var result = await response!.Content.ReadFromJsonAsync<APIResponseViewAccountSettings>();

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

                        // SECURITY NOTE:
                        // Only non-sensitive UI data is stored in the NavBar local storage key (e.g., display name,
                        // profile picture URL, and public username). Sensitive tokens or personal data (JWT, refresh tokens,
                        // email addresses used for authorization) must NOT be stored here. The authentication flow keeps
                        // tokens in-memory (TokenService) and uses HttpOnly cookies for refresh tokens.
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
                        response = await _httpClient.GetAsync($"/api/account/user/{Uri.EscapeDataString(profileUsername)}"); ;
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
                                await Task.Delay(delayMs, cancellationToken);
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
                            await Task.Delay(delayMs, cancellationToken);
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
            const int maxRetries = 3; // For transient errors only
            int currentAttempt = 0;

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
                // Ensure Authorization header is set using refresh-token endpoint (server reads HttpOnly cookie)
                if (!await EnsureAuthorizationHeaderAsync())
                {
                    return new APIResponseCreateTrail { Success = false, Message = "User is not authenticated" };
                }

                Console.WriteLine($"🔑 Attempting to create a new trail: {model.Title} (Attempt 1/{maxRetries})");
                LogException.LogToConsole($"🔑 Attempting to create a new trail: {model.Title} (Attempt 1/{maxRetries})");

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
                        if ((int)response.StatusCode >= 500 || response.StatusCode == System.Net.HttpStatusCode.RequestTimeout)
                        {
                            if (currentAttempt < maxRetries)
                            {
                                var delayMs = currentAttempt * 1000;
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
                            var delayMs = currentAttempt * 1000;
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
        /// Client-side method to update the profile picture URL of the currently authenticated user.
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
                // Ensure Authorization header is set using refresh-token endpoint (server reads HttpOnly cookie)
                if (!await EnsureAuthorizationHeaderAsync())
                {
                    return new APIResponseUploadPhoto
                    {
                        Success = false,
                        Message = "User is not authenticated"
                    };
                }

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

                            if (refreshedToken is not null && !string.IsNullOrEmpty(refreshedToken.JwtToken))
                            {
                                Console.WriteLine("✅ Token refreshed, retrying request...");
                                LogException.LogToConsole("✅ Token refreshed in UpdateProfilePictureUrlAsync, retrying request.");
                                tokenWasRefreshed = true;

                                // Update Authorization header with new token
                                _httpClient.DefaultRequestHeaders.Authorization =
                                    new AuthenticationHeaderValue("Bearer", refreshedToken.JwtToken);

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
                //_operation_response = await response.Content.ReadFromJsonAsync<APIResponseUploadPhoto>();
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

                Console.WriteLine($"✅ Updated profile picture for user successfully, (took {currentAttempt} attempt(s))");
                LogException.LogToConsole("✅ Updated profile picture for user successfully.");
                return result;

            }
            // Catch operation cancelled
            catch (OperationCanceledException)
            {
                // Client disconnected or request was cancelled
                Console.WriteLine("⚠️ Operation cancelled in UpdateProfilePictureUrlAsync");
                return new APIResponseUploadPhoto
                {
                    Success = false,
                    Message = "The operation was cancelled."
                };
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


        public async Task<APIResponseUploadPhoto> UploadTrailPhotoAsync(Guid trailId, System.IO.Stream fileStream, string fileName, string? contentType = null, IProgress<int>? progress = null, CancellationToken cancellationToken = default)
        {
            const int maxRetries = 3;
            int currentAttempt = 0;

            if (fileStream == null || !fileStream.CanRead)
            {
                return new APIResponseUploadPhoto { Success = false, Message = "No file provided" };
            }

            try
            {
                // Ensure Authorization header is set using refresh-token endpoint (server reads HttpOnly cookie)
                if (!await EnsureAuthorizationHeaderAsync())
                    return new APIResponseUploadPhoto { Success = false, Message = "User is not authenticated" };

                _httpClient.DefaultRequestHeaders.Authorization = _httpClient.DefaultRequestHeaders.Authorization; // no-op

                HttpResponseMessage? response = null;
                bool tokenWasRefreshed = false;

                while (currentAttempt < maxRetries)
                {
                    currentAttempt++;

                    try
                    {
                        // build multipart content for this attempt
                        using var content = new MultipartFormDataContent();
                        var streamContent = new StreamContent(fileStream);
                        try { streamContent.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(contentType ?? "application/octet-stream"); } catch { }
                        content.Add(new StringContent(trailId.ToString(), Encoding.UTF8, MediaTypeNames.Text.Plain), "TrailId");
                        content.Add(streamContent, "TrailPhoto", fileName);
                        if (!string.IsNullOrEmpty(contentType))
                            content.Add(new StringContent(contentType, Encoding.UTF8, MediaTypeNames.Text.Plain), "ContentType");

                        response = await _httpClient.PostAsync("api/trails/upload-trail-photo", content, cancellationToken);

                        if (response.IsSuccessStatusCode)
                            break;

                        if (CheckIfUnauthorized(response) && !tokenWasRefreshed)
                        {
                            var refreshedToken = await GetRefreshTokenAsync();
                            if (refreshedToken is not null && !string.IsNullOrEmpty(refreshedToken.JwtToken))
                            {
                                tokenWasRefreshed = true;
                                _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", refreshedToken.JwtToken);
                                currentAttempt--;
                                continue;
                            }
                            else
                            {
                                return new APIResponseUploadPhoto { Success = false, Message = "Session expired. Please log in again." };
                            }
                        }

                        if (CheckIfUnauthorized(response) && tokenWasRefreshed)
                        {
                            return new APIResponseUploadPhoto { Success = false, Message = "Authentication failed. Please log in again." };
                        }

                        if ((int)response.StatusCode >= 500 || response.StatusCode == System.Net.HttpStatusCode.RequestTimeout)
                        {
                            if (currentAttempt < maxRetries)
                            {
                                await Task.Delay(currentAttempt * 1000, cancellationToken);
                                continue;
                            }
                            else
                                break;
                        }

                        break;
                    }
                    catch (HttpRequestException)
                    {
                        if (currentAttempt < maxRetries)
                        {
                            await Task.Delay(currentAttempt * 1000, cancellationToken);
                            continue;
                        }
                        return new APIResponseUploadPhoto { Success = false, Message = "Network error. Please check your connection and try again." };
                    }
                }

                if (response == null || !response.IsSuccessStatusCode)
                {
                    var errorContent = response != null ? await response.Content.ReadAsStringAsync(cancellationToken) : "No response received";
                    Console.WriteLine($"❌ Final response failed: {response?.StatusCode}");
                    Console.WriteLine($"Error details: {errorContent}");
                    return new APIResponseUploadPhoto { Success = false, Message = $"Unable to upload trail photo. Status: {response?.StatusCode}. {errorContent}" };
                }

                var result = await response.Content.ReadFromJsonAsync<APIResponseUploadPhoto>(cancellationToken: cancellationToken);
                return result ?? new APIResponseUploadPhoto { Success = false, Message = "Failed to parse server response" };
            }
            catch (OperationCanceledException)
            {
                return new APIResponseUploadPhoto { Success = false, Message = "Upload cancelled" };
            }
            catch (Exception ex)
            {
                LogException.LogExceptions(ex);
                return new APIResponseUploadPhoto { Success = false, Message = "An unexpected error occurred during upload" };
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
                return (false, "Start coordinate is required.");

            if (model.End == null)
                return (false, "End coordinate is required.");

            if (model.Waypoints == null || model.Waypoints.Count < 2)
                return (false, "Waypoints must contain at least two coordinates (start and end).");

            if (model.LengthMeters <= 0)
                return (false, "LengthMeters must be greater zero.");
            if (model.Title != null && model.Title.Length > 150)
            {
                return (false, "Title exceeds maximum length of 150 characters.");
            }
            if (model.Description != null && model.Description.Length > 600)
            {
                return (false, "Description exceeds maximum length of 600 characters.");
            }
            //test if waypoints are not null
            if (model.Waypoints.Any(wp => wp == null))
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

        public async Task LogoutAsync()
        {
            try
            {
                var response = await _httpClient.PostAsync("api/account/identity/logout", null);
                if (!response.IsSuccessStatusCode)
                {
                    var friendly = await response.Content.ReadFromJsonAsync<BaseAPIResponseDTO>();
                    LogException.LogToConsole($"Logout failed: {friendly?.Message ?? response.StatusCode.ToString()}");
                }
            }
            catch (Exception ex)
            {
                LogException.LogExceptions(ex);
            }
        }
    }
}
