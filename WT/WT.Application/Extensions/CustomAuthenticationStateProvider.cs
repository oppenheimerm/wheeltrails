using Blazored.LocalStorage;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.Configuration;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using WT.Application.APIServiceLogs;
using WT.Application.DTO.Request.Account;
using WT.Application.DTO.Response;
using WT.Application.Services;
using Microsoft.JSInterop;

namespace WT.Application.Extensions
{
    /// <summary>
    /// Custom authentication state provider for Blazor WebAssembly that manages user authentication
    /// state using JWT tokens. Access tokens are stored in-memory via ITokenService. Refresh tokens
    /// are handled server-side via HttpOnly cookies and the refresh endpoint.
    /// </summary>
    public class CustomAuthenticationStateProvider : AuthenticationStateProvider
    {
        readonly ILocalStorageService? localStorageService;
        readonly IConfiguration? configuration;
        readonly string? LocalStorageKey;
        readonly HttpClient? _httpClient;
        readonly ITokenService? _token_service;
        readonly IJSRuntime? _jsRuntime;

        /// <summary>
        /// Represents an anonymous (unauthenticated) user with no claims.
        /// </summary>
        readonly ClaimsPrincipal anonymous = new(new ClaimsIdentity());

        /// <summary>
        /// In-memory session DTO containing user/session data returned from the API refresh endpoint.
        /// This is intentionally not persisted to localStorage by the authentication flow.
        /// </summary>
        AuthenticatedSessionDTO? AuthenticatedSessionDTO { get; set; }

        public CustomAuthenticationStateProvider(ILocalStorageService _localStorageService, IConfiguration _configuration, HttpClient httpClient, ITokenService tokenService, IJSRuntime? jsRuntime = null)
        {
            localStorageService = _localStorageService;
            configuration = _configuration;
            LocalStorageKey = configuration["ApplicationSettings:LocalStorageKey"]!;
            _httpClient = httpClient;
            _token_service = tokenService;
            _jsRuntime = jsRuntime;
        }

        /// <summary>
        /// Retrieves the current authentication state by reading and validating the stored JWT token.
        /// </summary>
        /// <returns>
        /// A <see cref="Task{AuthenticationState}"/> representing the current authentication state.
        /// Returns an anonymous state if no valid token is found or if validation fails.
        /// </returns>
        public override async Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            try
            {
                //1) If we have an in-memory access token, build claims from it
                if (_token_service is not null && !string.IsNullOrEmpty(_token_service.AccessToken))
                {
                    var claims = DecryptToken(_token_service.AccessToken!);
                    if (claims is null || string.IsNullOrEmpty(claims.Email) || claims.Id == Guid.Empty)
                    {
                        return await Task.FromResult(new AuthenticationState(anonymous));
                    }

                    var claimsPrincipal = SetClaimsPrincipal(claims);
                    return await Task.FromResult(new AuthenticationState(claimsPrincipal));
                }

                // NOTE: By design we do NOT rehydrate JWT from localStorage. Access tokens are kept
                // only in-memory (TokenService). To restore auth after a full page reload we rely on
                // the server-side HttpOnly refresh cookie and the refresh endpoint below. This avoids
                // persisting JWTs to localStorage and reduces XSS attack surface.

                // Decide whether to try refresh using HttpOnly cookie. We use a lightweight flag in
                // localStorage (HasSession) to avoid noisy refresh attempts for users who never logged in.
                try
                {
                    if (localStorageService is not null)
                    {
                        var hasSession = await localStorageService.GetItemAsync<bool>("HasSession");
                        if (!hasSession)
                        {
                            // No prior session recorded -> return anonymous without calling refresh endpoint
                            return await Task.FromResult(new AuthenticationState(anonymous));
                        }
                    }
                }
                catch (Exception ex)
                {
                    // If local storage read fails, fall back to attempting refresh (safe)
                    LogException.LogExceptions(ex);
                }

                //2) No in-memory token -> try to refresh using HttpOnly cookie via refresh endpoint
                if (_httpClient is null)
                {
                    LogException.LogToConsole("Authentication state provider: HttpClient not available");
                    return await Task.FromResult(new AuthenticationState(anonymous));
                }

                // Prefer JS fetch with credentials: 'include' when running in browser so cookies are sent.
                if (_jsRuntime != null)
                {
                    try
                    {
                        var refreshUrl = _httpClient.BaseAddress != null
                            ? new Uri(_httpClient.BaseAddress, "api/account/identity/refresh-token").ToString()
                            : "api/account/identity/refresh-token";

                        var json = await _jsRuntime.InvokeAsync<string>("wtApi.fetchRefreshToken", refreshUrl);
                        if (!string.IsNullOrEmpty(json))
                        {
                            var apiResult = JsonSerializer.Deserialize<APIResponseAuthentication>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                            if (apiResult != null && apiResult.Success && !string.IsNullOrEmpty(apiResult.JwtToken))
                            {
                                try
                                {
                                    var handler = new JwtSecurityTokenHandler();
                                    var jwt = handler.ReadJwtToken(apiResult.JwtToken);
                                    _token_service?.SetAccessToken(apiResult.JwtToken, jwt.ValidTo);
                                }
                                catch (Exception ex)
                                {
                                    LogException.LogExceptions(ex);
                                }

                                var userClaims = DecryptToken(apiResult.JwtToken!);
                                if (userClaims is null || string.IsNullOrEmpty(userClaims.Email) || userClaims.Id == Guid.Empty)
                                {
                                    return await Task.FromResult(new AuthenticationState(anonymous));
                                }

                                // Persist small non-sensitive session DTO so UI can render immediately after reload
                                try
                                {
                                    if (localStorageService is not null)
                                    {
                                        await localStorageService.SetItemAsync("HasSession", true);
                                        if (!string.IsNullOrEmpty(LocalStorageKey))
                                        {
                                            var session = new AuthenticatedSessionDTO
                                            {
                                                TimeStamp = DateTime.UtcNow,
                                                Id = userClaims.Id,
                                                FirstName = userClaims.FirstName,
                                                ProfileUsername = apiResult.User?.ProfileUsername,
                                                UserPhoto = apiResult.User?.ProfilePicture,
                                                Email = userClaims.Email,
                                                GpsAccuracy = apiResult.User?.GpsAccuracy ?? WT.Domain.Enums.GpsAccuracyLevel.Default,
                                                ShowRecordingWarning = apiResult.User?.ShowRecordingWarning ?? true,
                                                Bio = apiResult.User?.Bio
                                            };

                                            await localStorageService.SetItemAsync(LocalStorageKey, session);
                                        }
                                    }
                                }
                                catch { /* ignore local storage failures */ }

                                var principal = SetClaimsPrincipal(userClaims);
                                return await Task.FromResult(new AuthenticationState(principal));
                            }
                        }
                    }
                    catch (JSException jsEx)
                    {
                        // Fall back to HttpClient approach if JS fetch fails
                        Console.WriteLine($"⚠️ JS fetch refresh failed: {jsEx.Message}");
                    }
                }

                // Fallback to HttpClient POST (may not include cookies in some environments)
                var response = await _httpClient.PostAsync("api/account/identity/refresh-token", null);

                if (!response.IsSuccessStatusCode)
                {
                    // No valid refresh cookie or refresh failed
                    return await Task.FromResult(new AuthenticationState(anonymous));
                }

                var contentString = await response.Content.ReadAsStringAsync();
                var apiResult2 = JsonSerializer.Deserialize<APIResponseAuthentication>(contentString);
                if (apiResult2 is null || !apiResult2.Success || string.IsNullOrEmpty(apiResult2.JwtToken))
                {
                    return await Task.FromResult(new AuthenticationState(anonymous));
                }

                // Store access token in-memory and build claims
                try
                {
                    var handler2 = new JwtSecurityTokenHandler();
                    var jwt2 = handler2.ReadJwtToken(apiResult2.JwtToken);
                    _token_service?.SetAccessToken(apiResult2.JwtToken, jwt2.ValidTo);
                }
                catch (Exception ex)
                {
                    LogException.LogExceptions(ex);
                }

                var userClaims2 = DecryptToken(apiResult2.JwtToken!);
                if (userClaims2 is null || string.IsNullOrEmpty(userClaims2.Email) || userClaims2.Id == Guid.Empty)
                {
                    return await Task.FromResult(new AuthenticationState(anonymous));
                }

                // Persist small non-sensitive session DTO so UI can render immediately after reload
                try
                {
                    if (localStorageService is not null)
                    {
                        await localStorageService.SetItemAsync("HasSession", true);
                        if (!string.IsNullOrEmpty(LocalStorageKey))
                        {
                            var session = new AuthenticatedSessionDTO
                            {
                                TimeStamp = DateTime.UtcNow,
                                Id = userClaims2.Id,
                                FirstName = userClaims2.FirstName,
                                ProfileUsername = apiResult2.User?.ProfileUsername,
                                UserPhoto = apiResult2.User?.ProfilePicture,
                                Email = userClaims2.Email,
                                GpsAccuracy = apiResult2.User?.GpsAccuracy ?? WT.Domain.Enums.GpsAccuracyLevel.Default,
                                ShowRecordingWarning = apiResult2.User?.ShowRecordingWarning ?? true,
                                Bio = apiResult2.User?.Bio
                            };

                            await localStorageService.SetItemAsync(LocalStorageKey, session);
                        }
                    }
                }
                catch { /* ignore local storage failures */ }

                var principal2 = SetClaimsPrincipal(userClaims2);
                return await Task.FromResult(new AuthenticationState(principal2));
            }
            catch (InvalidOperationException)
            {
                // Ignore error during prerendering
                return await Task.FromResult(new AuthenticationState(anonymous));
            }
            catch (JsonException ex)
            {
                LogException.LogToConsole($"Authentication state provider: Failed to deserialize authentication data - {ex.Message}");
                // Clear corrupted data if any local storage key exists
                try
                {
                    if (localStorageService is not null && !string.IsNullOrEmpty(LocalStorageKey))
                    {
                        await localStorageService.RemoveItemAsync(LocalStorageKey);
                    }
                }
                catch { }

                return await Task.FromResult(new AuthenticationState(anonymous));
            }
            catch (Exception ex)
            {
                LogException.LogExceptions(ex);
                return await Task.FromResult(new AuthenticationState(anonymous));
            }
        }

        /// <summary>
        /// Decrypts and parses a JWT token to extract user claims.
        /// </summary>
        /// <param name="jwtToken">The JWT token string to decrypt and parse.</param>
        /// <returns>
        /// A <see cref="UserClaimsDTO"/> containing the extracted user information (ID, name, email, roles).
        /// Returns an empty <see cref="UserClaimsDTO"/> if the token is invalid or null if an exception occurs.
        /// </returns>
        /// <remarks>
        /// <para>
        /// This method uses <see cref="JwtSecurityTokenHandler"/> to read and parse the JWT token without
        /// validating the signature. This is acceptable for client-side claim extraction since the token
        /// was already validated by the API when it was issued.
        /// </para>
        /// <para>
        /// Extracted claims include:
        /// <list type="bullet">
        /// <item><description><see cref="ClaimTypes.NameIdentifier"/> - User's unique identifier (Guid)</description></item>
        /// <item><description><see cref="ClaimTypes.Name"/> - User's first name</description></item>
        /// <item><description><see cref="ClaimTypes.Email"/> - User's email address</description></item>
        /// <item><description><see cref="ClaimTypes.Role"/> - User's roles (multiple roles supported)</description></item>
        /// </list>
        /// </para>
        /// <para>
        /// <strong>Error Handling:</strong> Any exceptions during token parsing are logged using
        /// <see cref="LogException.LogExceptions"/> and the method returns null.
        /// </para>
        /// </remarks>
        public UserClaimsDTO DecryptToken(string jwtToken)
        {
            try
            {
                if (string.IsNullOrEmpty(jwtToken)) return new UserClaimsDTO();

                var handler = new JwtSecurityTokenHandler();
                var token = handler.ReadJwtToken(jwtToken);
                List<RoleDTO>? rolesCollection = new();

                var Id = token.Claims.FirstOrDefault(_ => _.Type == ClaimTypes.NameIdentifier);
                var firstName = token.Claims.FirstOrDefault(_ => _.Type == ClaimTypes.Name);
                var email = token.Claims.FirstOrDefault(_ => _.Type == ClaimTypes.Email);

                // Validate required claims exist
                if (Id is null || firstName is null || email is null)
                {
                    LogException.LogToConsole($"DecryptToken: Missing required claims in JWT token at {DateTime.UtcNow}");
                    return new UserClaimsDTO();
                }


                var _roles = token.Claims.Where(_ => _.Type == ClaimTypes.Role).ToList();
                if (_roles is not null && _roles.Any())
                {

                    if (_roles.Any())
                    {
                        var usrRoles = _roles
                            .Select(r => new RoleDTO()
                            {
                                RoleName = r.Value
                            });

                        rolesCollection = usrRoles.ToList();
                    }
                }

                return new UserClaimsDTO()
                {
                    Email = email!.Value,
                    FirstName = firstName!.Value,
                    Id = Guid.Parse(Id!.Value),
                    Roles = rolesCollection
                };
            }
            catch (FormatException ex)
            {
                // LOG: Invalid GUID format in token
                LogException.LogToConsole($"DecryptToken: Invalid user ID format in token - {ex.Message}");
                return new UserClaimsDTO();
            }
            catch (ArgumentException ex)
            {
                // LOG: Malformed JWT token
                LogException.LogToConsole($"DecryptToken: Malformed JWT token - {ex.Message}");
                return new UserClaimsDTO();
            }
            catch (Exception ex)
            {
                LogException.LogExceptions(ex);
                return null!;
            }
        }

        /// <summary>
        /// Updates the authentication state based on the API authentication response.
        /// This method handles both login (storing tokens) and logout (removing tokens) scenarios.
        /// </summary>
        /// <param name="apiResponseAuthentication">
        /// The authentication response from the API containing JWT token, refresh token, and user data.
        /// Pass null or a failed response to log out the user.
        /// </param>
        /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
        /// <remarks>
        /// <para>
        /// <strong>Login Flow:</strong> When a successful authentication response is provided:
        /// <list type="number">
        /// <item><description>Extract user claims from the JWT token</description></item>
        /// <item><description>Create <see cref="AuthenticatedLocalStorageDTO"/> with token and user data</description></item>
        /// <item><description>Serialize and store the data in browser local storage</description></item>
        /// <item><description>Create <see cref="ClaimsPrincipal"/> with user claims</description></item>
        /// <item><description>Notify the application of the authentication state change</description></item>
        /// </list>
        /// </para>
        /// <para>
        /// <strong>Logout Flow:</strong> When response is null or unsuccessful:
        /// <list type="number">
        /// <item><description>Remove authentication data from local storage</description></item>
        /// <item><description>Set claims principal to anonymous</description></item>
        /// <item><description>Notify the application of the authentication state change</description></item>
        /// </list>
        /// </para>
        /// <para>
        /// The <see cref="AuthenticationStateProvider.NotifyAuthenticationStateChanged"/> method triggers
        /// a re-render of all components that depend on authentication state (e.g., components using
        /// <c>[Authorize]</c> attribute or <c>&lt;AuthorizeView&gt;</c>).
        /// </para>
        /// <para>
        /// <strong>Dependency Validation:</strong> If local storage service or storage key is unavailable,
        /// the method safely returns an anonymous authentication state.
        /// </para>
        /// </remarks>
        public async Task UpdateAuthenticatedState(APIResponseAuthentication? apiResponseAuthentication)
        {
            Console.WriteLine("🔄 UpdateAuthenticatedState called");

            if (_token_service is null)
            {
                Console.WriteLine("❌ TokenService not available");
                NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(anonymous)));
                return;
            }

            var claimsPrincipal = new ClaimsPrincipal();

            if (apiResponseAuthentication is not null &&
                apiResponseAuthentication.Success &&
                !string.IsNullOrEmpty(apiResponseAuthentication.JwtToken))
            {
                Console.WriteLine("✅ Valid authentication response received");

                var getUserClaims = DecryptToken(apiResponseAuthentication.JwtToken!);

                if (getUserClaims is not null &&
                    getUserClaims.Id != Guid.Empty &&
                    !string.IsNullOrEmpty(getUserClaims.Email))
                {
                    try
                    {
                        var handler = new JwtSecurityTokenHandler();
                        var jwt = handler.ReadJwtToken(apiResponseAuthentication.JwtToken);
                        _token_service.SetAccessToken(apiResponseAuthentication.JwtToken, jwt.ValidTo);
                    }
                    catch (Exception ex)
                    {
                        LogException.LogExceptions(ex);
                    }

                    claimsPrincipal = SetClaimsPrincipal(getUserClaims);

                    // Persist a small non-sensitive flag indicating we have an authenticated session
                    try
                    {
                        if (localStorageService is not null)
                        {
                            await localStorageService.SetItemAsync("HasSession", true);

                            // Persist non-sensitive UI/session DTO only (do NOT store JWT or refresh token)
                            if (!string.IsNullOrEmpty(LocalStorageKey))
                            {
                                var session = new AuthenticatedSessionDTO
                                {
                                    TimeStamp = DateTime.UtcNow,
                                    Id = getUserClaims.Id,
                                    FirstName = getUserClaims.FirstName,
                                    ProfileUsername = apiResponseAuthentication.User?.ProfileUsername,
                                    UserPhoto = apiResponseAuthentication.User?.ProfilePicture,
                                    Email = getUserClaims.Email,
                                    GpsAccuracy = apiResponseAuthentication.User?.GpsAccuracy ?? WT.Domain.Enums.GpsAccuracyLevel.Default,
                                    ShowRecordingWarning = apiResponseAuthentication.User?.ShowRecordingWarning ?? true,
                                    Bio = apiResponseAuthentication.User?.Bio
                                };

                                await localStorageService.SetItemAsync(LocalStorageKey, session);
                            }
                        }
                    }
                    catch { /* ignore local storage write failures */ }
                }
                else
                {
                    Console.WriteLine("❌ Claims validation failed");
                }
            }
            else
            {
                Console.WriteLine("🚪 Logout scenario - clearing in-memory token");
                _token_service.Clear();
                claimsPrincipal = anonymous;

                // Clear session flag and stored auth from local storage
                try
                {
                    if (localStorageService is not null)
                    {
                        await localStorageService.RemoveItemAsync("HasSession");
                        if (!string.IsNullOrEmpty(LocalStorageKey))
                            await localStorageService.RemoveItemAsync(LocalStorageKey);
                    }
                }
                catch { /* ignore */ }
            }

            Console.WriteLine("📢 Notifying authentication state changed...");
            NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(claimsPrincipal)));
            Console.WriteLine("✅ Notification complete");
        }

        /// <summary>
        /// Creates a <see cref="ClaimsPrincipal"/> from the provided user claims.
        /// </summary>
        /// <param name="claims">The user claims extracted from the JWT token.</param>
        /// <returns>
        /// A <see cref="ClaimsPrincipal"/> containing the user's identity and claims.
        /// Returns an empty <see cref="ClaimsPrincipal"/> if claims are invalid or storage key is missing.
        /// </returns>
        /// <remarks>
        /// <para>
        /// This method constructs a <see cref="ClaimsIdentity"/> with the following claims:
        /// <list type="bullet">
        /// <item><description><see cref="ClaimTypes.NameIdentifier"/> - User's unique identifier</description></item>
        /// <item><description><see cref="ClaimTypes.Name"/> - User's first name</description></item>
        /// <item><description><see cref="ClaimTypes.Email"/> - User's email address</description></item>
        /// <item><description><see cref="ClaimTypes.Role"/> - User's roles (one claim per role)</description></item>
        /// </list>
        /// </para>
        /// <para>
        /// The authentication type for the <see cref="ClaimsIdentity"/> is set to the local storage key
        /// configured in application settings, marking the identity as authenticated.
        /// </para>
        /// <para>
        /// This claims principal is used by Blazor's authorization system to determine access to protected
        /// resources and components.
        /// </para>
        /// </remarks>
        private ClaimsPrincipal SetClaimsPrincipal(UserClaimsDTO claims)
        {
            Console.WriteLine($"🔧 SetClaimsPrincipal called for: {claims.Email}");

            if (claims.Email is null)
            {
                Console.WriteLine("❌ Email is null");
                return new ClaimsPrincipal();
            }

            var userClaims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, claims.Id.ToString()!),
                new Claim(ClaimTypes.Name, claims.FirstName!),
                new Claim(ClaimTypes.Email, claims.Email!),
            };

            if (claims.Roles is not null)
            {
                foreach (var role in claims.Roles)
                {
                    userClaims.Add(new Claim(ClaimTypes.Role, role.RoleName!));
                }
            }

            var identity = new ClaimsIdentity(userClaims, "Custom");
            var principal = new ClaimsPrincipal(identity);

            return principal;
        }
    }
}
