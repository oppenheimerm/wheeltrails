using Blazored.LocalStorage;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.Configuration;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json;
using WT.Application.APIServiceLogs;
using WT.Application.DTO.Request.Account;
using WT.Application.DTO.Response;
using WT.Application.Services;

namespace WT.Application.Extensions
{
    /// <summary>
    /// Custom authentication state provider for Blazor WebAssembly that manages user authentication
    /// state using JWT tokens stored in browser local storage.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This provider extends <see cref="AuthenticationStateProvider"/> to provide JWT-based authentication
    /// for Blazor WebAssembly applications. It handles token storage, retrieval, validation, and
    /// claims extraction from JWT tokens.
    /// </para>
    /// <para>
    /// <strong>Key Responsibilities:</strong>
    /// <list type="bullet">
    /// <item><description>Retrieve and validate authentication state from local storage</description></item>
    /// <item><description>Decrypt JWT tokens to extract user claims and roles</description></item>
    /// <item><description>Manage authentication state changes and notify the application</description></item>
    /// <item><description>Handle token refresh and user logout operations</description></item>
    /// </list>
    /// </para>
    /// <para>
    /// <strong>⚠️ SECURITY NOTE:</strong> This implementation stores JWT tokens in browser local storage.
    /// See <see cref="AuthenticatedLocalStorageDTO"/> for security considerations and GitHub issue #6
    /// for planned security enhancements.
    /// </para>
    /// </remarks>
    public class CustomAuthenticationStateProvider : AuthenticationStateProvider
    {
        readonly ILocalStorageService? localStorageService;
        readonly IConfiguration? configuration;
        readonly string? LocalStorageKey;
        
        /// <summary>
        /// Represents an anonymous (unauthenticated) user with no claims.
        /// </summary>
        readonly ClaimsPrincipal anonymous = new(new ClaimsIdentity());
        
        /// <summary>
        /// Gets or sets the current authenticated user's data stored in local storage.
        /// Contains JWT token, refresh token, and user metadata.
        /// </summary>
        AuthenticatedLocalStorageDTO? AuthenticatedLocalStorageDTO { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="CustomAuthenticationStateProvider"/> class.
        /// </summary>
        /// <param name="_localStorageService">Service for interacting with browser local storage.</param>
        /// <param name="_configuration">Application configuration containing the local storage key.</param>
        /// <remarks>
        /// The local storage key is retrieved from configuration using the key "ApplicationSettings:LocalStorageKey".
        /// This key is used to store and retrieve authentication data in the browser.
        /// </remarks>
        public CustomAuthenticationStateProvider(ILocalStorageService _localStorageService, IConfiguration _configuration)
        {
            localStorageService = _localStorageService;
            configuration = _configuration;
            LocalStorageKey = configuration["ApplicationSettings:LocalStorageKey"]!;
        }

        /// <summary>
        /// Retrieves the current authentication state by reading and validating the stored JWT token.
        /// </summary>
        /// <returns>
        /// A <see cref="Task{AuthenticationState}"/> representing the current authentication state.
        /// Returns an anonymous state if no valid token is found or if validation fails.
        /// </returns>
        /// <remarks>
        /// <para>
        /// This method is called by the Blazor framework to determine the current user's authentication status.
        /// The authentication flow:
        /// <list type="number">
        /// <item><description>Check if dependencies (local storage service, configuration) are available</description></item>
        /// <item><description>Retrieve authentication data from local storage using the configured key</description></item>
        /// <item><description>Deserialize the stored JSON data into <see cref="AuthenticatedLocalStorageDTO"/></description></item>
        /// <item><description>Validate the JWT token and extract user claims</description></item>
        /// <item><description>Create and return a <see cref="ClaimsPrincipal"/> with the user's claims</description></item>
        /// </list>
        /// </para>
        /// <para>
        /// If any step fails or if no authentication data exists, an anonymous (unauthenticated) state is returned.
        /// </para>
        /// <para>
        /// <strong>Note:</strong> <see cref="InvalidOperationException"/> is caught and ignored to handle
        /// prerendering scenarios in Blazor Server components.
        /// </para>
        /// </remarks>
        public override async Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            try
            {
                // Add null checks for injected dependencies
                if (localStorageService is null || configuration is null)
                    return await Task.FromResult(new AuthenticationState(anonymous));
                
                if (string.IsNullOrEmpty(LocalStorageKey))
                    return await Task.FromResult(new AuthenticationState(anonymous));

                var authData = await localStorageService.GetItemAsStringAsync(LocalStorageKey);

                //  User is anonymous / not logged in or authenticated
                if (authData is null)
                    return await Task.FromResult(new AuthenticationState(anonymous));

                //  Not null so get claims
                AuthenticatedLocalStorageDTO = JsonSerializer.Deserialize<AuthenticatedLocalStorageDTO>(authData);

                if (AuthenticatedLocalStorageDTO is not null && AuthenticatedLocalStorageDTO.JWtToken is not null && AuthenticatedLocalStorageDTO.Id is not null)
                {
                    var getUserClaims = DecryptToken(AuthenticatedLocalStorageDTO.JWtToken);
                    if (getUserClaims is null || string.IsNullOrEmpty(getUserClaims.Email) || getUserClaims.Id == Guid.Empty)
                    {
                        return await Task.FromResult(new AuthenticationState(anonymous));
                    }

                    //  Create a claims principal
                    var claimsPrincipal = SetClaimsPrincipal(getUserClaims);
                    return await Task.FromResult(new AuthenticationState(claimsPrincipal));
                }
                else
                {
                    return await Task.FromResult(new AuthenticationState(anonymous));
                }
            }
            catch (InvalidOperationException)
            {
                // Ignore error during prerendering
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
                List<RoleDTO>? rolesCollection = [];

                var Id = token.Claims.FirstOrDefault(_ => _.Type == ClaimTypes.NameIdentifier);
                var firstName = token.Claims.FirstOrDefault(_ => _.Type == ClaimTypes.Name);
                var email = token.Claims.FirstOrDefault(_ => _.Type == ClaimTypes.Email);


                var _roles = token.Claims.Where(_ => _.Type == ClaimTypes.Role).ToList();
                if (_roles is not null)
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
            // Validate dependencies
            if (localStorageService is null || string.IsNullOrEmpty(LocalStorageKey))
            {
                NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(anonymous)));
                return;
            }

            var claimsPrincipal = new ClaimsPrincipal();
            if (apiResponseAuthentication is not null && apiResponseAuthentication.Success &&
                !string.IsNullOrEmpty(apiResponseAuthentication.JwtToken))
            {
                var getUserClaims = DecryptToken(apiResponseAuthentication.JwtToken!);
                if (getUserClaims.Id != Guid.Empty && !string.IsNullOrEmpty(getUserClaims.Email))
                {
                    AuthenticatedLocalStorageDTO = new AuthenticatedLocalStorageDTO()
                    {
                        JWtToken = apiResponseAuthentication.JwtToken,
                        RefreshToken = apiResponseAuthentication.RefreshToken,
                        TimeStamp = DateTime.UtcNow,
                        Id = apiResponseAuthentication!.User!.Id,
                        UserPhoto = apiResponseAuthentication.User.ProfilePicture,
                        FirstName = apiResponseAuthentication.User.FirstName,
                        Bio = apiResponseAuthentication.User.Bio
                    };

                    var jsonString = JsonSerializer.Serialize(AuthenticatedLocalStorageDTO);

                    claimsPrincipal = SetClaimsPrincipal(getUserClaims);
                    await localStorageService.SetItemAsStringAsync(LocalStorageKey, jsonString);
                }
            }
            else
            {
                await localStorageService.RemoveItemAsync(LocalStorageKey);
                claimsPrincipal = anonymous; //  Set to anonymous if no user is authenticated
            }
            
            //  Notify App to rerender
            NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(claimsPrincipal)));
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
            if (claims.Email is null || string.IsNullOrEmpty(LocalStorageKey))
                return new ClaimsPrincipal();

            var userClaims = new List<Claim> {
                new Claim(ClaimTypes.NameIdentifier, claims.Id.ToString()!),
                new Claim(ClaimTypes.Name, claims.FirstName!),
                new Claim(ClaimTypes.Email, claims.Email!),
            };

            if (claims.Roles is not null)
            {
                foreach (var role in claims.Roles)
                {
                    userClaims.Add(
                        new Claim(ClaimTypes.Role, role.RoleName!));
                }
            }

            return new ClaimsPrincipal(
                new ClaimsIdentity(userClaims, LocalStorageKey));
        }
    }
}
