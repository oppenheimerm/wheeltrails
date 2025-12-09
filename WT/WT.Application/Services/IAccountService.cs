using WT.Application.DTO.Request.Account;
using WT.Application.DTO.Response;

namespace WT.Application.Services
{
    /// <summary>
    /// Defines the contract for user account management operations in the WheelyTrails application.
    /// This interface serves as a unified abstraction layer implemented by both client-side and server-side components.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <strong>Dual Implementation Pattern:</strong>
    /// </para>
    /// <para>
    /// This interface is implemented by two distinct service types that serve different architectural layers:
    /// </para>
    /// <list type="bullet">
    /// <item>
    /// <description>
    /// <strong>Client-Side (WT.Application.Services.AccountService):</strong> 
    /// HTTP client wrapper used by Blazor WebAssembly (WT.Client) and Blazor Server (WT.Admin) applications.
    /// Makes HTTP calls to the API backend and handles JSON serialization/deserialization.
    /// No direct database access or business logic - pure transport layer.
    /// </description>
    /// </item>
    /// <item>
    /// <description>
    /// <strong>Server-Side (WT.Infrastructure.Repositories.WTAccount):</strong>
    /// Repository implementation used by the API backend.
    /// Provides direct database access via Entity Framework Core and ASP.NET Identity.
    /// Implements authentication business logic, token generation, and security features.
    /// </description>
    /// </item>
    /// </list>
    /// <para>
    /// <strong>Architecture Flow:</strong>
    /// </para>
    /// <code>
    /// Blazor Component → AccountService (HTTP) → API Controller → WTAccount (Repository) → Database
    /// </code>
    /// <para>
    /// <strong>Security Considerations:</strong>
    /// </para>
    /// <list type="bullet">
    /// <item><description>All authentication operations are logged for audit trails</description></item>
    /// <item><description>Passwords are never transmitted in plain text (HTTPS required)</description></item>
    /// <item><description>JWT tokens expire after 30 minutes</description></item>
    /// <item><description>Refresh tokens valid for 7 days with automatic rotation</description></item>
    /// <item><description>IP addresses tracked for security monitoring</description></item>
    /// <item><description>Token compromise detection through descendant revocation</description></item>
    /// </list>
    /// <para>
    /// <strong>Configuration Requirements:</strong>
    /// </para>
    /// <list type="bullet">
    /// <item><description><c>JwtSettings:Secret</c> - JWT signing key (min 32 characters)</description></item>
    /// <item><description><c>JwtSettings:Issuer</c> - Token issuer (e.g., https://localhost:5001)</description></item>
    /// <item><description><c>JwtSettings:Audience</c> - Token audience (e.g., https://localhost:5001)</description></item>
    /// <item><description><c>ConnectionStrings:BaseApiUrl</c> - API base URL (client-side only)</description></item>
    /// <item><description><c>ApplicationSettings:LocalStorageKey</c> - Browser storage key (client-side only)</description></item>
    /// <item><description><c>ApplicationSettings:RefreshTokenTTL</c> - Refresh token cleanup period (default: 90 days)</description></item>
    /// </list>
    /// </remarks>
    public interface IAccountService
    {
        /// <summary>
        /// Creates the initial administrator account with all administrative roles.
        /// </summary>
        /// <returns>
        /// A <see cref="BaseAPIResponseDTO"/> indicating success or failure of the admin creation operation.
        /// On success, the admin account is created with email verification bypassed.
        /// </returns>
        /// <remarks>
        /// <para>
        /// <strong>Purpose:</strong> Initialize the application with a default administrator account that has full system access.
        /// This method should typically be called once during initial application setup or deployment.
        /// </para>
        /// <para>
        /// <strong>Behavior:</strong>
        /// </para>
        /// <list type="number">
        /// <item><description>Reads admin credentials from configuration (User Secrets in development, Azure Key Vault in production)</description></item>
        /// <item><description>Creates system roles if they don't exist: ADMIN_DEVELOPER, ADMIN_EDITOR, USER, USER_EDITOR</description></item>
        /// <item><description>Registers the admin user with configured credentials</description></item>
        /// <item><description>Assigns all admin roles to the newly created account</description></item>
        /// <item><description>Logs the operation with timestamp for security audit</description></item>
        /// <item><description>Returns error if admin role already exists (idempotent operation)</description></item>
        /// </list>
        /// <para>
        /// <strong>Required Configuration:</strong>
        /// </para>
        /// <code>
        /// "AdminUser": {
        ///   "FirstName": "Admin",
        ///   "Email": "admin@wheeltrails.com",
        ///   "Password": "SecurePassword123!"
        /// }
        /// </code>
        /// <para>
        /// <strong>Client Implementation:</strong> Makes HTTP POST to <c>/api/account/create-admin</c>
        /// </para>
        /// <para>
        /// <strong>Server Implementation:</strong> Creates user via ASP.NET Identity's UserManager and RoleManager
        /// </para>
        /// <para>
        /// <strong>Security Note:</strong> Admin credentials should be stored in User Secrets during development
        /// and Azure Key Vault or similar secure storage in production. Never commit credentials to source control.
        /// </para>
        /// </remarks>
        /// <example>
        /// <code>
        /// // Blazor client usage
        /// var result = await accountService.CreateAdmin();
        /// if (result.Success)
        /// {
        ///     Console.WriteLine("Admin account created successfully");
        /// }
        /// </code>
        /// </example>
        Task<BaseAPIResponseDTO> CreateAdmin();

        /// <summary>
        /// Registers a new user account with email verification requirement.
        /// </summary>
        /// <param name="model">
        /// The registration data transfer object containing user information, credentials, and consent.
        /// All required fields must be populated and pass validation rules.
        /// </param>
        /// <returns>
        /// A <see cref="BaseAPIResponseDTO"/> indicating registration success or failure.
        /// On success, the <see cref="BaseAPIResponseDTO.Message"/> property contains the email verification token
        /// that should be sent to the user's email address for account activation.
        /// </returns>
        /// <remarks>
        /// <para>
        /// <strong>Registration Flow:</strong>
        /// </para>
        /// <list type="number">
        /// <item><description>Validates email uniqueness (returns error if email already exists)</description></item>
        /// <item><description>Validates all required fields and data annotations</description></item>
        /// <item><description>Validates terms and conditions acceptance</description></item>
        /// <item><description>Creates ApplicationUser with ASP.NET Identity password hashing</description></item>
        /// <item><description>Generates unique 128-character cryptographic verification token</description></item>
        /// <item><description>Stores user name in Title Case format, with spaces removed</description></item>
        /// <item><description>Assigns default USER role to the new account</description></item>
        /// <item><description>Logs registration with timestamp and outcome</description></item>
        /// </list>
        /// <para>
        /// <strong>Validation Rules (<see cref="RegisterDTO"/>):</strong>
        /// </para>
        /// <list type="bullet">
        /// <item><description><strong>FirstName:</strong> Required, 3-30 characters</description></item>
        /// <item><description><strong>Email:</strong> Required, valid email format, unique</description></item>
        /// <item><description><strong>Password:</strong> Required, minimum 7 characters</description></item>
        /// <item><description><strong>ConfirmPassword:</strong> Required, must match Password</description></item>
        /// <item><description><strong>AcceptTerms:</strong> Required, must be true</description></item>
        /// <item><description><strong>CountryCode:</strong> Optional, exactly 2 characters if provided</description></item>
        /// <item><description><strong>Bio:</strong> Optional, maximum 500 characters</description></item>
        /// </list>
        /// <para>
        /// <strong>Data Processing:</strong>
        /// </para>
        /// <list type="bullet">
        /// <item><description>First name: Converted to Title Case (e.g., "john doe" → "Johndoe")</description></item>
        /// <item><description>Email: Used as both Email and UserName in Identity</description></item>
        /// <item><description>Password: Automatically hashed by ASP.NET Identity (never stored in plain text)</description></item>
        /// <item><description>Verification Token: 128-character hex string generated via <c>RandomNumberGenerator</c></description></item>
        /// </list>
        /// <para>
        /// <strong>Post-Registration Requirements:</strong>
        /// </para>
        /// <para>
        /// The user MUST verify their email address before they can log in. The verification token returned
        /// in the response should be sent to the user's email with a verification link pointing to
        /// <see cref="VerifyEmailAsync"/>. Email verification is currently disabled for testing but should
        /// be enabled in production.
        /// </para>
        /// <para>
        /// <strong>Client Implementation:</strong> Makes HTTP POST to <c>/api/account/identity/create</c>
        /// </para>
        /// <para>
        /// <strong>Server Implementation:</strong> Creates user via ASP.NET Identity's <c>UserManager.CreateAsync()</c>
        /// </para>
        /// <para>
        /// <strong>Error Handling:</strong> Returns detailed validation errors from ASP.NET Identity
        /// (e.g., password requirements, duplicate email). All errors are logged but generic messages
        /// returned to prevent information disclosure attacks.
        /// </para>
        /// </remarks>
        /// <example>
        /// <code>
        /// var registerModel = new RegisterDTO
        /// {
        ///     FirstName = "John",
        ///     Email = "john.doe@example.com",
        ///     Password = "SecurePass123!",
        ///     ConfirmPassword = "SecurePass123!",
        ///     AcceptTerms = true,
        ///     Bio = "Outdoor enthusiast"
        /// };
        /// 
        /// var result = await accountService.RegisterAsync(registerModel);
        /// 
        /// if (result.Success)
        /// {
        ///     var verificationToken = result.Message;
        ///     // Send verification email to user with token
        ///     await emailService.SendVerificationEmail(registerModel.Email, verificationToken);
        /// }
        /// else
        /// {
        ///     // Display error message to user
        ///     Console.WriteLine($"Registration failed: {result.Message}");
        /// }
        /// </code>
        /// </example>
        Task<BaseAPIResponseDTO> RegisterAsync(RegisterDTO model);

        /// <summary>
        /// Initiates password reset process by sending reset token via email.
        /// </summary>
        /// <param name="model">The forgot password request containing user's email.</param>
        /// <returns>A response indicating the request was processed.</returns>
        Task<BaseAPIResponseDTO> ForgotPasswordAsync(ForgotPasswordDTO model);

        /// <summary>
        /// Resets user password using valid reset token.
        /// </summary>
        /// <param name="model">The password reset data containing email, token, and new password.</param>
        /// <returns>A response indicating whether password was reset successfully.</returns>
        Task<BaseAPIResponseDTO> ResetPasswordAsync(ResetPasswordDTO model);

        /// <summary>
        /// Authenticates a user and issues JWT bearer token with refresh token for session management.
        /// </summary>
        /// <param name="model">
        /// The login credentials containing email address and password.
        /// Both fields are required and validated.
        /// </param>
        /// <returns>
        /// An <see cref="APIResponseAuthentication"/> containing:
        /// <list type="bullet">
        /// <item><description><strong>JwtToken:</strong> JWT bearer token valid for 30 minutes</description></item>
        /// <item><description><strong>RefreshToken:</strong> Refresh token valid for 7 days</description></item>
        /// <item><description><strong>User:</strong> User details including ID, name, email, roles, and profile picture</description></item>
        /// <item><description><strong>Success:</strong> Boolean indicating authentication result</description></item>
        /// <item><description><strong>Message:</strong> Descriptive message (success or error reason)</description></item>
        /// </list>
        /// </returns>
        /// <remarks>
        /// <para>
        /// <strong>Authentication Flow:</strong>
        /// </para>
        /// <list type="number">
        /// <item><description>Validates email exists in database</description></item>
        /// <item><description>Checks email verification status (currently disabled for testing)</description></item>
        /// <item><description>Verifies password hash using ASP.NET Identity's <c>SignInManager</c></description></item>
        /// <item><description>Retrieves user roles from database</description></item>
        /// <item><description>Generates JWT token with user claims (ID, name, email, roles)</description></item>
        /// <item><description>Generates cryptographically secure refresh token</description></item>
        /// <item><description>Stores refresh token in database with IP address and expiration</description></item>
        /// <item><description>Removes old inactive refresh tokens (cleanup based on TTL)</description></item>
        /// <item><description>Logs successful/failed authentication attempts with timestamp</description></item>
        /// </list>
        /// <para>
        /// <strong>JWT Token Properties:</strong>
        /// </para>
        /// <list type="bullet">
        /// <item><description><strong>Algorithm:</strong> HS256 (HMAC-SHA256)</description></item>
        /// <item><description><strong>Expiration:</strong> 30 minutes from creation</description></item>
        /// <item><description><strong>Claims:</strong> NameIdentifier (user ID), Name (first name), Email, Role (all assigned roles)</description></item>
        /// <item><description><strong>Issuer/Audience:</strong> Configured in <c>JwtSettings</c></description></item>
        /// </list>
        /// <para>
        /// <strong>Refresh Token Properties:</strong>
        /// </para>
        /// <list type="bullet">
        /// <item><description><strong>Format:</strong> 64-byte random value, base64 encoded (88 characters)</description></item>
        /// <item><description><strong>Expiration:</strong> 7 days from creation</description></item>
        /// <item><description><strong>Storage:</strong> Stored in database with creation timestamp and client IP address</description></item>
        /// <item><description><strong>Security:</strong> One-time use with automatic rotation (see <see cref="RefreshTokenAsync"/>)</description></item>
        /// </list>
        /// <para>
        /// <strong>Client Implementation:</strong>
        /// </para>
        /// <para>
        /// Makes HTTP POST to <c>/api/account/identity/login</c>. The client should store the JWT token
        /// and refresh token securely (browser local storage for Blazor WASM, session storage for Blazor Server).
        /// The JWT should be included in subsequent API requests via the <c>Authorization: Bearer {token}</c> header.
        /// </para>
        /// <para>
        /// <strong>Server Implementation:</strong>
        /// </para>
        /// <para>
        /// The server-side implementation (<c>WTAccount.LoginWithIpAsync</c>) requires the client's IP address
        /// for security auditing and token tracking. The API controller extracts the IP address from
        /// <c>HttpContext</c> (checking <c>X-Forwarded-For</c> header for proxy scenarios) before calling
        /// the repository method.
        /// </para>
        /// <para>
        /// <strong>Security Features:</strong>
        /// </para>
        /// <list type="bullet">
        /// <item><description>Password verification via ASP.NET Identity (prevents timing attacks)</description></item>
        /// <item><description>Failed login attempts logged for security monitoring</description></item>
        /// <item><description>IP address tracking for all authentication operations</description></item>
        /// <item><description>Automatic cleanup of expired refresh tokens</description></item>
        /// <item><description>Generic error messages to prevent user enumeration</description></item>
        /// </list>
        /// <para>
        /// <strong>Error Scenarios:</strong>
        /// </para>
        /// <list type="bullet">
        /// <item><description><c>Success = false, Message = "Invalid email or password"</c> - Credentials incorrect or user doesn't exist</description></item>
        /// <item><description><c>Success = false, Message = "Please verify your account"</c> - Email not verified (when enabled)</description></item>
        /// <item><description><c>Success = false, Message = "Your account is locked"</c> - Account administratively disabled (when implemented)</description></item>
        /// <item><description><c>Success = false, Message = "An error occurred during login"</c> - Unexpected server error (logged internally)</description></item>
        /// </list>
        /// </remarks>
        /// <example>
        /// <code>
        /// // Blazor WASM client-side usage
        /// var loginModel = new LoginDTO
        /// {
        ///     Email = "user@wheeltrails.com",
        ///     Password = "UserPassword123!"
        /// };
        /// 
        /// var response = await accountService.LoginAsync(loginModel);
        /// 
        /// if (response.Success)
        /// {
        ///     // Update authentication state provider
        ///     var authStateProvider = (CustomAuthenticationStateProvider)AuthStateProvider;
        ///     await authStateProvider.UpdateAuthenticatedState(response);
        ///     
        ///     // Store tokens in local storage (handled by auth state provider)
        ///     // Navigate to home page
        ///     NavigationManager.NavigateTo("/", forceLoad: false);
        /// }
        /// else
        /// {
        ///     errorMessage = response.Message;
        /// }
        /// </code>
        /// </example>
        Task<APIResponseAuthentication> LoginAsync(LoginDTO model);

        /// <summary>
        /// Creates a new system role for authorization purposes.
        /// </summary>
        /// <param name="model">
        /// The role creation data containing role code (4 characters), name, and description.
        /// </param>
        /// <returns>
        /// A <see cref="BaseAPIResponseDTO"/> indicating whether the role was created successfully.
        /// </returns>
        /// <remarks>
        /// <para>
        /// <strong>Authorization:</strong> This operation requires administrative privileges
        /// (typically ADMIN_DEVELOPER or ADMIN_EDITOR role). The API endpoint should be protected
        /// with <c>[Authorize(Roles = "ADMIN_DEVELOPER,ADMIN_EDITOR")]</c> attribute.
        /// </para>
        /// <para>
        /// <strong>Validation Rules:</strong>
        /// </para>
        /// <list type="bullet">
        /// <item><description><strong>RoleCode:</strong> Required, exactly 4 characters</description></item>
        /// <item><description><strong>RoleName:</strong> Required</description></item>
        /// <item><description><strong>Description:</strong> Required, maximum 50 characters</description></item>
        /// </list>
        /// <para>
        /// <strong>Standard Roles:</strong> The application uses these predefined roles:
        /// </para>
        /// <list type="bullet">
        /// <item><description><strong>ADMIN_DEVELOPER:</strong> Full system access including development features</description></item>
        /// <item><description><strong>ADMIN_EDITOR:</strong> Content management and user moderation</description></item>
        /// <item><description><strong>USER_EDITOR:</strong> Trail content contribution and editing</description></item>
        /// <item><description><strong>USER:</strong> Basic authenticated user privileges</description></item>
        /// </list>
        /// <para>
        /// <strong>Note:</strong> This method is currently not implemented (<c>NotImplementedException</c>)
        /// in the server-side repository. Standard roles are created via <see cref="CreateAdmin"/> method.
        /// Implementation should be added if dynamic role creation is required.
        /// </para>
        /// <para>
        /// <strong>Client Implementation:</strong> Makes HTTP POST to <c>/api/account/create-role</c>
        /// </para>
        /// <para>
        /// <strong>Server Implementation:</strong> Should use ASP.NET Identity's <c>RoleManager.CreateAsync()</c>
        /// </para>
        /// </remarks>
        Task<BaseAPIResponseDTO> CreateRoleASync(CreateRoleDTO model);

        /// <summary>
        /// Retrieves all system roles available for user assignment.
        /// </summary>
        /// <returns>
        /// A collection of <see cref="RoleDTO"/> objects containing role names.
        /// Returns empty collection if no roles exist (should not occur after <see cref="CreateAdmin"/>).
        /// </returns>
        /// <remarks>
        /// <para>
        /// <strong>Purpose:</strong> Provides a list of available roles for administrative interfaces
        /// (e.g., user management screens, role assignment dropdowns).
        /// </para>
        /// <para>
        /// <strong>Authorization:</strong> May require administrative privileges depending on implementation.
        /// Consider restricting to authenticated users or specific admin roles.
        /// </para>
        /// <para>
        /// <strong>Note:</strong> This method is currently not implemented (<c>NotImplementedException</c>)
        /// in the server-side repository. Implementation should use <c>RoleManager.Roles</c> to retrieve
        /// all roles from the database.
        /// </para>
        /// <para>
        /// <strong>Client Implementation:</strong> Makes HTTP GET to <c>/api/account/roles</c>
        /// </para>
        /// <para>
        /// <strong>Server Implementation:</strong> Should query roles via <c>RoleManager.Roles.ToListAsync()</c>
        /// </para>
        /// </remarks>
        /// <example>
        /// <code>
        /// var roles = await accountService.GetRolesAsync();
        /// 
        /// foreach (var role in roles)
        /// {
        ///     Console.WriteLine($"Role: {role.RoleName}");
        /// }
        /// </code>
        /// </example>
        Task<IEnumerable<RoleDTO>> GetRolesAsync();

        /// <summary>
        /// Assigns a specified role to a user account.
        /// </summary>
        /// <param name="userId">
        /// The unique identifier (GUID) of the user to receive the role assignment.
        /// </param>
        /// <param name="model">
        /// The role assignment data containing the role name to assign.
        /// </param>
        /// <returns>
        /// A <see cref="BaseAPIResponseDTO"/> indicating whether the role was assigned successfully.
        /// Returns error if user not found, role doesn't exist, or user already has the role.
        /// </returns>
        /// <remarks>
        /// <para>
        /// <strong>Purpose:</strong> Allows administrators to grant additional privileges to users
        /// by assigning them to specific roles (e.g., promoting a user to trail editor).
        /// </para>
        /// <para>
        /// <strong>Authorization:</strong> This operation requires administrative privileges.
        /// The API endpoint should be protected with appropriate role-based authorization.
        /// </para>
        /// <para>
        /// <strong>Validation Flow:</strong>
        /// </para>
        /// <list type="number">
        /// <item><description>Validates that the user exists in the database (by GUID)</description></item>
        /// <item><description>Validates that the specified role exists</description></item>
        /// <item><description>Uses ASP.NET Identity's <c>UserManager.AddToRoleAsync()</c> to assign role</description></item>
        /// <item><description>Returns detailed error messages for troubleshooting</description></item>
        /// </list>
        /// <para>
        /// <strong>Client Implementation:</strong> Makes HTTP POST to <c>/api/account/{userId}/add-role</c>
        /// </para>
        /// <para>
        /// <strong>Server Implementation:</strong> Uses <c>UserManager</c> and <c>RoleManager</c> from ASP.NET Identity
        /// </para>
        /// <para>
        /// <strong>Common Use Cases:</strong>
        /// </para>
        /// <list type="bullet">
        /// <item><description>Promoting regular users to trail editors (USER → USER_EDITOR)</description></item>
        /// <item><description>Granting administrative access (USER → ADMIN_EDITOR)</description></item>
        /// <item><description>Assigning multiple roles to a single user for different permissions</description></item>
        /// </list>
        /// </remarks>
        /// <example>
        /// <code>
        /// var userId = Guid.Parse("550e8400-e29b-41d4-a716-446655440000");
        /// var roleModel = new CreateRoleDTO
        /// {
        ///     RoleName = Constants.Role.USER_EDITOR
        /// };
        /// 
        /// var result = await accountService.AddUserToRoleAsync(userId, roleModel);
        /// 
        /// if (result.Success)
        /// {
        ///     Console.WriteLine("User promoted to trail editor successfully");
        /// }
        /// </code>
        /// </example>
        Task<BaseAPIResponseDTO> AddUserToRoleAsync(Guid userId, CreateRoleDTO model);

        /// <summary>
        /// Refreshes an expired JWT token using a valid refresh token, implementing token rotation for enhanced security.
        /// </summary>
        /// <param name="token">
        /// The current refresh token (88-character base64 string) to validate and exchange for new tokens.
        /// </param>
        /// <returns>
        /// An <see cref="APIResponseAuthentication"/> containing new JWT token, rotated refresh token,
        /// and updated user details on success. Returns error response if token is invalid, expired, or revoked.
        /// </returns>
        /// <remarks>
        /// <para>
        /// <strong>Purpose:</strong> Enables seamless user session continuation without requiring re-authentication.
        /// When the JWT token expires (after 30 minutes), the client can use the refresh token (valid for 7 days)
        /// to obtain new tokens without prompting the user to log in again.
        /// </para>
        /// <para>
        /// <strong>Token Rotation Security Pattern:</strong>
        /// </para>
        /// <para>
        /// This implementation follows the refresh token rotation best practice where each refresh token can
        /// only be used once. When a refresh token is used, it is immediately revoked and replaced with a new
        /// token, creating a chain of tokens for security auditing and compromise detection.
        /// </para>
        /// <para>
        /// <strong>Refresh Flow:</strong>
        /// </para>
        /// <list type="number">
        /// <item><description>Validates refresh token exists in database and belongs to a user</description></item>
        /// <item><description>Checks if token has been revoked (indicates potential compromise)</description></item>
        /// <item><description>If revoked token is reused, revokes entire token family chain (security measure)</description></item>
        /// <item><description>Validates token is still active (not expired, not already used)</description></item>
        /// <item><description>Generates new JWT token with current user claims and roles</description></item>
        /// <item><description>Generates new refresh token (rotated token)</description></item>
        /// <item><description>Revokes old refresh token, linking it to new token (creates audit trail)</description></item>
        /// <item><description>Removes old inactive refresh tokens based on TTL (90 days default)</description></item>
        /// <item><description>Returns new tokens to client</description></item>
        /// </list>
        /// <para>
        /// <strong>Security Features:</strong>
        /// </para>
        /// <list type="bullet">
        /// <item><description><strong>Automatic Token Rotation:</strong> Each refresh operation generates new tokens</description></item>
        /// <item><description><strong>Compromise Detection:</strong> Reuse of revoked tokens triggers security measures</description></item>
        /// <item><description><strong>Token Family Chains:</strong> Linked tokens enable tracking and revocation of entire chains</description></item>
        /// <item><description><strong>IP Address Tracking:</strong> Server implementation logs IP for all refresh operations</description></item>
        /// <item><description><strong>Automatic Cleanup:</strong> Old tokens removed based on configurable TTL</description></item>
        /// </list>
        /// <para>
        /// <strong>Token States:</strong>
        /// </para>
        /// <list type="bullet">
        /// <item><description><strong>Active:</strong> Not expired, not revoked - can be used for refresh</description></item>
        /// <item><description><strong>Expired:</strong> Past 7-day expiration - cannot be used</description></item>
        /// <item><description><strong>Revoked:</strong> Explicitly revoked (used once or security measure) - cannot be used</description></item>
        /// <item><description><strong>Replaced:</strong> Used successfully and replaced with new token</description></item>
        /// </list>
        /// <para>
        /// <strong>Client Implementation:</strong>
        /// </para>
        /// <para>
        /// Makes HTTP POST to <c>/api/account/identity/refresh-token</c>. The client should:
        /// </para>
        /// <list type="number">
        /// <item><description>Detect when JWT is about to expire (check exp claim)</description></item>
        /// <item><description>Automatically call <c>RefreshTokenAsync</c> to get new tokens</description></item>
        /// <item><description>Update stored tokens in local storage</description></item>
        /// <item><description>Retry failed API requests with new JWT</description></item>
        /// <item><description>Force logout if refresh fails (token compromised or expired)</description></item>
        /// </list>
        /// <para>
        /// <strong>Server Implementation:</strong>
        /// </para>
        /// <para>
        /// The server-side implementation (<c>WTAccount.RefreshTokenWithIpAsync</c>) requires the client's
        /// IP address for security tracking. The API controller extracts this from <c>HttpContext</c>
        /// before calling the repository method.
        /// </para>
        /// <para>
        /// <strong>Compromise Detection Example:</strong>
        /// </para>
        /// <para>
        /// If an attacker steals a refresh token and uses it, a new token is generated. When the legitimate
        /// user later tries to use their original token (now revoked), the system detects reuse of a revoked
        /// token and immediately revokes the entire token chain, including the attacker's token. Both the
        /// user and attacker are forced to re-authenticate.
        /// </para>
        /// <para>
        /// <strong>Error Scenarios:</strong>
        /// </para>
        /// <list type="bullet">
        /// <item><description><c>Success = false, Message = "Invalid refresh token"</c> - Token not found in database</description></item>
        /// <item><description><c>Success = false, Message = "Invalid token"</c> - Token expired or already used</description></item>
        /// <item><description>Silent revocation - Reuse of revoked token triggers security measures without returning new tokens</description></item>
        /// </list>
        /// <para>
        /// <strong>Configuration:</strong>
        /// </para>
        /// <list type="bullet">
        /// <item><description><c>ApplicationSettings:RefreshTokenTTL</c> - Days to keep inactive tokens (default: 90)</description></item>
        /// </list>
        /// </remarks>
        /// <example>
        /// <code>
        /// // Automatic refresh in HTTP interceptor (Blazor WASM pattern)
        /// public class AuthenticationHeaderHandler : DelegatingHandler
        /// {
        ///     private readonly IAccountService _accountService;
        ///     private readonly ILocalStorageService _localStorage;
        ///     
        ///     protected override async Task&lt;HttpResponseMessage&gt; SendAsync(
        ///         HttpRequestMessage request, 
        ///         CancellationToken cancellationToken)
        ///     {
        ///         var response = await base.SendAsync(request, cancellationToken);
        ///         
        ///         // If unauthorized, try to refresh token
        ///         if (response.StatusCode == HttpStatusCode.Unauthorized)
        ///         {
        ///             var refreshToken = await _localStorage.GetItemAsync&lt;string&gt;("refreshToken");
        ///             
        ///             if (!string.IsNullOrEmpty(refreshToken))
        ///             {
        ///                 var refreshResult = await _accountService.RefreshTokenAsync(refreshToken);
        ///                 
        ///                 if (refreshResult.Success)
        ///                 {
        ///                     // Update stored tokens
        ///                     await _localStorage.SetItemAsync("jwtToken", refreshResult.JwtToken);
        ///                     await _localStorage.SetItemAsync("refreshToken", refreshResult.RefreshToken);
        ///                     
        ///                     // Retry original request with new token
        ///                     request.Headers.Authorization = 
        ///                         new AuthenticationHeaderValue("Bearer", refreshResult.JwtToken);
        ///                     response = await base.SendAsync(request, cancellationToken);
        ///                 }
        ///                 else
        ///                 {
        ///                     // Force logout if refresh fails
        ///                     await _localStorage.RemoveItemAsync("jwtToken");
        ///                     await _localStorage.RemoveItemAsync("refreshToken");
        ///                     // Navigate to login page
        ///                 }
        ///             }
        ///         }
        ///         
        ///         return response;
        ///     }
        /// }
        /// </code>
        /// </example>
        Task<APIResponseAuthentication> RefreshTokenAsync(string token);

        /// <summary>
        /// Verifies a user's email address using the verification token sent during registration.
        /// </summary>
        /// <param name="token">
        /// The 128-character hexadecimal verification token generated during user registration.
        /// This token is unique per user and should be sent via email after account creation.
        /// </param>
        /// <returns>
        /// A <see cref="BaseAPIResponseDTO"/> indicating whether email verification was successful.
        /// On success, the user's <c>IsVerified</c> flag is set to true, allowing them to log in.
        /// </returns>
        /// <remarks>
        /// <para>
        /// <strong>Purpose:</strong> Confirms that the user has access to the email address they registered with,
        /// preventing fake account creation and ensuring communication channel validity.
        /// </para>
        /// <para>
        /// <strong>Verification Flow:</strong>
        /// </para>
        /// <list type="number">
        /// <item><description>User registers account via <see cref="RegisterAsync"/></description></item>
        /// <item><description>System generates unique 128-character verification token</description></item>
        /// <item><description>Token is returned in registration response (should be sent via email)</description></item>
        /// <item><description>Email contains link: <c>https://wheeltrails.com/verify-email?token={token}</c></description></item>
        /// <item><description>User clicks link, which calls this method with the token</description></item>
        /// <item><description>System validates token exists and hasn't been used</description></item>
        /// <item><description>User's <c>IsVerified</c> flag set to true, <c>VerificationToken</c> cleared</description></item>
        /// <item><description>User can now log in via <see cref="LoginAsync"/></description></item>
        /// </list>
        /// <para>
        /// <strong>Current Status:</strong> Email verification is currently DISABLED in the login flow for testing
        /// purposes. The verification check is commented out in <c>WTAccount.LoginWithIpAsync</c>:
        /// </para>
        /// <code>
        /// // Disabled for testing
        /// // if (!user.IsVerified)
        /// //     return new APIResponseAuthentication(false, "Please verify your account");
        /// </code>
        /// <para>
        /// <strong>Production Deployment:</strong> Before deploying to production, you should:
        /// </para>
        /// <list type="number">
        /// <item><description>Enable the verification check in the login method</description></item>
        /// <item><description>Implement email sending service (e.g., SendGrid, AWS SES)</description></item>
        /// <item><description>Create email templates with verification link</description></item>
        /// <item><description>Implement token expiration (e.g., 24-48 hours)</description></item>
        /// <item><description>Add "Resend verification email" functionality</description></item>
        /// </list>
        /// <para>
        /// <strong>Security Considerations:</strong>
        /// </para>
        /// <list type="bullet">
        /// <item><description>Tokens are cryptographically secure (generated via <c>RandomNumberGenerator</c>)</description></item>
        /// <item><description>Tokens are unique and checked against database for collisions</description></item>
        /// <item><description>Tokens should expire after reasonable time period (not currently implemented)</description></item>
        /// <item><description>Failed verification attempts should be logged for security monitoring</description></item>
        /// </list>
        /// <para>
        /// <strong>Client Implementation:</strong> Makes HTTP POST to <c>/api/account/verify-email</c>
        /// </para>
        /// <para>
        /// <strong>Server Implementation:</strong> Queries user by verification token, updates <c>IsVerified</c> flag
        /// </para>
        /// <para>
        /// <strong>Error Scenarios:</strong>
        /// </para>
        /// <list type="bullet">
        /// <item><description><c>Success = false, Message = "Invalid verification token"</c> - Token not found or already used</description></item>
        /// <item><description><c>Success = false, Message = "Verification token expired"</c> - Token too old (when implemented)</description></item>
        /// <item><description><c>Success = false, Message = "Account already verified"</c> - User attempting to re-verify</description></item>
        /// </list>
        /// </remarks>
        /// <example>
        /// <code>
        /// // Verification page in Blazor
        /// @page "/verify-email"
        /// @inject IAccountService AccountService
        /// @inject NavigationManager Navigation
        /// 
        /// @code {
        ///     [SupplyParameterFromQuery]
        ///     public string? Token { get; set; }
        ///     
        ///     protected override async Task OnInitializedAsync()
        ///     {
        ///         if (!string.IsNullOrEmpty(Token))
        ///         {
        ///             var result = await AccountService.VerifyEmailAsync(Token);
        ///             
        ///             if (result.Success)
        ///             {
        ///                 // Show success message
        ///                 // Redirect to login page
        ///                 await Task.Delay(2000);
        ///                 Navigation.NavigateTo("/account/identity/login");
        ///             }
        ///             else
        ///             {
        ///                 // Show error message
        ///             }
        ///         }
        ///     }
        /// }
        /// </code>
        /// </example>
        Task<BaseAPIResponseDTO> VerifyEmailAsync(string token);
    }
}
