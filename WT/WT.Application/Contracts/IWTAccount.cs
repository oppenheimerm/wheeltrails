using WT.Application.DTO.Request.Account;
using WT.Application.DTO.Response;

namespace WT.Application.Contracts
{
    /// <summary>
    /// Defines the contract for user account management operations including authentication,
    /// registration, role management, and token refresh functionality.
    /// </summary>
    /// <remarks>
    /// This interface provides the core account management capabilities for the WheelyTrails application,
    /// supporting JWT-based authentication with refresh tokens, role-based authorization, and user lifecycle management.
    /// Implementations should handle all business logic related to user accounts while maintaining security best practices.
    /// </remarks>
    public interface IWTAccount
    {
        /// <summary>
        /// Creates the default administrator account with predefined admin roles.
        /// </summary>
        /// <returns>
        /// A task representing the asynchronous operation, containing a <see cref="BaseAPIResponseDTO"/>
        /// indicating whether the admin account was created successfully.
        /// </returns>
        /// <remarks>
        /// This method should be called during application initialization to ensure at least one administrator exists.
        /// The admin credentials are read from application configuration (User Secrets in development).
        /// Creates the following roles if they don't exist: ADMIN_DEVELOPER, ADMIN_EDITOR, USER, USER_EDITOR.
        /// If an admin account already exists, this method should handle it gracefully.
        /// </remarks>
        Task<BaseAPIResponseDTO> CreateAdmin();

        /// <summary>
        /// Registers a new user account in the system.
        /// </summary>
        /// <param name="model">
        /// The registration data including user details, password, and optional role assignments.
        /// </param>
        /// <returns>
        /// A task representing the asynchronous operation, containing a <see cref="BaseAPIResponseDTO"/>
        /// with the registration result. On success, the message contains the verification token.
        /// </returns>
        /// <remarks>
        /// <para>This method performs the following operations:</para>
        /// <list type="bullet">
        /// <item><description>Validates the registration data (email uniqueness, password strength, required fields)</description></item>
        /// <item><description>Creates a new <see cref="WT.Domain.Entity.ApplicationUser"/> with hashed password</description></item>
        /// <item><description>Generates a unique verification token for email confirmation</description></item>
        /// <item><description>Assigns the USER role by default</description></item>
        /// <item><description>Stores user information in Title Case format</description></item>
        /// <item><description>Logs the registration attempt for audit purposes</description></item>
        /// </list>
        /// <para>The user must verify their email before they can log in.</para>
        /// </remarks>
        Task<BaseAPIResponseDTO> RegisterAsync(RegisterDTO model);

        /// <summary>
        /// Authenticates a user and issues JWT and refresh tokens upon successful login.
        /// </summary>
        /// <param name="model">
        /// The login credentials containing email and password.
        /// </param>
        /// <param name="ipAddress">
        /// The IP address of the client making the login request, used for security audit trails.
        /// </param>
        /// <returns>
        /// A task representing the asynchronous operation, containing an <see cref="APIResponseAuthentication"/>
        /// with JWT token (30-minute expiry), refresh token (7-day expiry), and user details on success.
        /// </returns>
        /// <remarks>
        /// <para>Authentication process:</para>
        /// <list type="number">
        /// <item><description>Validates email and password against stored credentials</description></item>
        /// <item><description>Checks if the user's email has been verified</description></item>
        /// <item><description>Retrieves user roles and includes them in JWT claims</description></item>
        /// <item><description>Generates a new JWT token with user claims</description></item>
        /// <item><description>Creates a refresh token for token renewal without re-authentication</description></item>
        /// <item><description>Cleans up expired refresh tokens based on configured TTL</description></item>
        /// <item><description>Logs the login attempt with timestamp and IP address</description></item>
        /// </list>
        /// <para>Failed login attempts are logged for security monitoring.</para>
        /// </remarks>
        Task<APIResponseAuthentication> LoginAsync(LoginDTO model, string ipAddress);

        /// <summary>
        /// Creates a new role in the system.
        /// </summary>
        /// <param name="model">
        /// The role data including role code, name, and description.
        /// </param>
        /// <returns>
        /// A task representing the asynchronous operation, containing a <see cref="BaseAPIResponseDTO"/>
        /// indicating whether the role was created successfully.
        /// </returns>
        /// <remarks>
        /// Role codes must be exactly 4 characters long and role names must be unique.
        /// This operation requires administrative privileges.
        /// </remarks>
        Task<BaseAPIResponseDTO> CreateRoleASync(CreateRoleDTO model);

        /// <summary>
        /// Retrieves all available roles in the system.
        /// </summary>
        /// <returns>
        /// A task representing the asynchronous operation, containing a collection of <see cref="RoleDTO"/>
        /// representing all system roles.
        /// </returns>
        /// <remarks>
        /// Standard system roles include:
        /// <list type="bullet">
        /// <item><description><c>ADMIN_DEVELOPER</c>: Full system access and development capabilities</description></item>
        /// <item><description><c>ADMIN_EDITOR</c>: Content management and user moderation</description></item>
        /// <item><description><c>USER_EDITOR</c>: Trail editing and content contribution</description></item>
        /// <item><description><c>USER</c>: Basic authenticated user privileges</description></item>
        /// </list>
        /// </remarks>
        Task<IEnumerable<RoleDTO>> GetRolesAsync();

        /// <summary>
        /// Assigns a role to an existing user account.
        /// </summary>
        /// <param name="userId">
        /// The unique identifier of the user to receive the role.
        /// </param>
        /// <param name="model">
        /// The role assignment data containing the role name to assign.
        /// </param>
        /// <returns>
        /// A task representing the asynchronous operation, containing a <see cref="BaseAPIResponseDTO"/>
        /// indicating whether the role was assigned successfully.
        /// </returns>
        /// <remarks>
        /// <para>This method performs validation to ensure:</para>
        /// <list type="bullet">
        /// <item><description>The user exists in the system</description></item>
        /// <item><description>The role exists and is valid</description></item>
        /// <item><description>The user doesn't already have the role</description></item>
        /// </list>
        /// <para>This operation requires administrative privileges and is logged for audit purposes.</para>
        /// </remarks>
        Task<BaseAPIResponseDTO> AddUserToRoleAsync(Guid userId, CreateRoleDTO model);

        /// <summary>
        /// Refreshes an expired JWT token using a valid refresh token, implementing token rotation for enhanced security.
        /// </summary>
        /// <param name="token">
        /// The current refresh token to validate and exchange for new tokens.
        /// </param>
        /// <param name="ipAddress">
        /// The IP address of the client making the refresh request, used for security audit trails.
        /// </param>
        /// <returns>
        /// A task representing the asynchronous operation, containing an <see cref="APIResponseAuthentication"/>
        /// with a new JWT token, rotated refresh token, and updated user details on success.
        /// </returns>
        /// <remarks>
        /// <para>Token refresh process:</para>
        /// <list type="number">
        /// <item><description>Validates the refresh token exists and belongs to a valid user</description></item>
        /// <item><description>Checks if the token is active (not expired or revoked)</description></item>
        /// <item><description>Detects and handles attempted reuse of revoked tokens (security threat)</description></item>
        /// <item><description>Generates a new JWT token with current user claims and roles</description></item>
        /// <item><description>Creates a new refresh token and revokes the old one (token rotation)</description></item>
        /// <item><description>Cleans up expired refresh tokens based on configured TTL (default 90 days)</description></item>
        /// <item><description>Logs the refresh operation for security monitoring</description></item>
        /// </list>
        /// <para>
        /// <strong>Security Features:</strong>
        /// Implements automatic detection of compromised tokens. If a revoked token is reused,
        /// all descendant tokens in the chain are automatically revoked to prevent unauthorized access.
        /// </para>
        /// <para>Refresh tokens are valid for 7 days, while JWT tokens expire after 30 minutes.</para>
        /// </remarks>
        Task<APIResponseAuthentication> RefreshTokenAsync(string token, string ipAddress);
    }
}
