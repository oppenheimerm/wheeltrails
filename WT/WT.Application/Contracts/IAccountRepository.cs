using WT.Application.Contracts;
using WT.Application.DTO.Request.Account;
using WT.Application.DTO.Response;
using WT.Domain.Entity;

namespace WT.Application.Contracts
{
    /// <summary>
    /// Server-side repository interface for direct database operations on user accounts.
    /// </summary>
    public interface IAccountRepository
    {
        Task<BaseAPIResponseDTO> CreateAdmin();
        Task<BaseAPIResponseDTO> RegisterAsync(RegisterDTO model);
        Task<BaseAPIResponseDTO> CreateRoleASync(CreateRoleDTO model);
        Task<IEnumerable<RoleDTO>> GetRolesAsync();
        Task<BaseAPIResponseDTO> AddUserToRoleAsync(Guid userId, CreateRoleDTO model);
        Task<BaseAPIResponseDTO> VerifyEmailAsync(string token);
        Task<BaseAPIResponseDTO> ForgotPasswordAsync(ForgotPasswordDTO model);
        Task<BaseAPIResponseDTO> ResetPasswordAsync(ResetPasswordDTO model);

        /// <summary>
        /// Password reset for an <see cref="ApplicationUser"/> who is already authenticated.  Front-end client
        /// must make user re-login after password change.
        /// </summary>
        /// <param name="model"></param>
        /// <param name="userId"></param>
        /// <param name="IpAddress"></param>
        /// <returns></returns>
        Task<BaseAPIResponseDTO> AuthenticatedResetPasswordAsync(AuthenticatedResetPasswordDTO model, string userId, string IpAddress);
        Task<BaseAPIResponseDTO> SoftDeleteUserAsync(Guid userId, string? reason = null);

        // Server-side methods with IP address parameters (internal)
        Task<APIResponseAuthentication> LoginWithIpAsync(LoginDTO model, string ipAddress);
        Task<APIResponseAuthentication> RefreshTokenWithIpAsync(string token, string ipAddress);

        // Direct database access methods
        Task<ApplicationUser?> FindUserByIdAsync(Guid id);
        Task<ApplicationUser?> FindUserByEmailAsync(string email);
        Task<ApplicationUser?> FindUserByProfileUsernameAsync(string profileUsername);

        /// <summary>
        /// Method to get a public user profile by profile username.  Only public info is returned.
        /// We also handle cancellation tokens to abort processing if client disconnects.
        /// </summary>
        /// <param name="profileUsername"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        Task<APIResponsePublicViewProfile?> GetUserProfileByUsernameAsync(string profileUsername, CancellationToken cancellationToken);
        Task<bool> IsProfileUsernameAvailableAsync(string profileUsername);

        // JWT token generation
        Task<string?> GenerateToken(ApplicationUser user);

        // ✅ NEW: Get account settings for authenticated user
        Task<APIResponseViewAccountSettings> GetAccountSettingsAsync(string userId);

        /// <summary>
        /// Method to update the profile picture URL of a <see cref="ApplicationUser"/>.
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="profilePhotoUrl"></param>
        /// <returns></returns>
        Task<APIResponseUploadPhoto> UpdateProfilePictureUrlAsync(Guid userId, string profilePhotoUrl);

        /// <summary>
        /// Updates user account settings with robust validation and error handling.
        /// </summary>
        /// <param name="userId">The unique identifier (GUID) of the user whose settings should be updated.</param>
        /// <param name="model">
        /// The settings update request containing:
        /// <list type="bullet">
        /// <item><description>FirstName: Required, max 50 characters</description></item>
        /// <item><description>Bio: Optional, max 500 characters</description></item>
        /// <item><description>CountryCode: Optional, exactly 2 characters</description></item>
        /// <item><description>GpsAccuracy: Required, must be a valid GpsAccuracyLevel enum value</description></item>
        /// </list>
        /// </param>
        /// <returns>
        /// An <see cref="APIResponseUpdateUserSetting"/> containing:
        /// <list type="bullet">
        /// <item><description>Success: Boolean indicating if the update succeeded</description></item>
        /// <item><description>Message: User-friendly status or error message</description></item>
        /// <item><description>UpdatedSettings: The updated settings values if successful</description></item>
        /// </list>
        /// </returns>
        /// <remarks>
        /// <para><strong>Update Process:</strong></para>
        /// <list type="number">
        /// <item><description>Validates the input model is not null</description></item>
        /// <item><description>Finds the user by ID and checks if account exists</description></item>
        /// <item><description>Verifies the account is not soft-deleted (IsDeleted flag)</description></item>
        /// <item><description>Applies settings update via <see cref="ApplySettingsUpdate"/> helper with validation</description></item>
        /// <item><description>Persists changes to database via ASP.NET Identity's UserManager</description></item>
        /// <item><description>Returns updated settings in response DTO</description></item>
        /// <item><description>Logs all operations for audit trail</description></item>
        /// </list>
        /// 
        /// <para><strong>Validation Rules (via ApplySettingsUpdate helper):</strong></para>
        /// <list type="bullet">
        /// <item><description><strong>FirstName:</strong> Required, 2-50 characters, converted to Title Case with spaces removed</description></item>
        /// <item><description><strong>Bio:</strong> Optional, max 500 characters, trimmed, set to null if empty</description></item>
        /// <item><description><strong>CountryCode:</strong> Optional, exactly 2 characters if provided, converted to uppercase</description></item>
        /// <item><description><strong>GpsAccuracy:</strong> Must be a valid <see cref="GpsAccuracyLevel"/> enum value (Default or High)</description></item>
        /// </list>
        /// 
        /// <para><strong>Security & Authorization:</strong></para>
        /// <list type="bullet">
        /// <item><description>Should be called from an authorized API endpoint with authenticated user</description></item>
        /// <item><description>Validates user ownership via userId parameter (from JWT claims)</description></item>
        /// <item><description>Prevents updates to soft-deleted accounts</description></item>
        /// <item><description>All operations are logged for security audit trail</description></item>
        /// </list>
        /// 
        /// <para><strong>Error Handling:</strong></para>
        /// <list type="bullet">
        /// <item><description>Returns user-friendly error messages (no sensitive data)</description></item>
        /// <item><description>Logs detailed errors to file for debugging</description></item>
        /// <item><description>Handles null model, missing user, deleted accounts, validation failures</description></item>
        /// <item><description>Catches and logs unexpected exceptions</description></item>
        /// </list>
        /// 
        /// <para><strong>Database Impact:</strong></para>
        /// <para>
        /// Updates the following <see cref="ApplicationUser"/> properties in the database:
        /// </para>
        /// <list type="bullet">
        /// <item><description><c>FirstName</c>: User's display name in Title Case</description></item>
        /// <item><description><c>Bio</c>: User's biographical information</description></item>
        /// <item><description><c>CountryCode</c>: ISO 3166-1 alpha-2 country code (e.g., "US", "GB")</description></item>
        /// <item><description><c>CreateTrailGpsAccuracy</c>: GPS accuracy preference for trail recording</description></item>
        /// </list>
        /// 
        /// <para><strong>Usage Example (from API Controller):</strong></para>
        /// <code>
        /// [Authorize(Roles = "USER")]
        /// [HttpPut("settings")]
        /// public async Task&lt;IActionResult&gt; UpdateSettings([FromBody] UpdateSettingsRequest model)
        /// {
        ///     var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        ///     if (!Guid.TryParse(userId, out var userGuid))
        ///         return BadRequest("Invalid user identifier");
        ///     
        ///     var result = await _accountRepository.UpdateUserSettingAsync(userGuid, model);
        ///     return result.Success ? Ok(result) : BadRequest(result);
        /// }
        /// </code>
        /// 
        /// <para><strong>Logging:</strong></para>
        /// <para>All operations are logged with timestamps to <c>LogException.LogToFile()</c>:</para>
        /// <list type="bullet">
        /// <item><description>Invalid model or user ID</description></item>
        /// <item><description>User not found or deleted</description></item>
        /// <item><description>Validation failures with error details</description></item>
        /// <item><description>Successful updates with user ID</description></item>
        /// <item><description>Database update failures with Identity errors</description></item>
        /// <item><description>Unexpected exceptions with full stack trace</description></item>
        /// </list>
        /// 
        /// <para><strong>Related Methods:</strong></para>
        /// <list type="bullet">
        /// <item><description><see cref="ApplySettingsUpdate"/>: Helper method that performs validation and applies changes</description></item>
        /// <item><description><see cref="GetAccountSettingsAsync"/>: Retrieves current user settings</description></item>
        /// <item><description><see cref="FindUserByIdAsync"/>: Finds user by GUID</description></item>
        /// </list>
        /// 
        /// <para><strong>Thread Safety:</strong></para>
        /// <para>
        /// This method uses ASP.NET Identity's <c>UserManager</c> which is scoped per request.
        /// Safe for concurrent requests from different users, but should not be called
        /// concurrently for the same user to avoid race conditions.
        /// </para>
        /// </remarks>
        /// <exception cref="Exception">
        /// Catches and logs all exceptions, returning a generic error message to prevent
        /// information disclosure. Detailed errors are logged to file for troubleshooting.
        /// </exception>
        /// <seealso cref="UpdateSettingsRequest"/>
        /// <seealso cref="APIResponseUpdateUserSetting"/>
        /// <seealso cref="UpdateSettingsResonseDTO"/>
        /// <seealso cref="ApplySettingsUpdate"/>
        /// <seealso cref="ApplicationUser"/>
        /// <seealso cref="GpsAccuracyLevel"/>
        Task<APIResponseUpdateUserSetting> UpdateUserSettingAsync(Guid userId, UpdateSettingsRequest model);

        Task<APIResponseViewAccountSettings?> GetNavbarUserInfoAsync(Guid userId);
    }
}