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

        Task<APIResponseViewAccountSettings?> GetNavbarUserInfoAsync(Guid userId);
    }
}