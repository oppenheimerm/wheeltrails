using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Identity;
using WT.Application.DTO.Request.Account;
using WT.Application.DTO.Response;
using WT.Domain.Entity;

namespace WT.Application.Services
{
    /// <summary>
    /// Client-side service interface for account operations via HTTP.
    /// Implemented by AccountService in WT.Application (used by Blazor).
    /// </summary>
    public interface IAccountService
    {
        Task<BaseAPIResponseDTO> CreateAdmin();
        Task<BaseAPIResponseDTO> RegisterAsync(RegisterDTO model);
        Task<BaseAPIResponseDTO> ForgotPasswordAsync(ForgotPasswordDTO model);
        Task<BaseAPIResponseDTO> ResetPasswordAsync(ResetPasswordDTO model);
        Task<APIResponseAuthentication> LoginAsync(LoginDTO model);
        Task<BaseAPIResponseDTO> CreateRoleASync(CreateRoleDTO model);
        Task<IEnumerable<RoleDTO>> GetRolesAsync();
        Task<BaseAPIResponseDTO> AddUserToRoleAsync(Guid userId, CreateRoleDTO model);
        Task<APIResponseAuthentication> RefreshTokenAsync(string token);
        Task<BaseAPIResponseDTO> VerifyEmailAsync(string token);
        
        // ✅ ProfileUsername methods
        Task<bool> IsProfileUsernameAvailableAsync(string profileUsername);
        Task<ApplicationUserDTO?> FindUserByProfileUsernameAsync(string profileUsername);
        
        // ✅ Combined validation (availability + profanity check)
        Task<UsernameValidationResultDTO> ValidateProfileUsernameAsync(string profileUsername);
        
        // ✅ NEW: Get account settings for authenticated user (client-side calls API)
        Task<APIResponseViewAccountSettings> GetAccountSettingsAsync();
    }

    public class UsernameValidationResult
    {
        public bool IsValid { get; set; }
        public bool IsAvailable { get; set; }
        public string? Message { get; set; }
    }
}
