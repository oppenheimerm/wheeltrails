using Microsoft.AspNetCore.Identity;
using WT.Application.DTO.Request.Account;
using WT.Application.DTO.Response;

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
        
        // ✅ REMOVED: FindUserByIdAsync - Not needed for HTTP client
        // ✅ REMOVED: FindUserByUserName - Not needed for HTTP client
    }
}
