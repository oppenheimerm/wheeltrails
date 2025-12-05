
using WT.Application.DTO.Request.Account;
using WT.Application.DTO.Response;

namespace WT.Application.Services
{
    /// <summary>
    /// The IAccountService interface defines methods for user account management, including registration, login, 
    /// role management, and token refreshing.  It mirrors the 
    /// <see cref="WT.Application.Contracts.IWTAccount"/> IWTAccount interface.  This interface implementation is 
    /// used in the Application presentation layer to decouple the business logic from the underlying infrastructure.
    /// </summary>
    public interface IAccountService
    {
        Task<BaseAPIResponseDTO> CreateAdmin();

        Task<BaseAPIResponseDTO> RegisterAsync(RegisterDTO model);

        Task<APIResponseAuthentication> LoginAsync(LoginDTO model, string ipAddress);

        Task<BaseAPIResponseDTO> CreateRoleASync(CreateRoleDTO model);

        Task<IEnumerable<RoleDTO>> GetRolesAsync();

        Task<BaseAPIResponseDTO> AddUserToRoleAsync(Guid userId, CreateRoleDTO model);

        /// <summary>
        /// This method refreshes a JWT token using a valid refresh token.
        /// </summary>
        /// <param name="token"></param>
        /// <param name="ipAddress"></param>
        /// <returns></returns>
        Task<APIResponseAuthentication> RefreshTokenAsync(string token, string ipAddress);
    }
}
