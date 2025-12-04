using WT.Application.DTO.Request.Account;
using WT.Application.DTO.Response;

namespace WT.Application.Contracts
{
    public interface IWTAccount
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
