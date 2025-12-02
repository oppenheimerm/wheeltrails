using WT.Application.DTO.Request.Account;
using WT.Application.DTO.Response;

namespace WT.Application.Contracts
{
    public interface IWTAccount
    {
        Task CreateAdmin();

        Task<BaseAPIResponseDTO> RegisterAsync(RegisterDTO model);

        Task<APIResponseAuthentication> LoginAsync(LoginDTO model, string ipAddress);

        Task<BaseAPIResponseDTO> CreateRoleASync(CreateRoleDTO model);

        Task<IEnumerable<RoleDTO>> GetRolesAsync();

        Task<BaseAPIResponseDTO> AddUserToRoleAsync(Guid userId, CreateRoleDTO model);
    }
}
