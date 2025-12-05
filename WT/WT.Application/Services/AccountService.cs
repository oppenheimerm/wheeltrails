
using WT.Application.DTO.Request.Account;
using WT.Application.DTO.Response;

namespace WT.Application.Services
{
    public class AccountService : IAccountService
    {
        public Task<BaseAPIResponseDTO> AddUserToRoleAsync(Guid userId, CreateRoleDTO model)
        {
            throw new NotImplementedException();
        }

        public Task<BaseAPIResponseDTO> CreateAdmin()
        {
            throw new NotImplementedException();
        }

        public Task<BaseAPIResponseDTO> CreateRoleASync(CreateRoleDTO model)
        {
            throw new NotImplementedException();
        }

        public Task<IEnumerable<RoleDTO>> GetRolesAsync()
        {
            throw new NotImplementedException();
        }

        public Task<APIResponseAuthentication> LoginAsync(LoginDTO model, string ipAddress)
        {
            throw new NotImplementedException();
        }

        public Task<APIResponseAuthentication> RefreshTokenAsync(string token, string ipAddress)
        {
            throw new NotImplementedException();
        }

        public Task<BaseAPIResponseDTO> RegisterAsync(RegisterDTO model)
        {
            throw new NotImplementedException();
        }
    }
}
