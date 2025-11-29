
namespace WT.Application.DTO.Response
{
    public class UserClaimsDTO
    {
        public Guid? Id { get; set; }
        public string? FirstName { get; set; }
        public string? Email { get; set; }
        public List<RoleDTO>? Roles { get; set; }
    }
}
