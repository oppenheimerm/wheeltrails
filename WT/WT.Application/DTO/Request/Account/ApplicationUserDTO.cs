
using WT.Application.DTO.Response;

namespace WT.Application.DTO.Request.Account
{
    /// <summary>
    /// Data Transfer Object for <see cref="WT.Domain.Entity.ApplicationUser"/> entity."/>
    /// </summary>
    public class ApplicationUserDTO
    {
        public Guid Id { get; set; }
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public string? UserPhoto { get; set; }

        public List<RoleDTO>? Roles { get; set; }

        public string? Bio { get; set; }
    }
}
