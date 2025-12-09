using System.ComponentModel.DataAnnotations;
using WT.Application.DTO.Response;

namespace WT.Application.DTO.Request.Account
{
    /// <summary>
    /// Admin-only user creation with role assignment
    /// </summary>
    public class AdminCreateUserDTO : RegisterDTO
    {
        /// <summary>
        /// Roles to assign - only accessible by administrators
        /// </summary>
        public List<RoleDTO>? Roles { get; set; }
    }
}