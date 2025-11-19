
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace WT.Application.DTO.Request.Account
{
    public class CreateRoleDTO
    {
        [Required]
        [MaxLength(4, ErrorMessage = "Role code must be 4 characters long"), MinLength(4)]
        public string? RoleCode { get; set; }
        [Required]
        public string? RoleName { get; set; }
        [Required]
        [StringLength(50)]
        public string? Description { get; set; }
    }
}
