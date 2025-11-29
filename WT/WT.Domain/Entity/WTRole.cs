using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;

namespace WT.Domain.Entity
{
    /// <summary>
    /// WTRole inherits from <see cref="IdentityRole"/>: This gives you all the built-in Identity functionality 
    /// (Id, Name, NormalizedName, ConcurrencyStamp) while allowing the user of custom properties like RoleCode, 
    /// Description, and CreatedDate.
    /// </summary>
    public class WTRole : IdentityRole<Guid>
    {
        public WTRole()
        {
            CreatedDate = DateTime.UtcNow;
        }

        public WTRole(string roleName) : base(roleName)
        {
            CreatedDate = DateTime.UtcNow;
        }

        [Required]
        [MaxLength(4, ErrorMessage = "Role code must be 4 characters long"), MinLength(4)]
        public string? RoleCode { get; set; }

        [Required]
        public string? RoleName { get; set; }

        [StringLength(50)]
        public string? Description { get; set; }

        public DateTime? CreatedDate { get; set; }
    }
}
