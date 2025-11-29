
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace WT.Domain.Entity
{
    /// <summary>
    /// Represents a role within the WT application.
    /// </summary>
    public class WTRole
    {
        public WTRole()
        {
            CreatedDate = DateTime.UtcNow;
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        [MaxLength(4, ErrorMessage = "Role code must be 4 characters long"), MinLength(4)]
        public string? RoleCode { get; set; }

        [Required]
        public string? RoleName { get; set; }

        [Required]
        [StringLength(50)]
        public string? Description { get; set; }

        public DateTime? CreatedDate { get; private set; }
    }
}
