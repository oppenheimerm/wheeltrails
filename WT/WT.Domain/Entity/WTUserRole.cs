
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Data;
using System.Security.Principal;

namespace WT.Domain.Entity
{
    internal class WTUserRole
    {
        [Key]
        public int? Id { get; set; }

        [Required]
        [ForeignKey(nameof(Role))]
        public string? RoleCode { get; set; }

        public WTRole? Role { get; set; }

        [Required]
        [ForeignKey(nameof(User))]
        public Guid? UserId { get; set; }

        public WTUser? User { get; set; }

        [Required]
        public DateTime? AddedDate { get; set; }

    }
}
