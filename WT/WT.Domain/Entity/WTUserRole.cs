
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace WT.Domain.Entity
{
    public class WTUserRole
    {
        [Key]
        public int? Id { get; set; }

        [Required]
        [ForeignKey(nameof(Role))]
        public Guid? RoleId { get; set; }

        public WTRole? Role { get; set; }

        [Required]
        [ForeignKey(nameof(User))]
        public Guid? UserId { get; set; }

        public ApplicationUser? User { get; set; }

        [Required]
        public DateTime? AddedDate { get; set; }

    }
}
