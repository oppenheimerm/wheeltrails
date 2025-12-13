using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace WT.Domain.Entity
{
    /// <summary>
    /// Represents a user comment on a trail.
    /// </summary>
    public class Comment
    {
        [Key]
        public int Id { get; set; } // ✅ NOT nullable - auto-incrementing PK

        [Required]
        [MaxLength(300, ErrorMessage = "Comments have a maximum length of 300 characters.")]
        public string? Content { get; set; }

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow; // ✅ NOT nullable

        /// <summary>
        /// Last time the comment was edited
        /// </summary>
        public DateTime? UpdatedAt { get; set; }

        // ✅ Foreign Key to ApplicationUser (who wrote the comment)
        [Required]
        [ForeignKey(nameof(User))]
        public Guid UserId { get; set; } // ✅ NOT nullable

        /// <summary>
        /// Navigation property to the user who created this comment
        /// </summary>
        public ApplicationUser? User { get; set; }

        // ✅ Foreign Key to WTTrail (trail being commented on)
        [Required]
        [ForeignKey(nameof(Trail))]
        public Guid TrailId { get; set; } // ✅ NOT nullable

        /// <summary>
        /// Navigation property to the trail this comment belongs to
        /// </summary>
        public WTTrail? Trail { get; set; }
    }
}
