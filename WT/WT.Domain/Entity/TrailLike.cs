using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace WT.Domain.Entity
{
    /// <summary>
    /// Represents a user's "like" on a trail, including optional rating.
    /// Junction table for Many-to-Many relationship between ApplicationUser and WTTrail.
    /// </summary>
    public class TrailLike
    {
        [Key]
        public int Id { get; set; }

        /// <summary>
        /// Foreign Key to ApplicationUser (who liked the trail)
        /// </summary>
        [Required]
        [ForeignKey(nameof(User))]
        public Guid UserId { get; set; }

        /// <summary>
        /// Navigation property to the user who liked this trail
        /// </summary>
        public ApplicationUser? User { get; set; }

        /// <summary>
        /// Foreign Key to WTTrail (trail that was liked)
        /// </summary>
        [Required]
        [ForeignKey(nameof(Trail))]
        public Guid TrailId { get; set; }

        /// <summary>
        /// Navigation property to the trail that was liked
        /// </summary>
        public WTTrail? Trail { get; set; }

        /// <summary>
        /// When the user liked this trail
        /// </summary>
        public DateTime LikedAt { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Optional rating (1-5 stars). Null if user liked without rating.
        /// </summary>
        [Range(1, 5, ErrorMessage = "Rating must be between 1 and 5")]
        public int? Rating { get; set; }
    }
}