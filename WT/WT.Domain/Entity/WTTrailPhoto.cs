using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace WT.Domain.Entity
{
    /// <summary>
    /// Represents a photo uploaded for a trail.
    /// Stores the Firebase Storage URL and optional description.
    /// </summary>
    public class WTTrailPhoto
    {
        /// <summary>
        /// Unique identifier for the photo.
        /// </summary>
        [Key]
        public Guid Id { get; set; } = Guid.NewGuid(); // ✅ NOT nullable, auto-generated

        /// <summary>
        /// Firebase Storage URL for the photo.
        /// </summary>
        [Required]
        [MaxLength(512, ErrorMessage = "PhotoName has a maximum length of 512 characters.")] // ✅ Increased for full URLs
        public string? PhotoName { get; set; }

        /// <summary>
        /// Optional description or caption for the photo.
        /// </summary>
        [MaxLength(500, ErrorMessage = "Description has a maximum length of 500 characters.")]
        public string? Description { get; set; }

        /// <summary>
        /// When the photo was uploaded.
        /// </summary>
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow; // ✅ Use UtcNow, NOT Now

        /// <summary>
        /// Foreign Key to WTTrail (trail this photo belongs to).
        /// </summary>
        [Required]
        [ForeignKey(nameof(Trail))]
        public Guid TrailId { get; set; } // ✅ NOT nullable, matches navigation property name

        /// <summary>
        /// Navigation property to the trail this photo belongs to.
        /// </summary>
        public WTTrail? Trail { get; set; }
    }
}
