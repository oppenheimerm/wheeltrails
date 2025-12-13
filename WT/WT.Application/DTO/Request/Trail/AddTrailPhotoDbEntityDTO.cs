using System.ComponentModel.DataAnnotations;

namespace WT.Application.DTO.Request.Trail
{
    /// <summary>
    /// DTO for adding a trail photo entity to the database.
    /// The photo file is stored in Firebase Storage (see FirebaseStorageService),
    /// and this DTO contains the URL and metadata for database persistence.
    /// </summary>
    public class AddTrailPhotoDbEntityDTO
    {
        /// <summary>
        /// Firebase Storage URL for the photo.
        /// </summary>
        [Required(ErrorMessage = "Photo URL is required")]
        [MaxLength(512, ErrorMessage = "Photo URL has a maximum length of 512 characters")]
        [Url(ErrorMessage = "PhotoName must be a valid URL")]
        public string? PhotoName { get; set; }

        /// <summary>
        /// Optional description or caption for the photo.
        /// </summary>
        [MaxLength(500, ErrorMessage = "Description has a maximum length of 500 characters")]
        public string? Description { get; set; }

        /// <summary>
        /// ID of the trail this photo belongs to.
        /// </summary>
        [Required(ErrorMessage = "Trail ID is required")]
        public Guid TrailId { get; set; }

        // ❌ REMOVED: [ForeignKey] attribute - DTOs don't use EF attributes
        // ❌ REMOVED: CreatedAt - should be set server-side, not from client
    }
}
