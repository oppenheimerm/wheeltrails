using System.ComponentModel.DataAnnotations;
using WT.Domain.Enums;

namespace WT.Application.DTO.Request.Trail
{
    /// <summary>
    /// DTO for creating a new trail. Photos are uploaded separately.
    /// </summary>
    public class CreateTrailDTO
    {
        [Required]
        [MaxLength(150, ErrorMessage = "Title has a maximum length of 150 characters.")]
        public string? Title { get; set; }

        [MaxLength(600, ErrorMessage = "Description has a maximum length of 600 characters.")]
        public string? Description { get; set; }

        [Required]
        [Range(-90, 90, ErrorMessage = "Latitude must be between -90 and 90")]
        public double? Latitude { get; set; }

        [Required]
        [Range(-180, 180, ErrorMessage = "Longitude must be between -180 and 180")]
        public double? Longitude { get; set; }

        // ✅ NEW: Trail difficulty
        [Required]
        public TrailDifficulty Difficulty { get; set; } = TrailDifficulty.Easy;

        // ✅ NEW: Surface types (can be multiple via flags)
        [Required]
        public SurfaceType SurfaceTypes { get; set; } = SurfaceType.Paved;

        // ❌ NO UserId here - security risk!
    }
}
