using System.ComponentModel.DataAnnotations;
using WT.Domain.Enums;
using WT.Domain.Geo;

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

        /// <summary>
        /// Starting geographical coordinates of the trail.
        /// </summary>
        [Required]
        public WTLatLng? Start { get; set; }

        /// <summary>
        /// Ending geographical coordinates of the trail.
        /// </summary>
        [Required]
        public WTLatLng? End { get; set; }

        /// <summary>
        /// Represent intermediate waypoints along the trail route.
        /// </summary>
        [Required]
        public List<WTLatLng> Waypoints { get; set; } = new();

        // ✅ NEW: Trail difficulty
        [Required]
        public TrailDifficulty Difficulty { get; set; } = TrailDifficulty.Easy;

        // ✅ NEW: Surface types (can be multiple via flags)
        [Required]
        public SurfaceType SurfaceTypes { get; set; } = SurfaceType.Paved;

        public List<WTPointOfInterest> PointsOfInterest { get; set; } = new();

        /// <summary>
        /// Length of the trail in meters.
        /// </summary>
        [Required]
        public double LengthMeters { get; set; }

        /// <summary>
        /// Elevation profile data points along the trail.
        /// </summary>
        public List<double> ElevationProfile { get; set; } = new();
    }
}
