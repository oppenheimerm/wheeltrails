
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using WT.Application.DTO.Request.Account;
using WT.Domain.Entity;
using WT.Domain.Enums;
using WT.Domain.Geo;

namespace WT.Application.DTO.Response
{
    public class TrailDTO
    {
        public Guid Id { get; set; } = Guid.NewGuid();

        public string? Title { get; set; }
        public string? Description { get; set; }

        /// <summary>
        /// Profile of the user who created the trail.
        /// </summary>
        public ApplicationUserDTO? User { get; set; }

        /// <summary>
        /// Starting geographical coordinates of the trail.
        /// </summary>
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

        /// <summary>
        /// Length of the trail in meters.
        /// </summary>
        [Required]
        public double LengthMeters { get; set; }

        /// <summary>
        /// Elevation profile data points along the trail.
        /// </summary>
        public List<double> ElevationProfile { get; set; } = new();

        /// <summary>
        /// Represent points of interest (POIs) along the trail.
        /// </summary>
        public List<WTPointOfInterest> PointsOfInterest { get; set; } = new();

        public TrailDifficulty Difficulty { get; set; } = TrailDifficulty.Easy;

        public SurfaceType SurfaceTypes { get; set; } = SurfaceType.Paved;

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        public DateTime? UpdatedAt { get; set; }

        // ✅ Navigation properties (manage relationships via EF Core)
        // We will not populate these directly in the DTO,  On page load, we
        // will use computed properties instead.

        //public ICollection<WTTrailPhoto>? Images { get; set; }
        //public ICollection<Comment>? Comments { get; set; }
        //public ICollection<TrailLike>? Likes { get; set; }

        // ✅ Computed properties (read-only, not stored in database)
        /// <summary>
        /// Total number of likes for this trail.
        /// </summary>

        public int? LikeCount { get; set; }

        public double? AverageRating { get; set; }

        public int? RatingCount {get; set; }

        /// <summary>
        /// Number of comments on this trail.
        /// </summary>
        public int? CommentCount {get; set; }   

        /// <summary>
        /// Number of photos uploaded for this trail.
        /// </summary>
        public int? PhotoCount {get; set; }

        public bool TrailLocked { get;  }
    }
}
