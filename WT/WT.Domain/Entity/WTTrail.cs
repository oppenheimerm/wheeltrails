using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using WT.Domain.Enums;
using WT.Domain.Geo;

namespace WT.Domain.Entity
{
    public class WTTrail
    {
        [Key]
        public Guid Id { get; set; } = Guid.NewGuid();

        [Required]
        [MaxLength(150, ErrorMessage = "Title has a maximum length of 150 characters.")]
        public string? Title { get; set; }

        [MaxLength(600, ErrorMessage = "Description has a maximum length of 600 characters.")]
        public string? Description { get; set; }

        [Required]
        [ForeignKey(nameof(User))]
        public Guid UserId { get; set; }

        public ApplicationUser? User { get; set; }

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



        [Required]
        public TrailDifficulty Difficulty { get; set; } = TrailDifficulty.Easy;

        [Required]
        public SurfaceType SurfaceTypes { get; set; } = SurfaceType.Paved;

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        public DateTime? UpdatedAt { get; set; }

        // ✅ Navigation properties (manage relationships via EF Core)
        public ICollection<WTTrailPhoto>? Images { get; set; }
        public ICollection<Comment>? Comments { get; set; }
        public ICollection<TrailLike>? Likes { get; set; }

        // ✅ Computed properties (read-only, not stored in database)
        /// <summary>
        /// Total number of likes for this trail.
        /// </summary>
        [NotMapped]
        public int LikeCount => Likes?.Count ?? 0;

        /// <summary>
        /// Average rating from all likes (1-5 stars).
        /// Returns null if no ratings have been given.
        /// </summary>
        [NotMapped]
        public double? AverageRating => 
            Likes?.Where(l => l.Rating.HasValue)
                  .Select(l => l.Rating!.Value)
                  .DefaultIfEmpty()
                  .Average() is var avg && avg > 0 ? avg : null;

        /// <summary>
        /// Number of likes that include a rating.
        /// </summary>
        [NotMapped]
        public int RatingCount => Likes?.Count(l => l.Rating.HasValue) ?? 0;

        /// <summary>
        /// Number of comments on this trail.
        /// </summary>
        [NotMapped]
        public int CommentCount => Comments?.Count ?? 0;

        /// <summary>
        /// Number of photos uploaded for this trail.
        /// </summary>
        [NotMapped]
        public int PhotoCount => Images?.Count ?? 0;

        // ✅ NEW: Trail lock status to prevent edits/deletions
        // This is usefull for
        // promoted or featured trails.
        public bool TrailLocked { get; set; } = false;
    }
}
