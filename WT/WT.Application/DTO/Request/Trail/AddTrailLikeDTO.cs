
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using WT.Domain.Entity;

namespace WT.Application.DTO.Request.Trail
{
    public class AddTrailLikeDTO
    {

        // For srict data integrity, we do NOT include UserId here.  It shoud always
        // be derived from the authenticated user context, i.e. the JWT token.
        //public Guid UserId { get; set; }
                
        /// <summary>
        /// Foreign Key to WTTrail (trail that was liked)
        /// </summary>
        [Required]        
        public Guid TrailId { get; set; }

        // We do NOT allow setting LikedAt from outside to ensure integrity.  This
        // should always be set to current time when the like is created.
        //public DateTime LikedAt { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Optional rating (1-5 stars). Null if user liked without rating.
        /// </summary>
        [Required]
        [Range(1, 5, ErrorMessage = "Rating must be between 1 and 5")]
        public int? Rating { get; set; }
    }
}
