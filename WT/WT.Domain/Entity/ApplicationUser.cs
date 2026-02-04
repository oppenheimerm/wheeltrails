using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;


namespace WT.Domain.Entity
{
    public class ApplicationUser : IdentityUser<Guid>
    {
        [Required, MaxLength(50, ErrorMessage = "First name has a maximum size 50 characters.")]
        public string? FirstName { get; set; }

        /// <summary>
        /// Unique profile username for display purposes and profile URLs (e.g., @john_doe).
        /// Different from Email. Set once during registration and CANNOT be changed.
        /// Must be unique and not contain offensive words.
        /// Used in profile URLs: /user/profileusername or /@profileusername
        /// </summary>
        [Required]
        [MaxLength(20, ErrorMessage = "Profile username has a maximum size of 20 characters.")]
        [MinLength(3, ErrorMessage = "Profile username must be at least 3 characters.")]
        [RegularExpression(@"^[a-zA-Z0-9_.-]+$", ErrorMessage = "Profile username can only contain letters, numbers, underscores, dashes, and dots.")]
        public string ProfileUsername { get; set; } = string.Empty;

        /// <summary>
        /// When the profile username was created (same as account registration date).
        /// </summary>
        public DateTime ProfileUsernameCreatedAt { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Firebase Storage URL for the photo.
        /// </summary>
        [MaxLength(512, ErrorMessage = "ProfilePicture has a maximum length of 512 characters.")] // ✅ Increased for full URLs
        public string? ProfilePicture { get; set; }

        [MaxLength(500, ErrorMessage = "Bio has a maximum size 500 characters.")]
        public string? Bio { get; set; }

        [NotMapped] // Don't map to database - managed separately
        public List<IdentityRole<Guid>>? Roles { get; set; }

        public DateTime? Verified { get; set; }

        [NotMapped]
        public bool IsVerified => Verified.HasValue;

        public string? VerificationToken { get; set; }
        
        public bool AcceptTerms { get; set; }

        [MaxLength(2, ErrorMessage = "Country code must be 2 characters long."), MinLength(2)]
        public string? CountryCode { get; set; }

        [NotMapped] // Don't map to database - managed separately
        public List<RefreshToken>? RefreshTokens { get; set; }
        
        // Navigation property for the trails created by the user
        public ICollection<WTTrail>? Trails { get; set; }
        
        // Navigation property for comments made by the user
        public ICollection<Comment>? Comments { get; set; }

        // Navigation property for trails liked by the user
        public ICollection<TrailLike>? LikedTrails { get; set; }
        
        /// <summary>
        /// Indicates if the user account has been soft-deleted
        /// </summary>
        public bool IsDeleted { get; set; } = false;

        /// <summary>
        /// When the user account was soft-deleted
        /// </summary>
        public DateTime? DeletedAt { get; set; }

        /// <summary>
        /// Reason for account deletion (optional)
        /// </summary>
        [MaxLength(500)]
        public string? DeleteReason { get; set; }
    }
}

