using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace WT.Domain.Entity
{
    public class ApplicationUser : IdentityUser<Guid>
    {
        [Required, MaxLength(50, ErrorMessage = "First name has a maximum size 50 characters.")]
        public string? FirstName { get; set; }

        /// <summary>
        /// Unique username for display purposes (different from email).
        /// Once set, it cannot be changed for 90 days <see cref="UsernameSetDate"/>. 
        /// For the last time it was set. Must be unique and not contain offensive words.
        /// </summary>
        [MaxLength(20, ErrorMessage = "Username has a maximum size of 20 characters.")]
        [MinLength(3, ErrorMessage = "Username must be at least 3 characters.")]
        [RegularExpression(@"^[a-zA-Z0-9_.-]+$", ErrorMessage = "Username can only contain letters, numbers, underscores, dashes, and dots.")]
        public string? Username { get; set; }

        /// <summary>
        /// Indicates if username has been set (cannot be changed after first set).
        /// </summary>
        public bool UsernameIsSet { get; set; } = false;


        /// <summary>
        /// The date when the username was set for the first time.
        /// </summary>
        public DateTime? UsernameSetDate { get; set; }

        public string? ProfilePicture { get; set; }

        [MaxLength(500, ErrorMessage = "Bio has a maximum size 500 characters.")]
        public string? Bio { get; set; }

        public List<IdentityRole<Guid>>? Roles { get; set; }

        [Range(typeof(bool), "true", "true")]

        public DateTime? Verified { get; set; }

        public bool IsVerified => Verified.HasValue;

        public string? VerificationToken { get; set; }
        public bool AcceptTerms { get; set; }

        [MaxLength(2, ErrorMessage = "Country code must be 2 characters long."), MinLength(2)]
        public string? CountryCode { get; set; }
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

