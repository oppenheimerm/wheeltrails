using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace WT.Application.DTO.Request.Account
{
    /// <summary>
    /// Public user registration - no role assignment allowed
    /// </summary>
    public class RegisterDTO
    {
        [Required(ErrorMessage = "First name is required.")]
        [StringLength(50, MinimumLength = 3)]
        public string? FirstName { get; set; }

        [Required(ErrorMessage = "Email is required.")]
        [EmailAddress(ErrorMessage = "Invalid email address.")]
        public string? Email { get; set; }

        // ✅ NEW: ProfileUsername (for display and URLs)
        [Required(ErrorMessage = "Profile username is required.")]
        [StringLength(20, MinimumLength = 3, ErrorMessage = "Profile username must be between 3 and 20 characters.")]
        [RegularExpression(@"^[a-zA-Z0-9_.-]+$", ErrorMessage = "Profile username can only contain letters, numbers, underscores, dashes, and dots.")]
        public string? ProfileUsername { get; set; }

        [MaxLength(500)]
        public string? Bio { get; set; }

        [Required(ErrorMessage = "Password is required.")]
        [StringLength(100, MinimumLength = 7)]
        public string? Password { get; set; }

        [Required(ErrorMessage = "Password confirmation is required.")]
        [Compare(nameof(Password), ErrorMessage = "Passwords do not match.")]
        public string? ConfirmPassword { get; set; }

        public bool AcceptTerms { get; set; }

        [MaxLength(2), MinLength(2)]
        public string? CountryCode { get; set; }
    }
}
