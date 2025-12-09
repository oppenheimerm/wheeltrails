using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace WT.Application.DTO.Request.Account
{
    /// <summary>
    /// Public user registration - no role assignment allowed
    /// </summary>
    public class RegisterDTO
    {
        [Required]
        [StringLength(30)]
        [MinLength(3, ErrorMessage = "First name is required.")]
        [PersonalData]
        public string FirstName { get; set; } = string.Empty;

        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email format")]
        [Display(Name = "Email")]
        public string Email { get; set; } = string.Empty;

        [MaxLength(2, ErrorMessage = "Country code must be 2 characters long."), MinLength(2)]
        public string? CountryCode { get; set; }

        [MaxLength(500, ErrorMessage = "Bio has a maximum size 500 characters.")]
        public string? Bio { get; set; }

        [Required]
        [MinLength(7)]
        public string? Password { get; set; }

        [Required]
        [Compare("Password")]
        public string? ConfirmPassword { get; set; }

        [Range(typeof(bool), "true", "true")]
        public bool AcceptTerms { get; set; }

        // ❌ REMOVED - Security risk for public registration
        // public List<RoleDTO>? Roles { get; set; }
    }
}
