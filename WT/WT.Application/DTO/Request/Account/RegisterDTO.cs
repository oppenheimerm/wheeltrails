
using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;
using WT.Application.DTO.Response;

namespace WT.Application.DTO.Request.Account
{
    public class RegisterDTO
    {
        [Required]
        [StringLength(30)]
        [MinLength(3, ErrorMessage = "First name is reqired.")]
        [PersonalData]
        public string FirstName { get; set; } = string.Empty;

        [Required]
        [StringLength(30)]
        [MinLength(3, ErrorMessage = "Last name is reqired.")]
        [PersonalData]
        public string LasttName { get; set; } = string.Empty;

        // Ensure email address is valid
        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email format")]
        [Display(Name = "Email")]
        public string Email { get; set; } = "";


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

        public List<RoleDTO>? Roles {get; set; }
    }
}
