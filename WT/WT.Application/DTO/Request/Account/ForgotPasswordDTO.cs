using System.ComponentModel.DataAnnotations;

namespace WT.Application.DTO.Request.Account
{
    /// <summary>
    /// Data transfer object for password reset requests.
    /// </summary>
    public class ForgotPasswordDTO
    {
        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email format")]
        [Display(Name = "Email")]
        public string Email { get; set; } = string.Empty;
    }
}
