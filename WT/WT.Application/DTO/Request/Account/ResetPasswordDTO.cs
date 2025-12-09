using System.ComponentModel.DataAnnotations;

namespace WT.Application.DTO.Request.Account
{
    /// <summary>
    /// Data transfer object for password reset requests.
    /// </summary>
    public class ResetPasswordDTO
    {
        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email format")]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "Reset token is required")]
        public string Token { get; set; } = string.Empty;

        [Required(ErrorMessage = "New password is required")]
        [MinLength(7, ErrorMessage = "Password must be at least 7 characters")]
        [DataType(DataType.Password)]
        public string NewPassword { get; set; } = string.Empty;

        [Required(ErrorMessage = "Password confirmation is required")]
        [Compare(nameof(NewPassword), ErrorMessage = "Passwords do not match")]
        [DataType(DataType.Password)]
        public string ConfirmPassword { get; set; } = string.Empty;
    }
}
