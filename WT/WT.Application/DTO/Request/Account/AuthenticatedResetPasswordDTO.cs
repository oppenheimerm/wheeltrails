
using System.ComponentModel.DataAnnotations;

namespace WT.Application.DTO.Request.Account
{
    /// <summary>
    /// Reset password request DTO for authenticated users. Not to be 
    /// confused with <see cref="ResetPasswordDTO"/>, which is used for unauthenticated users.
    /// </summary>
    public class AuthenticatedResetPasswordDTO
    {
        // Remember this is a request, from an authenticated user, and to ensure security
        //  We should get the user ID from the authentication context, not from the request body.
        //[Required]
        //public Guid UserId { get; set; }

        [Required(ErrorMessage = "Current password is required")]
        [DataType(DataType.Password)]
        public string CurrentPassword { get; set; } = string.Empty;

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
