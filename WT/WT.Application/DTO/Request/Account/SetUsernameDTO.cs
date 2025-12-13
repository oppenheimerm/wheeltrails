using System.ComponentModel.DataAnnotations;

namespace WT.Application.DTO.Request.Account
{
    public class SetUsernameDTO
    {
        [Required(ErrorMessage = "Username is required")]
        [StringLength(20, MinimumLength = 3, ErrorMessage = "Username must be between 3 and 20 characters")]
        [RegularExpression(@"^[a-zA-Z0-9_.-]+$", ErrorMessage = "Username can only contain letters, numbers, underscores, dashes, and dots")]
        public string Username { get; set; } = string.Empty;
    }
}
