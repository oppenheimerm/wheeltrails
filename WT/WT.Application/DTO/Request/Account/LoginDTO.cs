using System.ComponentModel.DataAnnotations;

namespace WT.Application.DTO.Request.Account
{
    /// <summary>
    /// Lightweight DTO for user login. 
    /// </summary>
    public class LoginDTO
    {
        [Required]
        [EmailAddress]
        [DataType(DataType.EmailAddress)]
        public string? Email { get; set; }

        [Required]
        public string? Password { get; set; }
    }
}
