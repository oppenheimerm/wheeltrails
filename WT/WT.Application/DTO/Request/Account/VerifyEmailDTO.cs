
using System.ComponentModel.DataAnnotations;

namespace WT.Application.DTO.Request.Account
{
    /// <summary>
    /// Data Transfer Object for verifying a user's email address.
    /// </summary>
    public class VerifyEmailDTO
    {
        [Required]
        public string? Token { get; set; }
    }
}
