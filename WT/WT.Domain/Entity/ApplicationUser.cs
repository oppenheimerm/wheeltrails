using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace WT.Domain.Entity
{
    public class ApplicationUser : IdentityUser<Guid>
    {
        public string? ProfilePicture { get; set; }
        [MaxLength(500, ErrorMessage = "Bio has a maximum size 500 characters.")]
        public string? Bio { get; set; }
        public List<WTRole>? Roles { get; set; }
        [Range(typeof(bool), "true", "true")]

        public DateTime? Verified { get; set; }

        public bool IsVerified => Verified.HasValue;
        public bool AcceptTerms { get; set; }

        [MaxLength(2, ErrorMessage = "Country code must be 2 characters long."), MinLength(2)]
        public string? CountryCode { get; set; }
    }
}

