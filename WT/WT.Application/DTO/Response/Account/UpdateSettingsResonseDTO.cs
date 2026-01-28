
using System.ComponentModel.DataAnnotations;
using WT.Domain.Enums;

namespace WT.Application.DTO.Response.Account
{
    public class UpdateSettingsResonseDTO
    {
        [Required, MaxLength(50, ErrorMessage = "First name has a maximum size 50 characters.")]
        public string? FirstName { get; set; }

        [MaxLength(500, ErrorMessage = "Bio has a maximum size 500 characters.")]
        public string? Bio { get; set; }

        [MaxLength(2, ErrorMessage = "Country code must be 2 characters long."), MinLength(2)]
        public string? CountryCode { get; set; }

        public GpsAccuracyLevel GpsAccuracy { get; set; }
    }
}
