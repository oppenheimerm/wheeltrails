
using WT.Application.DTO.Response;
using WT.Domain.Enums;

namespace WT.Application.DTO.Request.Account
{
    /// <summary>
    /// Data Transfer Object for <see cref="WT.Domain.Entity.ApplicationUser"/> entity."/>
    /// </summary>
    public class ApplicationUserDTO
    {
        public Guid Id { get; set; }
        public string? FirstName { get; set; }
        public string? ProfileUsername { get; set; }
        public string? Email { get; set; }
        public string? ProfilePicture { get; set; }
        public List<RoleDTO>? Roles { get; set; }
        public string? CountryCode { get; set; }
        public string? Bio { get; set; }
        public DateTime? RegistrationDate { get; set; }
        public GpsAccuracyLevel GpsAccuracy { get; set; }
        public bool ShowRecordingWarning { get; set; } = true;
    }
}
