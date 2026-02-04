

namespace WT.Application.DTO.Response.Account
{

    /// <summary>
    /// Represents an authenticated user's settings information. The
    /// Email property is included here becasue it is only displayed to this specific user,
    /// and follow our privacy guidelines of not exposing email addresses publicly.
    /// </summary>
    public class APIResponseUserSettingsDTO
    {

        public string? Email { get; set; }
        public string? FirstName { get; set; }
        public string? ProfileUsername { get; set; }
        public DateTime? MemberSince { get; set; }
        public string? ProfilePicture { get; set; }
        public string? Bio { get; set; }
        public string? CountryCode { get; set; }
    }
}
