
namespace WT.Application.DTO.Response.Account
{
    /// <summary>
    /// Lightweight DTO for viewing public profile information. Email and sensitive data are excluded.
    /// </summary>
    public class PublicViewProfileDTO
    {
        public string? FirstName { get; set; }
        public string? ProfileUsername { get; set; }
        public DateTime? MemberSince {get; set; }
        public string? ProfilePicture {get; set; }
        public string? Bio {get; set; }
        public string? CountryCode { get; set; }    
        public int? TrailsCount {get; set; }
        public int? CommentsCount { get; set; }
        public int? LikesCount { get; set; }
    }
}
