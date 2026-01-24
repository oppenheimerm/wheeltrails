
namespace WT.Application.DTO.Response.Account
{
    /// <summary>
    /// Public-facing user data for trail listings and details.
    /// Contains only information safe to expose to anonymous/other users.
    /// </summary>
    public class PublicViewProfileDTO
    {
        public Guid Id { get; set; }
        public string? FirstName { get; set; }
        public string? ProfileUsername { get; set; }
        public DateTime? MemberSince {get; set; }
        public string? ProfilePicture {get; set; }
        public string? Bio {get; set; }
        public string? CountryCode { get; set; }    
        public int? TrailsCount {get; set; }
        public int? CommentsCount { get; set; }
        public int? LikesCount { get; set; }
        // ❌ NO personal preferences
        // ❌ NO email
        // ❌ NO roles (unless specifically needed)
    }
}
