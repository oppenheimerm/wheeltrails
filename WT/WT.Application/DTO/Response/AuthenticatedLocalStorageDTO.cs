public class AuthenticatedLocalStorageDTO
{
    public string? JWtToken { get; set; }
    public string? RefreshToken { get; set; }
    public DateTime TimeStamp { get; set; }
    public Guid Id { get; set; }
    public string? Email { get; set; } // ✅ Make sure this exists
    public string? FirstName { get; set; }
    public string? UserPhoto { get; set; }
    public string? Bio { get; set; }
}