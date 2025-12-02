namespace WT.Application.DTO.Request.Account
{
    /// <summary>
    /// A DTO for handling refresh token requests. // Might not be necessar aw we have <see cref="WT.Domain.Entity.RefreshToken"/>
    /// </summary>
    public class RefreshTokenDTO
    {
        public string? Token { get; set; }
    }
}
