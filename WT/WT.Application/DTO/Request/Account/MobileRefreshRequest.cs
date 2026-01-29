namespace WT.Application.DTO.Request.Account
{
    /// <summary>
    /// Request DTO for mobile clients to provide refresh token in request body.
    /// Web clients using HttpOnly cookies should send null/empty body.
    /// </summary>
    public class MobileRefreshRequest
    {
        /// <summary>
        /// Refresh token provided by mobile clients. Not used by web clients (they use HttpOnly cookies).
        /// </summary>
        public string? RefreshToken { get; set; }
    }
}
