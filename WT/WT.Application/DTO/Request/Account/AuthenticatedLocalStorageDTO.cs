using WT.Domain.Enums;

namespace WT.Application.DTO.Request.Account
{
    /// <summary>
    /// Represents authentication/session data returned from the API when refreshing tokens.
    /// This is an in-memory/session DTO and should not be interpreted to mean the data is
    /// persisted to browser localStorage. Access tokens are stored in-memory by the client
    /// <see cref="WT.Client.Services.TokenService"/> and refresh tokens are handled server-side
    /// with HttpOnly cookies.
    /// </summary>
    public class AuthenticatedSessionDTO
    {
        /// <summary>
        /// JWT access token returned by the API.
        /// </summary>
        public string? JWtToken { get; set; }

        /// <summary>
        /// Refresh token (server rotates and stores this in an HttpOnly cookie when appropriate).
        /// </summary>
        public string? RefreshToken { get; set; }

        /// <summary>
        /// Timestamp when this session data was created.
        /// </summary>
        public DateTime? TimeStamp { get; set; }

        /// <summary>
        /// Authenticated user's identifier.
        /// </summary>
        public Guid? Id { get; set; }

        /// <summary>
        /// Authenticated user's first name.
        /// </summary>
        public string? FirstName { get; set; }

        /// <summary>
        /// Public profile username used in UI (non-sensitive).
        /// </summary>
        public string? ProfileUsername { get; set; }

        /// <summary>
        /// User bio (non-sensitive UI field).
        /// </summary>
        public string? Bio { get; set; }

        /// <summary>
        /// User profile picture URL (public, non-sensitive UI field).
        /// </summary>
        public string? UserPhoto { get; set; }

        /// <summary>
        /// User email (only used for the authenticated user's private views; avoid exposing publicly).
        /// </summary>
        public string? Email { get; set; }
    }
}
