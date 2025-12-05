namespace WT.Application.DTO.Request.Account
{
    /// <summary>
    /// Represents the authentication data stored in browser local storage for Blazor WebAssembly applications.
    /// Contains JWT access token, refresh token, and user information required for maintaining authenticated sessions.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Authentication flow:
    /// <list type="number">
    /// <item>On successful authentication, the API returns a JWT access token (expires after 30 minutes)</item>
    /// <item>A refresh token is also provided (expires after 7 days)</item>
    /// <item>The JWT token is used to access secured API routes via Authorization header</item>
    /// <item>When the JWT expires, the refresh token is used to obtain a new JWT without requiring re-authentication</item>
    /// </list>
    /// </para>
    /// <para>
    /// <strong>⚠️ SECURITY WARNING - KNOWN ISSUE:</strong> 
    /// Storing tokens in local storage makes them accessible to JavaScript and vulnerable to XSS attacks.
    /// While this is a common limitation for Blazor WebAssembly applications, it should be addressed.
    /// </para>
    /// <para>
    /// <strong>GitHub Issue:</strong> See issue #6 - "Enhance Token Storage Security for Blazor WASM"
    /// </para>
    /// </remarks>
    public class AuthenticatedLocalStorageDTO
    {
        /// <summary>
        /// Gets or sets the JWT access token used for authenticating API requests.
        /// This token expires after 30 minutes and must be included in the Authorization header as a Bearer token.
        /// </summary>
        public string? JWtToken { get; set; }

        /// <summary>
        /// Gets or sets the refresh token used to obtain new JWT access tokens when they expire.
        /// This token is valid for 7 days and should be sent to the refresh token endpoint.
        /// </summary>
        public string? RefreshToken { get; set; }

        /// <summary>
        /// Gets or sets the timestamp when this authentication data was stored.
        /// Used to track token age and determine when refresh is needed.
        /// </summary>
        public DateTime? TimeStamp { get; set; }

        /// <summary>
        /// Gets or sets the unique identifier of the authenticated user.
        /// </summary>
        public Guid? Id { get; set; }

        /// <summary>
        /// Gets or sets the first name of the authenticated user.
        /// </summary>
        public string? FirstName { get; set; }

        /// <summary>
        /// Gets or sets the Bio or description of the authenticated user.
        /// </summary>
        public string? Bio { get; set; }

        /// <summary>
        /// Gets or sets the URL or path to the user's profile photo.
        /// </summary>
        public string? UserPhoto { get; set; }

        /// <summary>
        /// Gets or sets the email address of the authenticated user.
        /// </summary>
        public string? Email { get; set; }
    }
}
