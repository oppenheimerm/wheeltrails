
namespace WT.Application.DTO.Request.Account
{
    /// <summary>
    /// Authenticated user navbar properties.
    /// </summary>
    public class NavBarSettingsDTO
    {

        public DateTime? RegistrationDate { get; set; }


        /// <summary>
        /// Gets or sets the first name of the authenticated user.
        /// </summary>
        public string? FirstName { get; set; }

        /// <summary>
        /// Gets or sets the puiblic username of the authenticated user.
        /// </summary>
        public string ProfileUsername { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the Bio or description of the authenticated user.
        /// </summary>
        public string? Bio { get; set; }

        /// <summary>
        /// Gets or sets the URL or path to the user's profile photo.
        /// </summary>
        public string? UserPhoto { get; set; }
    }
}
