
using WT.Application.DTO.Request.Account;
using WT.Application.DTO.Response.Account;

namespace WT.Application.DTO.Response
{
    public record BaseAPIResponseDTO
    (
        bool Success = false,
        string Message = null!
    );

    //  Authentication


    /// <summary>
    /// Handles the response for authentication-related operations.
    /// </summary>
    /// <param name="Success"></param>
    /// <param name="Message"></param>
    /// <param name="User"></param>
    /// <param name="JwtToken"></param>
    /// <param name="RefreshToken"></param>
    public record APIResponseAuthentication(
    bool Success = false,
    string Message = null!,
    ApplicationUserDTO? User = null!,
    string? JwtToken = "",
    string? RefreshToken = ""
    ) : BaseAPIResponseDTO(Success, Message);

    /// <summary>
    /// Handles the response for photo upload operations.
    /// </summary>
    /// <param name="Success"></param>
    /// <param name="Message"></param>
    /// <param name="PhotoUrl"></param>
    public record APIResponseUploadPhoto(
        bool Success = false,
        string Message = null!,
        string PhotoUrl = ""
    ) : BaseAPIResponseDTO(Success, Message);

    // User Profile
    public record APIResponseViewAccountSettings(
        bool Success = false,
        string Message = null!,
        APIResponseUserSettingsDTO? UserSettings = null!
    ) : BaseAPIResponseDTO(Success, Message);

    /// <summary>
    /// Public view profile response DTO. Returns lightweight public profile information.
    /// </summary>
    /// <param name="Success"></param>
    /// <param name="Message"></param>
    /// <param name="PublicProfile"></param>
    /// <param name="FailuerCode"></param>
    public record APIResponsePublicViewProfile(
        bool Success = false,
        string Message = null!,
        PublicViewProfileDTO? PublicProfile = null!,
        // Handle OperationCancelledExceptions
        int? FailuerCode = null!
    ) : BaseAPIResponseDTO(Success, Message);


    /// <summary>
    /// Handles the response for trail creation operations.  Returns trail ID and title upon success.
    /// </summary>
    /// <param name="Success"></param>
    /// <param name="Message"></param>
    /// <param name="TrailId"></param>
    /// <param name="TrailTitle"></param>
    public record APIResponseCreateTrail(
        bool Success = false,
        string Message = null!,
        Guid? TrailId = null,
        string? TrailTitle = "") : BaseAPIResponseDTO(Success, Message);

}
