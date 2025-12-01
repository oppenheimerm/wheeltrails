
using WT.Application.DTO.Request.Account;

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
}
