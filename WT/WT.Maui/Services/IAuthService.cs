using System.Net.Http;
using System.Threading.Tasks;
using WT.Application.DTO.Request.Account;

namespace WT.Maui.Services
{
    public interface IAuthService
    {
        bool IsLoggedIn { get; }
        Task<bool> RestoreSessionAsync();
        Task<bool> TryRefreshAsync();
        /// <summary>
        /// Ensures the supplied HttpClient has a valid Authorization header.
        /// Sets the header when a valid access token is available (tries refresh if needed).
        /// Returns true when header is set and client is authorized.
        /// </summary>
        Task<bool> EnsureAuthorizationHeaderAsync(HttpClient client);
        Task LogoutAsync();
        Task<bool> LoginAsync(LoginDTO model);
    }
}
