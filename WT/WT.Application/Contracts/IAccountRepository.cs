using WT.Application.Contracts;
using WT.Application.DTO.Request.Account;
using WT.Application.DTO.Response;
using WT.Domain.Entity;

namespace WT.Application.Contracts
{
    /// <summary>
    /// Server-side repository interface for direct database operations on user accounts.
    /// Provides low-level data access methods for user lookups and validation.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <strong>Architecture:</strong> This interface is part of the Application layer (WT.Application)
    /// and is implemented by <c>WTAccount</c> in the Infrastructure layer (WT.Infrastructure).
    /// It follows Clean Architecture principles by defining contracts in the Application layer
    /// while keeping implementation details in Infrastructure.
    /// </para>
    /// <para>
    /// <strong>Usage Context:</strong> These methods are intended for server-side operations only
    /// and should NOT be exposed directly to client applications (Blazor WebAssembly/Server).
    /// They are typically used by:
    /// - Authentication services for user verification
    /// - Account management services for user queries
    /// - Validation services for username/email uniqueness checks
    /// </para>
    /// <para>
    /// <strong>Security Note:</strong> These methods return sensitive user data including
    /// <see cref="ApplicationUser"/> entities. Ensure proper authorization checks are performed
    /// before calling these methods and never expose raw user entities to API consumers.
    /// Use DTOs (e.g., <c>ApplicationUserDTO</c>) for client-facing responses.
    /// </para>
    /// <para>
    /// <strong>Related Interfaces:</strong>
    /// - <c>IWTAccount</c>: Higher-level service interface for account operations (registration, login, etc.)
    /// - <c>IWTTrailRepository</c>: Repository interface for trail-related operations
    /// </para>
    /// </remarks>
    public interface IAccountRepository
    {
        Task<BaseAPIResponseDTO> CreateAdmin();
        Task<BaseAPIResponseDTO> RegisterAsync(RegisterDTO model);
        Task<BaseAPIResponseDTO> CreateRoleASync(CreateRoleDTO model);
        Task<IEnumerable<RoleDTO>> GetRolesAsync();
        Task<BaseAPIResponseDTO> AddUserToRoleAsync(Guid userId, CreateRoleDTO model);
        Task<BaseAPIResponseDTO> VerifyEmailAsync(string token);
        Task<BaseAPIResponseDTO> ForgotPasswordAsync(ForgotPasswordDTO model);
        Task<BaseAPIResponseDTO> ResetPasswordAsync(ResetPasswordDTO model);
        Task<BaseAPIResponseDTO> SoftDeleteUserAsync(Guid userId, string? reason = null);

        // Server-side methods with IP address parameters (internal)
        Task<APIResponseAuthentication> LoginWithIpAsync(LoginDTO model, string ipAddress);
        Task<APIResponseAuthentication> RefreshTokenWithIpAsync(string token, string ipAddress);

        // Direct database access methods
        Task<ApplicationUser?> FindUserByIdAsync(Guid id);
        Task<ApplicationUser?> FindUserByEmailAsync(string email);

        // ✅ ProfileUsername methods (returns domain entity for server-side use)
        Task<ApplicationUser?> FindUserByProfileUsernameAsync(string profileUsername);
        Task<bool> IsProfileUsernameAvailableAsync(string profileUsername);

        // JWT token generation
        Task<string?> GenerateToken(ApplicationUser user);

    }
}