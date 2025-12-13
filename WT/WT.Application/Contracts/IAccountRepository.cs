using WT.Application.Contracts;
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
        /// <summary>
        /// Finds a user by their unique identifier (GUID).
        /// </summary>
        /// <param name="id">The GUID of the user to find</param>
        /// <returns>
        /// The <see cref="ApplicationUser"/> entity if found; otherwise, <c>null</c>.
        /// </returns>
        /// <remarks>
        /// <para>
        /// This method performs a direct database lookup using the user's primary key (Id).
        /// It returns the complete <see cref="ApplicationUser"/> entity including all properties
        /// but does NOT eagerly load navigation properties (RefreshTokens, Trails, Comments, etc.)
        /// by default.
        /// </para>
        /// <para>
        /// <strong>Common Use Cases:</strong>
        /// - Validating JWT token claims (user ID from token)
        /// - Retrieving user details for authenticated operations
        /// - Verifying user existence before performing operations
        /// </para>
        /// <para>
        /// <strong>Performance Note:</strong> This is a fast lookup using the indexed primary key.
        /// If you need related data (trails, comments, etc.), use appropriate Include() methods
        /// in the implementation or create a specific repository method.
        /// </para>
        /// <para>
        /// <strong>Example Usage:</strong>
        /// <code>
        /// var user = await _accountRepository.FindUserByIdAsync(userId);
        /// if (user == null || user.IsDeleted)
        /// {
        ///     return Unauthorized("Invalid user");
        /// }
        /// </code>
        /// </para>
        /// </remarks>
        Task<ApplicationUser?> FindUserByIdAsync(Guid id);

        /// <summary>
        /// Finds a user by their unique username (case-insensitive search).
        /// </summary>
        /// <param name="username">The username to search for (case-insensitive)</param>
        /// <returns>
        /// The <see cref="ApplicationUser"/> entity if found; otherwise, <c>null</c>.
        /// </returns>
        /// <remarks>
        /// <para>
        /// This method performs a case-insensitive lookup using the user's <see cref="ApplicationUser.Username"/> property.
        /// Usernames in the Wheel Trails system are:
        /// - Unique across all users (enforced at database and application level)
        /// - 3-20 characters in length
        /// - Can only contain letters, numbers, underscores, dashes, and dots
        /// - Once set, cannot be changed for 90 days (see <see cref="ApplicationUser.UsernameSetDate"/>)
        /// </para>
        /// <para>
        /// <strong>Important:</strong> This method searches the <see cref="ApplicationUser.Username"/> property,
        /// NOT the <see cref="ApplicationUser.UserName"/> property (which stores the email for Identity purposes).
        /// </para>
        /// <para>
        /// <strong>Common Use Cases:</strong>
        /// - Username availability checks during registration/username setting
        /// - User profile lookups by username
        /// - Public user searches (after filtering soft-deleted accounts)
        /// </para>
        /// <para>
        /// <strong>Performance Note:</strong> This lookup uses a database index on the Username field.
        /// The search is case-insensitive to ensure uniqueness regardless of casing.
        /// </para>
        /// <para>
        /// <strong>Example Usage:</strong>
        /// <code>
        /// var existingUser = await _accountRepository.FindUserByUserName(requestedUsername);
        /// if (existingUser != null)
        /// {
        ///     return BadRequest("Username is already taken");
        /// }
        /// </code>
        /// </para>
        /// </remarks>
        Task<ApplicationUser?> FindUserByUserName(string username);

        /// <summary>
        /// Finds a user by their email address (case-insensitive search).
        /// </summary>
        /// <param name="email">The email address to search for (case-insensitive)</param>
        /// <returns>
        /// The <see cref="ApplicationUser"/> entity if found; otherwise, <c>null</c>.
        /// </returns>
        /// <remarks>
        /// <para>
        /// This method performs a case-insensitive lookup using the user's email address.
        /// In the Wheel Trails system, email addresses are:
        /// - Unique across all users (enforced by ASP.NET Core Identity)
        /// - Used as the login identifier (stored in <see cref="ApplicationUser.Email"/> and <see cref="ApplicationUser.UserName"/>)
        /// - Required to be verified before account activation (see <see cref="ApplicationUser.EmailConfirmed"/>)
        /// </para>
        /// <para>
        /// <strong>Common Use Cases:</strong>
        /// - Login authentication (finding user by email for credential verification)
        /// - Email availability checks during registration
        /// - Password reset flows (finding user by email to send reset link)
        /// - Email verification flows
        /// </para>
        /// <para>
        /// <strong>Performance Note:</strong> This lookup uses ASP.NET Core Identity's normalized email index
        /// for efficient case-insensitive searching. The implementation typically uses
        /// <c>UserManager.FindByEmailAsync()</c> or equivalent EF Core query.
        /// </para>
        /// <para>
        /// <strong>Security Consideration:</strong> Be cautious about exposing whether an email exists in the system.
        /// For security reasons (preventing user enumeration attacks), consider returning generic messages
        /// like "If an account exists, you will receive an email" instead of "Email not found".
        /// </para>
        /// <para>
        /// <strong>Example Usage:</strong>
        /// <code>
        /// var user = await _accountRepository.FindUserByEmailAsync(loginDto.Email);
        /// if (user == null || !user.EmailConfirmed)
        /// {
        ///     return Unauthorized("Invalid credentials or unverified email");
        /// }
        /// </code>
        /// </para>
        /// </remarks>
        Task<ApplicationUser?> FindUserByEmailAsync(string email);

        /// <summary>
        /// Checks if a username is available for use (not taken by another user).
        /// Performs case-insensitive validation.
        /// </summary>
        /// <param name="username">The username to check for availability (case-insensitive)</param>
        /// <returns>
        /// <c>true</c> if the username is available (not in use); <c>false</c> if the username is already taken.
        /// </returns>
        /// <remarks>
        /// <para>
        /// This method checks if the provided username is available for use by querying the database
        /// for existing users with the same username (case-insensitive comparison). It is used to
        /// enforce username uniqueness across the system.
        /// </para>
        /// <para>
        /// <strong>Username Rules:</strong>
        /// - Must be unique across all users
        /// - 3-20 characters in length (validated separately via <see cref="ApplicationUser.Username"/> annotations)
        /// - Can only contain: letters (a-z, A-Z), numbers (0-9), underscores (_), dashes (-), and dots (.)
        /// - Once set, cannot be changed for 90 days (business rule enforced separately)
        /// - Must not contain offensive words (validated separately)
        /// </para>
        /// <para>
        /// <strong>Common Use Cases:</strong>
        /// - Pre-validation during username setting (before saving to database)
        /// - Real-time username availability checks in UI (via dedicated API endpoint)
        /// - Validation during account registration if username is provided
        /// </para>
        /// <para>
        /// <strong>Implementation Note:</strong> This method typically uses <c>AnyAsync()</c> for efficient
        /// existence checking without loading the full user entity. It should exclude soft-deleted accounts
        /// and check against <see cref="ApplicationUser.Username"/> (not <see cref="ApplicationUser.UserName"/>).
        /// </para>
        /// <para>
        /// <strong>Performance Note:</strong> This query uses an indexed database field for fast lookups.
        /// Consider caching results for frequently checked usernames to reduce database load.
        /// </para>
        /// <para>
        /// <strong>Example Usage:</strong>
        /// <code>
        /// // Client-side username validation endpoint
        /// [HttpGet("check-username/{username}")]
        /// public async Task&lt;IActionResult&gt; CheckUsernameAvailability(string username)
        /// {
        ///     var isAvailable = await _accountRepository.IsUsernameAvailableAsync(username);
        ///     return Ok(new { available = isAvailable });
        /// }
        /// 
        /// // Server-side validation before setting username
        /// if (!await _accountRepository.IsUsernameAvailableAsync(newUsername))
        /// {
        ///     return BadRequest("Username is already taken");
        /// }
        /// </code>
        /// </para>
        /// <para>
        /// <strong>Related Properties:</strong>
        /// - <see cref="ApplicationUser.Username"/>: The actual username field
        /// - <see cref="ApplicationUser.UsernameIsSet"/>: Flag indicating if username has been set
        /// - <see cref="ApplicationUser.UsernameSetDate"/>: Timestamp of when username was last set (for 90-day rule)
        /// </para>
        /// </remarks>
        Task<bool> IsUsernameAvailableAsync(string username);
    }
}