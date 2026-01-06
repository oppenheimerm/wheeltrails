using System.Threading.Tasks;

namespace WT.Application.Contracts
{
    /// <summary>
    /// Contract for validating user-chosen profile usernames.
    /// Implementations should provide synchronous and asynchronous checks for
    /// allowed characters, length limits, and profanity/offensive-word filtering.
    /// 
    /// The production implementation <c>WT.Infrastructure.Services.UsernameValidator</c>
    /// loads a bad-words list from an embedded resource <c>WT.Infrastructure.Data.BadWords.en.txt</c>
    /// and performs substring checks to reject usernames containing obscene or offensive words.
    /// </summary>
    public interface IUsernameValidator
    {
        /// <summary>
        /// Synchronously determines whether the provided <paramref name="username"/> is allowed.
        /// Return <c>false</c> for null/empty values, invalid characters, out-of-range lengths,
        /// or when the username contains profanity / blocked words.
        /// </summary>
        /// <param name="username">The candidate username to validate.</param>
        /// <returns><c>true</c> when the username passes all checks; otherwise <c>false</c>.</returns>
        bool IsUsernameAllowed(string username);

        /// <summary>
        /// Asynchronously validates the provided <paramref name="username"/>. Implementations may
        /// perform I/O (for example, loading a remote list) and should expose an async API for callers.
        /// </summary>
        /// <param name="username">The candidate username to validate.</param>
        /// <returns>A task that resolves to <c>true</c> when the username is valid; otherwise <c>false</c>.</returns>
        Task<bool> IsUsernameValidAsync(string username);

        /// <summary>
        /// Returns a human-readable rejection reason when a username fails validation.
        /// Implementations should return <c>null</c> when the username is valid.
        /// </summary>
        /// <param name="username">The candidate username to inspect.</param>
        /// <returns>A rejection message or <c>null</c> when the username is acceptable.</returns>
        string? GetRejectionReason(string username);

        /// <summary>
        /// Number of loaded blocked / bad words used by the validator for profanity checks.
        /// This is primarily intended for diagnostics and telemetry (e.g., logging on startup).
        /// </summary>
        int BadWordCount { get; }
    }
}
