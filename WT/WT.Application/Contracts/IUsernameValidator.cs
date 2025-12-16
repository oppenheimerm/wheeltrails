namespace WT.Application.Contracts
{
    /// <summary>
    /// Validates usernames against offensive words and profanity.
    /// Uses the LDNOOBW (List of Dirty, Naughty, Obscene, and Otherwise Bad Words) list.
    /// </summary>
    public interface IUsernameValidator
    {
        /// <summary>
        /// Validates if username contains offensive words (synchronous).
        /// </summary>
        /// <param name="username">Username to validate</param>
        /// <returns>True if username is acceptable, false if it contains bad words</returns>
        bool IsUsernameAllowed(string username);

        /// <summary>
        /// Validates if username contains offensive words (asynchronous).
        /// </summary>
        /// <param name="username">Username to validate</param>
        /// <returns>True if username is acceptable, false if it contains bad words</returns>
        Task<bool> IsUsernameValidAsync(string username);

        /// <summary>
        /// Gets the reason why username was rejected (if applicable).
        /// </summary>
        /// <param name="username">The username that was validated</param>
        /// <returns>Rejection reason or null if username is valid</returns>
        string? GetRejectionReason(string username);
    }
}