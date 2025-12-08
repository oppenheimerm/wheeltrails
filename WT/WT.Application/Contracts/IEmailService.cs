namespace WT.Application.Contracts
{
    /// <summary>
    /// Interface for email sending operations.
    /// </summary>
    public interface IEmailService
    {
        /// <summary>
        /// Sends a verification email to a user with their verification token.
        /// </summary>
        /// <param name="toEmail">The recipient's email address.</param>
        /// <param name="firstName">The user's first name for personalization.</param>
        /// <param name="verificationToken">The 128-character verification token.</param>
        /// <returns>True if email sent successfully, false otherwise.</returns>
        Task<bool> SendVerificationEmailAsync(string toEmail, string firstName, string verificationToken);

        /// <summary>
        /// Sends a password reset email to a user.
        /// </summary>
        /// <param name="toEmail">The recipient's email address.</param>
        /// <param name="firstName">The user's first name.</param>
        /// <param name="resetToken">The password reset token.</param>
        /// <returns>True if email sent successfully, false otherwise.</returns>
        Task<bool> SendPasswordResetEmailAsync(string toEmail, string firstName, string resetToken);
    }
}