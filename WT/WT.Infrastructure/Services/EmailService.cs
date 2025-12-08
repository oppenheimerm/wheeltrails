using Microsoft.Extensions.Configuration;
using System.Net;
using System.Net.Mail;
using WT.Application.APIServiceLogs;
using WT.Application.Contracts;

namespace WT.Infrastructure.Services
{
    /// <summary>
    /// Email service implementation using SMTP.
    /// Supports SendGrid, Gmail, Outlook, or any SMTP provider.
    /// </summary>
    public class EmailService : IEmailService
    {
        private readonly IConfiguration _config;
        private readonly string _fromEmail;
        private readonly string _fromName;

        public EmailService(IConfiguration config)
        {
            _config = config;
            _fromEmail = _config["EmailSettings:FromEmail"] ?? "noreply@wheeltrails.com";
            _fromName = _config["EmailSettings:FromName"] ?? "WheelyTrails";
        }

        /// <summary>
        /// Sends a verification email to a user with their verification token.
        /// </summary>
        public async Task<bool> SendVerificationEmailAsync(string toEmail, string firstName, string verificationToken)
        {
            try
            {
                var verificationUrl = $"{_config["EmailSettings:ClientUrl"]}/verify-email?token={verificationToken}";

                var subject = "Verify Your WheelyTrails Account";
                var body = CreateVerificationEmailBody(firstName, verificationUrl);

                return await SendEmailAsync(toEmail, subject, body);
            }
            catch (Exception ex)
            {
                LogException.LogExceptions(ex);
                return false;
            }
        }

        /// <summary>
        /// Sends a password reset email to a user.
        /// </summary>
        public async Task<bool> SendPasswordResetEmailAsync(string toEmail, string firstName, string resetToken)
        {
            try
            {
                var resetUrl = $"{_config["EmailSettings:ClientUrl"]}/reset-password?token={resetToken}";

                var subject = "Reset Your WheelyTrails Password";
                var body = CreatePasswordResetEmailBody(firstName, resetUrl);

                return await SendEmailAsync(toEmail, subject, body);
            }
            catch (Exception ex)
            {
                LogException.LogExceptions(ex);
                return false;
            }
        }

        /// <summary>
        /// Core email sending method using SMTP.
        /// </summary>
        private async Task<bool> SendEmailAsync(string toEmail, string subject, string htmlBody)
        {
            try
            {
                var smtpHost = _config["EmailSettings:SmtpHost"];
                var smtpPort = int.Parse(_config["EmailSettings:SmtpPort"] ?? "587");
                var smtpUser = _config["EmailSettings:SmtpUser"];
                var smtpPassword = _config["EmailSettings:SmtpPassword"];
                var enableSsl = bool.Parse(_config["EmailSettings:EnableSsl"] ?? "true");

                using var smtpClient = new SmtpClient(smtpHost, smtpPort)
                {
                    Credentials = new NetworkCredential(smtpUser, smtpPassword),
                    EnableSsl = enableSsl
                };

                var mailMessage = new MailMessage
                {
                    From = new MailAddress(_fromEmail, _fromName),
                    Subject = subject,
                    Body = htmlBody,
                    IsBodyHtml = true
                };

                mailMessage.To.Add(toEmail);

                await smtpClient.SendMailAsync(mailMessage);

                LogException.LogToFile($"Verification email sent to {toEmail} at {DateTime.UtcNow}");
                return true;
            }
            catch (Exception ex)
            {
                LogException.LogExceptions(ex);
                LogException.LogToFile($"Failed to send email to {toEmail}: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Creates HTML body for verification email.
        /// </summary>
        private string CreateVerificationEmailBody(string firstName, string verificationUrl)
        {
            return $@"
<!DOCTYPE html>
<html>
<head>
    <meta charset='utf-8'>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background-color: #4F46E5; color: white; padding: 20px; text-align: center; }}
        .content {{ padding: 30px; background-color: #f9fafb; }}
        .button {{ display: inline-block; padding: 12px 30px; background-color: #4F46E5; 
                   color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; }}
        .footer {{ text-align: center; padding: 20px; color: #666; font-size: 12px; }}
    </style>
</head>
<body>
    <div class='container'>
        <div class='header'>
            <h1>Welcome to WheelyTrails! 🦽🌲</h1>
        </div>
        <div class='content'>
            <h2>Hi {firstName},</h2>
            <p>Thank you for registering with WheelyTrails. We're excited to have you join our community!</p>
            <p>Please verify your email address by clicking the button below:</p>
            <div style='text-align: center;'>
                <a href='{verificationUrl}' class='button'>Verify Email Address</a>
            </div>
            <p>Or copy and paste this link into your browser:</p>
            <p style='word-break: break-all; color: #4F46E5;'>{verificationUrl}</p>
            <p><strong>This link will expire in 48 hours.</strong></p>
            <p>If you didn't create a WheelyTrails account, please ignore this email.</p>
        </div>
        <div class='footer'>
            <p>&copy; {DateTime.UtcNow.Year} WheelyTrails. All rights reserved.</p>
            <p>Empowering wheelchair users to explore the world, one accessible trail at a time.</p>
        </div>
    </div>
</body>
</html>";
        }

        /// <summary>
        /// Creates HTML body for password reset email.
        /// </summary>
        private string CreatePasswordResetEmailBody(string firstName, string resetUrl)
        {
            return $@"
<!DOCTYPE html>
<html>
<head>
    <meta charset='utf-8'>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background-color: #DC2626; color: white; padding: 20px; text-align: center; }}
        .content {{ padding: 30px; background-color: #f9fafb; }}
        .button {{ display: inline-block; padding: 12px 30px; background-color: #DC2626; 
                   color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; }}
        .footer {{ text-align: center; padding: 20px; color: #666; font-size: 12px; }}
    </style>
</head>
<body>
    <div class='container'>
        <div class='header'>
            <h1>Reset Your Password</h1>
        </div>
        <div class='content'>
            <h2>Hi {firstName},</h2>
            <p>We received a request to reset your WheelyTrails password.</p>
            <p>Click the button below to reset your password:</p>
            <div style='text-align: center;'>
                <a href='{resetUrl}' class='button'>Reset Password</a>
            </div>
            <p>Or copy and paste this link into your browser:</p>
            <p style='word-break: break-all; color: #DC2626;'>{resetUrl}</p>
            <p><strong>This link will expire in 24 hours.</strong></p>
            <p>If you didn't request a password reset, please ignore this email. Your password will remain unchanged.</p>
        </div>
        <div class='footer'>
            <p>&copy; {DateTime.UtcNow.Year} WheelyTrails. All rights reserved.</p>
        </div>
    </div>
</body>
</html>";
        }
    }
}