using Microsoft.Extensions.Configuration;
using SendGrid;
using SendGrid.Helpers.Mail;
using WT.Application.APIServiceLogs;
using WT.Application.Contracts;

namespace WT.Infrastructure.Services
{
 /// <summary>
 /// Email service implementation using SendGrid.
 /// Reads API key and default from config (user-secrets in development).
 /// </summary>
 public class SendGridEmailService : IEmailService
 {
 private readonly IConfiguration _config;
 private readonly string _fromEmail;
 private readonly string _fromName;
 private readonly string _apiKey;

 public SendGridEmailService(IConfiguration config)
 {
 _config = config;
 _fromEmail = _config["EmailSettings:FromEmail"] ?? "noreply@wheeltrails.com";
 _fromName = _config["EmailSettings:FromName"] ?? "WheelyTrails";
 _apiKey = _config["EmailSettings:SendGridApiKey"] ?? string.Empty;
 }

 public async Task<bool> SendVerificationEmailAsync(string toEmail, string firstName, string verificationToken)
 {
 try
 {
 var clientUrl = _config["EmailSettings:ClientUrl"]?.TrimEnd('/') ?? string.Empty;
 var verificationUrl = string.IsNullOrEmpty(clientUrl) ? verificationToken : $"{clientUrl}/verify-email?token={Uri.EscapeDataString(verificationToken)}";

 var subject = "Verify Your WheelyTrails Account";
 var htmlBody = CreateVerificationEmailBody(firstName, verificationUrl);

 return await SendEmailAsync(toEmail, subject, htmlBody);
 }
 catch (Exception ex)
 {
 LogException.LogExceptions(ex);
 return false;
 }
 }

 public async Task<bool> SendPasswordResetEmailAsync(string toEmail, string firstName, string resetToken)
 {
 try
 {
 var clientUrl = _config["EmailSettings:ClientUrl"]?.TrimEnd('/') ?? string.Empty;
 var resetUrl = string.IsNullOrEmpty(clientUrl) ? resetToken : $"{clientUrl}/reset-password?token={Uri.EscapeDataString(resetToken)}";

 var subject = "Reset Your WheelyTrails Password";
 var htmlBody = CreatePasswordResetEmailBody(firstName, resetUrl);

 return await SendEmailAsync(toEmail, subject, htmlBody);
 }
 catch (Exception ex)
 {
 LogException.LogExceptions(ex);
 return false;
 }
 }

 private async Task<bool> SendEmailAsync(string toEmail, string subject, string htmlBody)
 {
 try
 {
 if (string.IsNullOrEmpty(_apiKey))
 {
 LogException.LogToFile("SendGrid API key not configured.");
 return false;
 }

 var client = new SendGridClient(_apiKey);
 var from = new EmailAddress(_fromEmail, _fromName);
 var to = new EmailAddress(toEmail);
 var msg = MailHelper.CreateSingleEmail(from, to, subject, plainTextContent: null, htmlContent: htmlBody);

 var response = await client.SendEmailAsync(msg);

 if (response.IsSuccessStatusCode)
 {
 LogException.LogToFile($"SendGrid email sent to {toEmail} at {DateTime.UtcNow}");
 return true;
 }
 else
 {
 var body = await response.Body.ReadAsStringAsync();
 LogException.LogToFile($"Failed to send SendGrid email to {toEmail}: {response.StatusCode} {body}");
 return false;
 }
 }
 catch (Exception ex)
 {
 LogException.LogExceptions(ex);
 return false;
 }
 }

 // Reuse same HTML templates as existing EmailService for consistency
 private string CreateVerificationEmailBody(string firstName, string verificationUrl)
 {
 return $@"<!DOCTYPE html>
<html>
<head>
 <meta charset='utf-8'>
 <style>
 body {{ font-family: Arial, sans-serif; line-height:1.6; color: #333; }}
 .container {{ max-width:600px; margin:0 auto; padding:20px; }}
 .header {{ background-color: #4F46E5; color: white; padding:20px; text-align: center; }}
 .content {{ padding:30px; background-color: #f9fafb; }}
 .button {{ display: inline-block; padding:12px30px; background-color: #4F46E5; 
 color: white; text-decoration: none; border-radius:5px; margin:20px0; }}
 .footer {{ text-align: center; padding:20px; color: #666; font-size:12px; }}
 </style>
</head>
<body>
 <div class='container'>
 <div class='header'>
 <h1>Welcome to WheelyTrails! ????</h1>
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
 <p><strong>This link will expire in48 hours.</strong></p>
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

 private string CreatePasswordResetEmailBody(string firstName, string resetUrl)
 {
 return $@"<!DOCTYPE html>
<html>
<head>
 <meta charset='utf-8'>
 <style>
 body {{ font-family: Arial, sans-serif; line-height:1.6; color: #333; }}
 .container {{ max-width:600px; margin:0 auto; padding:20px; }}
 .header {{ background-color: #DC2626; color: white; padding:20px; text-align: center; }}
 .content {{ padding:30px; background-color: #f9fafb; }}
 .button {{ display: inline-block; padding:12px30px; background-color: #DC2626; 
 color: white; text-decoration: none; border-radius:5px; margin:20px0; }}
 .footer {{ text-align: center; padding:20px; color: #666; font-size:12px; }}
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
 <p><strong>This link will expire in24 hours.</strong></p>
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
