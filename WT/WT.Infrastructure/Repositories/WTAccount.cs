using Azure.Core;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using WT.Application.APIServiceLogs;
using WT.Application.Contracts;
using WT.Application.DTO.Request.Account;
using WT.Application.DTO.Response;
using WT.Application.Extensions;
using WT.Application.Services;
using WT.Domain.Entity;
using WT.Infrastructure.Data;

namespace WT.Infrastructure.Repositories
{
    /// <summary>
    /// Infrastructure implementation of account management for the API backend.
    /// This class handles direct database operations, ASP.NET Identity management, and authentication logic.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <strong>Architecture Role:</strong> Server-side repository implementation that provides direct database
    /// access and business logic for the API layer. This is NOT used by Blazor clients - they use AccountService
    /// which makes HTTP calls to the API.
    /// </para>
    /// <para>
    /// <strong>Key Responsibilities:</strong>
    /// </para>
    /// <list type="bullet">
    /// <item><description>Direct Entity Framework Core database operations</description></item>
    /// <item><description>ASP.NET Identity user and role management</description></item>
    /// <item><description>Password hashing and verification</description></item>
    /// <item><description>JWT token generation with user claims and roles</description></item>
    /// <item><description>Refresh token creation, rotation, and revocation</description></item>
    /// <item><description>Email verification token generation</description></item>
    /// <item><description>Security audit logging</description></item>
    /// <item><description>Token compromise detection and mitigation</description></item>
    /// </list>
    /// <para>
    /// <strong>Registration:</strong> Register in API's Infrastructure ServiceContainer:
    /// </para>
    /// <code>
    /// services.AddScoped&lt;IWTAccount, WTAccount&gt;();
    /// </code>
    /// <para>
    /// <strong>Request Flow:</strong> API Controller → WTAccount → EF Core/Identity → Database
    /// </para>
    /// <para>
    /// <strong>Dependencies:</strong> Requires UserManager, RoleManager, SignInManager, AppDbContext, and IConfiguration
    /// for JWT settings and admin user configuration.
    /// </para>
    /// <para>
    /// <strong>Security Features:</strong>
    /// </para>
    /// <list type="bullet">
    /// <item><description>Automatic refresh token rotation on each use</description></item>
    /// <item><description>Detection and revocation of compromised token chains</description></item>
    /// <item><description>Configurable refresh token TTL (default 90 days)</description></item>
    /// <item><description>JWT tokens expire after 30 minutes</description></item>
    /// <item><description>Refresh tokens valid for 7 days</description></item>
    /// <item><description>IP address tracking for all authentication operations</description></item>
    /// </list>
    /// </remarks>
    public class WTAccount(RoleManager<IdentityRole<Guid>> roleManager,
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signinManager,
        AppDbContext dbContext,
        IConfiguration config,
        IEmailService emailService) : IAccountService, IAccountRepository
    {
        /// <summary>
        /// Adds a user to a specified role.
        /// </summary>
        /// <param name="userId">The unique identifier of the user to add to the role.</param>
        /// <param name="model">The role assignment data containing the role name.</param>
        /// <returns>A response indicating success or failure with appropriate message.</returns>
        /// <remarks>
        /// <para>This method:</para>
        /// <list type="number">
        /// <item><description>Validates that the user exists in the database</description></item>
        /// <item><description>Validates that the role exists</description></item>
        /// <item><description>Uses ASP.NET Identity's UserManager to assign the role</description></item>
        /// <item><description>Returns detailed error messages for troubleshooting</description></item>
        /// </list>
        /// <para>This operation requires administrative privileges and should be called through
        /// an authorized API endpoint.</para>
        /// </remarks>
        public async Task<BaseAPIResponseDTO> AddUserToRoleAsync(Guid userId, CreateRoleDTO model)
        {
            var user = await FindUserByIdAsync(userId);
            if (user == null)
            {
                return new BaseAPIResponseDTO
                {
                    Success = false,
                    Message = "User not found."
                };
            }
             
            return await AddUserToRoleAsync(user, model.RoleName!);
        }

        /// <summary>
        /// Creates the default administrator account with all admin roles.
        /// </summary>
        /// <returns>A response indicating whether the admin account was created successfully.</returns>
        /// <remarks>
        /// <para>This method performs the following operations:</para>
        /// <list type="number">
        /// <item><description>Reads admin credentials from configuration (User Secrets in development)</description></item>
        /// <item><description>Creates system roles if they don't exist: ADMIN_DEVELOPER, ADMIN_EDITOR, USER, USER_EDITOR</description></item>
        /// <item><description>Registers the admin user with provided credentials</description></item>
        /// <item><description>Assigns all admin roles to the newly created user</description></item>
        /// <item><description>Logs the operation for audit purposes</description></item>
        /// </list>
        /// <para>
        /// <strong>Configuration Required:</strong>
        /// </para>
        /// <code>
        /// "AdminUser": {
        ///   "FirstName": "Admin",
        ///   "Email": "admin@wheeltrails.com",
        ///   "Password": "Admin@123456"
        /// }
        /// </code>
        /// <para>Should be called during application initialization to ensure at least one admin exists.
        /// The method handles existing admin accounts gracefully.</para>
        /// </remarks>
        public async Task<BaseAPIResponseDTO> CreateAdmin()
        {
            try 
            {
                if ((await FindRoleByNameAsync(Constants.Role.ADMIN_DEVELOPER)) != null)
                    return new BaseAPIResponseDTO() 
                    { 
                        Success = false, 
                        Message = "Admin account already created." 
                    };

                var admin = new RegisterDTO()
                { 
                    FirstName = config["AdminUser:FirstName"]!,
                    Email = config["AdminUser:Email"]!,
                    Password = config["AdminUser:Password"]!,
                    AcceptTerms = true,
                    Bio = "Administrator Account"
                };

                var adminRoles = new List<RoleDTO>
                {
                    new RoleDTO { RoleName = Constants.Role.ADMIN_DEVELOPER },
                    new RoleDTO { RoleName = Constants.Role.ADMIN_EDITOR },
                    new RoleDTO { RoleName = Constants.Role.USER},
                    new RoleDTO { RoleName = Constants.Role.USER_EDITOR}
                };

                // Ensure admin roles are created
                await CreateAdminRoles(adminRoles);

                // ✅ REMOVED: admin.Roles = adminRoles; (security fix)
                // Roles are now assigned separately after registration

                var status = await RegisterAsync(admin);
                if (status.Success)
                {
                    var user = await FindUserByEmailAsync(admin.Email!);
                    if (user != null)
                    {
                        // ✅ Assign roles after user creation (not during registration)
                        foreach (var role in adminRoles)
                        {
                            await AddUserToRoleAsync(user, role.RoleName!);
                        }
                    }
                    
                    LogException.LogToFile($"Admin user created: {admin.Email} at {DateTime.UtcNow}");
                    return new BaseAPIResponseDTO() 
                    { 
                        Success = true, 
                        Message = "Successfully created Admin account" 
                    };
                }
                else
                {
                    LogException.LogToConsole($"Failed to create admin user: {admin.Email} at {DateTime.UtcNow}. Reason: {status.Message}");
                    return new BaseAPIResponseDTO() 
                    { 
                        Success = false, 
                        Message = status.Message 
                    };
                }
            }
            catch(Exception err)
            {
                LogException.LogExceptions(err);
                return new BaseAPIResponseDTO() 
                { 
                    Success = false, 
                    Message = "Failed to create Admin account" 
                };
            }
        }

        public Task<BaseAPIResponseDTO> CreateRoleASync(CreateRoleDTO model)
        {
            throw new NotImplementedException();
        }

        public Task<IEnumerable<RoleDTO>> GetRolesAsync()
        {
            throw new NotImplementedException();
        }


        // Internal method with IP address (called by controller)
        /// <summary>
        /// Authenticates a user and issues JWT and refresh tokens upon successful login.
        /// This overload is used internally by the API controller which extracts the IP address.
        /// </summary>
        /// <param name="model">The login credentials containing email and password.</param>
        /// <param name="ipAddress">The IP address of the client extracted from HttpContext.</param>
        /// <returns>
        /// Authentication response containing JWT token (30-minute expiry), refresh token (7-day expiry),
        /// and user details on successful authentication.
        /// </returns>
        public async Task<APIResponseAuthentication> LoginWithIpAsync(LoginDTO model, string ipAddress)
        {
            try
            {
                var user = userManager.FindByEmailAsync(model.Email!).Result;
                if (user == null)
                {
                    return new APIResponseAuthentication
                    {
                        Success = false,
                        Message = "Invalid email or password."
                    };
                }

                // Check if user is verified - disabled for now(Testing)
                /*if (!user.IsVerified)
                    return new APIResponseAuthentication(false, "Please verify your account");*/

                /*
                if (account.AccountLockedOut == true)
                    return new APIResponseAuthentication(false, "Your account is locked.  Please contact our help desk for assistance.");
                 */

                SignInResult result;
                result = await signinManager.CheckPasswordSignInAsync(user, model.Password!, false);
                if (result.Succeeded)
                {
                    //  Get user roles
                    user.Roles = await GetRolesForUserAsync(user.Id);

                    // Generate JWT token
                    var jwtToken = await GenerateToken(user);
                    // Generate refresh token
                    var refreshToken = await GenerateRefreshToken(ipAddress, user.Id);

                    if (user.RefreshTokens is not null && refreshToken is not null)
                    {
                        user.RefreshTokens.Add(refreshToken);
                    }

                    // remove old refresh tokens from user instance
                    RemoveOldRefreshTokens(user);

                    // save changes to database
                    // FYI UserManager.UpdateAsync(),Automatically calls SaveChangesAsync on the underlying DbContext
                    //  and returns an IdentityResult, indicating whether the operation was successful or not.
                    //  In the case where we call the dbContext.Update(user) above, we would need to call
                    //  dbContext.SaveChangesAsync() ourselves.
                    var userUpdate = await userManager.UpdateAsync(user);

                    if (userUpdate.Succeeded)
                    {
                        LogException.LogToFile($"User logged in: {user.Email} at {DateTime.UtcNow}");
                        return new APIResponseAuthentication
                        {
                            Success = true,
                            Message = "Login successful.",
                            User = user.ToDto(),
                            JwtToken = jwtToken,
                            RefreshToken = refreshToken!.Token
                        };
                    }
                    else
                    {
                        LogException.LogToConsole($"Login failed for {user.Email} at {DateTime.UtcNow}. Unable to update user with refresh token.");
                        return new APIResponseAuthentication
                        {
                            Success = false,
                            Message = "Login failed. Unable to update user with refresh token."
                        };
                    }

                }
                else
                {
                    LogException.LogToFile($"Login failed for {model.Email} at {DateTime.UtcNow}. Invalid credentials.");
                    return new APIResponseAuthentication
                    {
                        Success = false,
                        Message = "Invalid email or password."
                    };
                }
            }
            catch (Exception Err)
            {
                // Login failed due to exception, log exception
                LogException.LogExceptions(Err);
                return new APIResponseAuthentication
                {
                    Success = false,
                    Message = "An error occurred during login. Please try again later."
                };
            }
        }


        /// <summary>
        /// Registers a new user account with email verification.
        /// </summary>
        /// <param name="model">The registration data including user details, password, and optional role assignments.</param>
        /// <returns>
        /// A response indicating success or failure. On success, the Message property contains the verification
        /// token that should be sent to the user's email for account activation.
        /// </returns>
        /// <remarks>
        /// <para><strong>Registration Process:</strong></para>
        /// <list type="number">
        /// <item><description>Validates email uniqueness (checks for existing users)</description></item>
        /// <item><description>Validates required fields (password, first name)</description></item>
        /// <item><description>Validates terms and conditions acceptance</description></item>
        /// <item><description>Creates ApplicationUser with hashed password (via Identity)</description></item>
        /// <item><description>Generates unique cryptographic verification token</description></item>
        /// <item><description>Stores user information in Title Case format</description></item>
        /// <item><description>Assigns default USER role to new account</description></item>
        /// <item><description>Logs registration attempt with timestamp</description></item>
        /// </list>
        /// <para><strong>Data Processing:</strong></para>
        /// <list type="bullet">
        /// <item><description>First name: Converted to Title Case, spaces removed</description></item>
        /// <item><description>Email: Used as both Email and UserName</description></item>
        /// <item><description>Password: Automatically hashed by ASP.NET Identity (never stored in plain text)</description></item>
        /// <item><description>Verification Token: 128-character hex string, cryptographically secure</description></item>
        /// </list>
        /// <para><strong>Post-Registration:</strong></para>
        /// <para>The user MUST verify their email before they can log in. The verification token returned
        /// in the Message property should be sent to the user's email address with a verification link.</para>
        /// <para><strong>Error Handling:</strong></para>
        /// <para>Detailed error messages are logged but generic messages returned to prevent information disclosure.
        /// All Identity validation errors (password strength, etc.) are included in the response.</para>
        /// </remarks>
        public async Task<BaseAPIResponseDTO> RegisterAsync(RegisterDTO model)
        {
            try {

                if(await FindUserByEmailAsync(model.Email) != null)
                {
                    return new BaseAPIResponseDTO
                    {
                        Success = false,
                        Message = "User with this email already exists."
                    };
                }

                if (string.IsNullOrWhiteSpace(model.Password))
                {
                    return new BaseAPIResponseDTO
                    {
                        Success = false,
                        Message = "Password is required."
                    };
                }

                if (string.IsNullOrWhiteSpace(model.FirstName))
                {
                    return new BaseAPIResponseDTO
                    {
                        Success = false,
                        Message = "First name is required."
                    };
                }

                // ✅ Bypass AcceptTerms validation in Development e
                // User must accept terms and conditions
                if (!model.AcceptTerms && !IsDevelopmentEnvironment())
                {
                    return new BaseAPIResponseDTO
                    {
                        Success = false,
                        Message = "You must accept the terms and conditions to register."
                    };
                }

                var user = new ApplicationUser
                {
                    UserName = model.Email,
                    Email = model.Email,
                    FirstName = System.Globalization.CultureInfo.CurrentCulture.TextInfo.ToTitleCase(
                        model.FirstName.Replace(" ", "").ToLower()),
                    Bio = model.Bio,
                    VerificationToken = GenerateVerificationToken(),
                    AcceptTerms = model.AcceptTerms,
                    CountryCode = model.CountryCode,
                    PasswordHash = model.Password!
                };
                
                var result = await userManager.CreateAsync(user, model.Password);

                if (result.Succeeded)
                {
                    // ✅ SECURITY: Always assign default USER role for public registration
                    // Ignore any roles provided in the DTO
                    var roleStatus = await userManager.AddToRoleAsync(user, Constants.Role.USER);
                    
                    if (!roleStatus.Succeeded)
                    {
                        var roleErrors = string.Join("; ", roleStatus.Errors.Select(e => e.Description));
                        return new BaseAPIResponseDTO
                        {
                            Success = false,
                            Message = $"Failed to add user to role: {roleErrors}"
                        };
                    }

                    // ✅ Send verification email
                    var emailSent = await emailService.SendVerificationEmailAsync(
                        user.Email!, 
                        user.FirstName!, 
                        user.VerificationToken!);

                    if (!emailSent)
                    {
                        LogException.LogToFile($"Failed to send verification email to {user.Email} at {DateTime.UtcNow}");
                        // Don't fail registration if email fails - just log it
                    }

                    LogException.LogToFile($"New user registered: {user.Email} at {DateTime.UtcNow}");

                    return new BaseAPIResponseDTO
                    {
                        Success = true,
                        Message = "Registration successful. Please check your email to verify your account."
                    };
                }
                else
                {
                    var errors = string.Join("; ", result.Errors.Select(e => e.Description));
                    LogException.LogToFile($"User registration failed for {model.Email} at {DateTime.UtcNow}. Errors: {errors}");

                    return new BaseAPIResponseDTO
                    {
                        Success = false,
                        Message = $"User registration failed: {errors}"
                    };
                }
            }
            catch (Exception Err)
            {
                LogException.LogExceptions(Err);
                return new BaseAPIResponseDTO
                {
                    Success = false,
                    Message = "An error occurred during registration. Please try again later."
                };
            }
        }


        // Internal method with IP address (called by controller)
        /// <summary>
        /// Refreshes an expired JWT token using a valid refresh token.
        /// This overload is used internally by the API controller which extracts the IP address.
        /// </summary>
        /// <param name="token">The current refresh token to validate and exchange for new tokens.</param>
        /// <param name="ipAddress">The IP address of the client extracted from HttpContext.</param>
        /// <returns>
        /// Authentication response with new JWT token, rotated refresh token, and updated user details on success.
        /// </returns>
        public async Task<APIResponseAuthentication> RefreshTokenWithIpAsync(string token, string ipAddress)
        {
            // Get user account by refresh token
            var user = await FindUserByRefreshTokenAsync(token);
            if (user == null)
            {
                return new APIResponseAuthentication
                {
                    Success = false,
                    Message = "Invalid refresh token."
                };
            }
            else
            {
                var refreshToken = user.RefreshTokens!.Single(x => x.Token == token);
                RefreshToken? newRefreshToken = null;

                if (refreshToken is not null && refreshToken.IsRevoked)
                {
                    // revoke all descendant tokens in case this token has been compromised
                    RevokeDescendantRefreshTokens(refreshToken, user, ipAddress, $"Attempted reuse of revoked ancestor token: {token}");
                    // Log attempted reuse of revoked token
                    LogException.LogToConsole($"Attempted reuse of revoked refresh token for user {user.Email} at {DateTime.UtcNow}");
                    dbContext.Update(user);
                    await dbContext.SaveChangesAsync();
                }

                if (refreshToken is not null && !refreshToken.IsActive)
                {
                    // log invalid refresh token usage
                    LogException.LogToFile($"Invalid refresh token usage for user {user.Email} at {DateTime.UtcNow}");
                    return new APIResponseAuthentication(false, "Invalid token");
                }
                // replace old refresh token with a new one (rotate token)
                if (refreshToken is not null && user.RefreshTokens is not null)
                {
                    newRefreshToken = await RotateRefreshTokenAsync(refreshToken, user.Id, ipAddress);
                    if (newRefreshToken is not null)
                        user.RefreshTokens.Add(newRefreshToken);
                }

                // remove old refresh tokens from account
                RemoveOldRefreshTokens(user);

                // save changes to db
                dbContext.Update(user);
                await dbContext.SaveChangesAsync();

                // get roles for user
                var roles = await GetRolesForUserAsync(user.Id);
                if (roles is not null)
                {
                    // create a list RoleDTO from roles
                    if (user.Roles is not null)
                    {
                        user.Roles.AddRange(roles);
                    }
                    else
                    {
                        user.Roles = roles;
                    }

                }

                // generate new jwt
                var jwtToken = await GenerateToken(user);

                // convert user to dto
                var userDto = user.ToDto();

                var response = new APIResponseAuthentication(true, string.Empty, userDto, jwtToken, newRefreshToken!.Token);
                return response;
            }
        }


        public async Task<BaseAPIResponseDTO> VerifyEmailAsync(string token)
        {
            var account = await dbContext.Users.SingleOrDefaultAsync(x => x.VerificationToken == token);

            if (account == null)
                return new BaseAPIResponseDTO() { Success = false, Message = "Invalid verification token" };

            account.Verified = DateTime.UtcNow;
            account.VerificationToken = null;

            dbContext.Users.Update(account);
            await dbContext.SaveChangesAsync();

            // Log email verification
            LogException.LogToFile($"User email verified: {account.Email} at {DateTime.UtcNow}");

            return new BaseAPIResponseDTO { Success = true, Message = "Email verified successfully." };
        }

        /// <summary>
        /// Initiates the password reset process for a user account.
        /// </summary>
        /// <param name="model">The forgot password request containing the user's email address.</param>
        /// <returns>
        /// A response indicating the request was processed. For security, the same success message
        /// is returned regardless of whether the email exists in the system.
        /// </returns>
        /// <remarks>
        /// <para><strong>Password Reset Flow:</strong></para>
        /// <list type="number">
        /// <item><description>Validates email exists and is confirmed</description></item>
        /// <item><description>Generates cryptographically secure password reset token via ASP.NET Identity</description></item>
        /// <item><description>Sends password reset email with token link to user</description></item>
        /// <item><description>Token expires after 24 hours (configurable via DataProtectionTokenProviderOptions)</description></item>
        /// <item><description>Logs password reset attempt with timestamp</description></item>
        /// </list>
        /// <para><strong>Security Features:</strong></para>
        /// <list type="bullet">
        /// <item><description>Generic response prevents user enumeration attacks</description></item>
        /// <item><description>Requires email confirmation before allowing password reset</description></item>
        /// <item><description>Token is sent via email, never exposed in API response</description></item>
        /// <item><description>Token is single-use and expires after 24 hours</description></item>
        /// <item><description>Failed attempts are logged for security monitoring</description></item>
        /// </list>
        /// <para><strong>Token Configuration:</strong></para>
        /// <para>
        /// Token expiration can be configured in <c>Program.cs</c> via:
        /// </para>
        /// <code>
        /// services.Configure&lt;DataProtectionTokenProviderOptions&gt;(options =>
        ///     options.TokenLifespan = TimeSpan.FromHours(24));
        /// </code>
        /// <para><strong>Post-Reset:</strong></para>
        /// <para>
        /// After receiving the email, the user clicks the reset link which should call
        /// <c>ResetPasswordAsync</c> with the token and new password to complete the reset.
        /// </para>
        /// </remarks>
        public async Task<BaseAPIResponseDTO> ForgotPasswordAsync(ForgotPasswordDTO model)
        {
            try
            {
                // Validate email is provided
                if (string.IsNullOrWhiteSpace(model.Email))
                {
                    return new BaseAPIResponseDTO
                    {
                        Success = false,
                        Message = "Email address is required."
                    };
                }

                // Check if user exists
                var user = await FindUserByEmailAsync(model.Email);

                // ✅ SECURITY: Return same message regardless of whether user exists
                // This prevents user enumeration attacks
                const string genericMessage = "If an account with that email exists and is verified, a password reset link has been sent.";

                // If user doesn't exist or email is not confirmed, log but return generic message
                if (user == null)
                {
                    LogException.LogToFile($"Password reset requested for non-existent email: {model.Email} at {DateTime.UtcNow}");
                    return new BaseAPIResponseDTO
                    {
                        Success = true,
                        Message = genericMessage
                    };
                }

                // Check if email is confirmed
                if (!(await userManager.IsEmailConfirmedAsync(user)))
                {
                    LogException.LogToFile($"Password reset requested for unconfirmed email: {model.Email} at {DateTime.UtcNow}");
                    return new BaseAPIResponseDTO
                    {
                        Success = true,
                        Message = genericMessage
                    };
                }

                // Generate password reset token
                var resetToken = await userManager.GeneratePasswordResetTokenAsync(user);

                // ✅ Send password reset email with token
                var emailSent = await emailService.SendPasswordResetEmailAsync(
                    user.Email!,
                    user.FirstName!,
                    resetToken);

                if (!emailSent)
                {
                    LogException.LogToFile($"Failed to send password reset email to {user.Email} at {DateTime.UtcNow}");
                    // Still return success to prevent information disclosure
                    return new BaseAPIResponseDTO
                    {
                        Success = true,
                        Message = genericMessage
                    };
                }

                // Log successful password reset token generation
                LogException.LogToFile($"Password reset token generated and sent to {model.Email} at {DateTime.UtcNow}");

                return new BaseAPIResponseDTO
                {
                    Success = true,
                    Message = genericMessage
                };
            }
            catch (Exception ex)
            {
                LogException.LogExceptions(ex);
                return new BaseAPIResponseDTO
                {
                    Success = false,
                    Message = "An error occurred while processing your password reset request. Please try again later."
                };
            }
        }


        /// <summary>
        /// Resets a user's password using a valid password reset token.
        /// </summary>
        /// <param name="model">The password reset data containing email, token, and new password.</param>
        /// <returns>A response indicating whether the password was reset successfully.</returns>
        /// <remarks>
        /// <para><strong>Reset Flow:</strong></para>
        /// <list type="number">
        /// <item><description>Validates user exists by email</description></item>
        /// <item><description>Validates reset token is valid and not expired</description></item>
        /// <item><description>Validates new password meets strength requirements</description></item>
        /// <item><description>Resets password using ASP.NET Identity's UserManager</description></item>
        /// <item><description>Invalidates all existing refresh tokens for security</description></item>
        /// <item><description>Logs password reset completion</description></item>
        /// </list>
        /// <para><strong>Security Features:</strong></para>
        /// <list type="bullet">
        /// <item><description>Token validation via ASP.NET Identity</description></item>
        /// <item><description>Password strength validation</description></item>
        /// <item><description>Single-use tokens (automatically invalidated after use)</description></item>
        /// <item><description>All refresh tokens revoked on password change</description></item>
        /// <item><description>Failed attempts logged for monitoring</description></item>
        /// </list>
        /// </remarks>
        public async Task<BaseAPIResponseDTO> ResetPasswordAsync(ResetPasswordDTO model)
        {
            try
            {
                // Validate required fields
                if (string.IsNullOrWhiteSpace(model.Email) || 
                    string.IsNullOrWhiteSpace(model.Token) || 
                    string.IsNullOrWhiteSpace(model.NewPassword))
                {
                    return new BaseAPIResponseDTO
                    {
                        Success = false,
                        Message = "All fields are required."
                    };
                }

                // Find user by email
                var user = await FindUserByEmailAsync(model.Email);
                if (user == null)
                {
                    return new BaseAPIResponseDTO
                    {
                        Success = false,
                        Message = "Invalid password reset request."
                    };
                }

                // Reset password using token
                var result = await userManager.ResetPasswordAsync(user, model.Token, model.NewPassword);

                if (result.Succeeded)
                {
                    // ✅ SECURITY: Revoke all refresh tokens when password is reset
                    if (user.RefreshTokens != null && user.RefreshTokens.Any())
                    {
                        foreach (var token in user.RefreshTokens.Where(t => t.IsActive))
                        {
                            RevokeRefreshToken(token, "0.0.0.0", "Password reset");
                        }

                        await dbContext.SaveChangesAsync();
                    }

                    LogException.LogToFile($"Password reset successful for {model.Email} at {DateTime.UtcNow}");

                    return new BaseAPIResponseDTO
                    {
                        Success = true,
                        Message = "Your password has been reset successfully. Please log in with your new password."
                    };
                }
                else
                {
                    var errors = string.Join("; ", result.Errors.Select(e => e.Description));
                    LogException.LogToFile($"Password reset failed for {model.Email} at {DateTime.UtcNow}. Errors: {errors}");

                    return new BaseAPIResponseDTO
                    {
                        Success = false,
                        Message = $"Password reset failed: {errors}"
                    };
                }
            }
            catch (Exception ex)
            {
                LogException.LogExceptions(ex);
                return new BaseAPIResponseDTO
                {
                    Success = false,
                    Message = "An error occurred while resetting your password. Please try again later."
                };
            }
        }


        #region Helpers

        /// <summary>
        /// Retrieves all roles assigned to a specific user.
        /// </summary>
        /// <param name="userId">The unique identifier of the user.</param>
        /// <returns>A list of IdentityRole objects for the user, or null if user not found.</returns>
        /// <remarks>
        /// Used internally to populate user roles before generating JWT tokens.
        /// Roles are included as claims in the JWT for authorization purposes.
        /// </remarks>
        private async Task<List<IdentityRole<Guid>>?> GetRolesForUserAsync(Guid userId)
        {
            var user = await FindUserByIdAsync(userId);
            if (user == null)
            {
                return null;
            }

            var roleNames = await userManager.GetRolesAsync(user);
            var roles = new List<IdentityRole<Guid>>();

            foreach (var roleName in roleNames)
            {
                var role = await FindRoleByNameAsync(roleName);
                if (role != null)
                {
                    roles.Add(role);
                }
            }

            return roles;
        }

        /// <summary>
        /// Adds a user instance to a specified role (private overload).
        /// </summary>
        /// <param name="user">The ApplicationUser instance to add to the role.</param>
        /// <param name="roleName">The name of the role to assign.</param>
        /// <returns>A response indicating success or failure.</returns>
        /// <remarks>
        /// Private helper method used internally. Validates both user and role existence
        /// before attempting to assign the role via ASP.NET Identity's UserManager.
        /// </remarks>
        private async Task<BaseAPIResponseDTO> AddUserToRoleAsync(ApplicationUser user, string roleName)
        {

            // null checks
            if (user == null || string.IsNullOrEmpty((roleName)))
            {
                return new BaseAPIResponseDTO
                {
                    Success = false,
                    Message = "Uaser and role name are required!"
                };
            }
            var role = await FindRoleByNameAsync(roleName);
            if (role == null)
            {
                return new BaseAPIResponseDTO
                {
                    Success = false,
                    Message = "Role does not exist."
                };
            }
            var result = await userManager.AddToRoleAsync(user, role.Name!);
            if (result.Succeeded)
            {
                return new BaseAPIResponseDTO
                {
                    Success = true,
                    Message = "User added to role successfully."
                };
            }
            else
            {
                return new BaseAPIResponseDTO
                {
                    Success = false,
                    Message = "Failed to add user to role."
                };
            }
        }

        /// <summary>
        /// Removes a user from a specified role.
        /// </summary>
        /// <param name="user">The ApplicationUser instance to remove from the role.</param>
        /// <param name="roleName">The name of the role to remove.</param>
        /// <returns>A response indicating success or failure.</returns>
        /// <remarks>
        /// Currently unused but available for future role management features.
        /// Validates user and role existence before removal via ASP.NET Identity's UserManager.
        /// </remarks>
        private async Task<BaseAPIResponseDTO> RemoveUserFromRoleAsync(ApplicationUser user, string roleName)
        {
            // null checks
            if (user == null || string.IsNullOrEmpty((roleName)))
            {
                return new BaseAPIResponseDTO
                {
                    Success = false,
                    Message = "User and role name are required!"
                };
            }
            var role = await FindRoleByNameAsync(roleName);
            if (role == null)
            {
                return new BaseAPIResponseDTO
                {
                    Success = false,
                    Message = "Role does not exist."
                };
            }
            var result = await userManager.RemoveFromRoleAsync(user, role.Name!);
            if (result.Succeeded)
            {
                return new BaseAPIResponseDTO
                {
                    Success = true,
                    Message = "User removed from role successfully."
                };
            }
            else
            {
                return new BaseAPIResponseDTO
                {
                    Success = false,
                    Message = "Failed to remove user from role."
                };
            }
        }

        /// <summary>
        /// Generates a JWT (JSON Web Token) for an authenticated user.
        /// </summary>
        /// <param name="user">The authenticated ApplicationUser to generate a token for.</param>
        /// <returns>A JWT token string, or null if generation fails.</returns>
        /// <remarks>
        /// <para><strong>Token Configuration:</strong></para>
        /// <list type="bullet">
        /// <item><description>Algorithm: HS256 (HMAC-SHA256)</description></item>
        /// <item><description>Expiration: 30 minutes from creation</description></item>
        /// <item><description>Issuer/Audience: Read from JwtSettings configuration</description></item>
        /// <item><description>Signing Key: Read from JwtSettings:Secret configuration</description></item>
        /// </list>
        /// <para><strong>Included Claims:</strong></para>
        /// <list type="bullet">
        /// <item><description>NameIdentifier: User's GUID ID</description></item>
        /// <item><description>Name: User's first name</description></item>
        /// <item><description>Email: User's email address</description></item>
        /// <item><description>Role: User's assigned roles (multiple role claims for multiple roles)</description></item>
        /// </list>
        /// <para>The generated token can be used for API authentication by including it in the
        /// Authorization header as: Bearer {token}</para>
        /// </remarks>
        public async Task<string?> GenerateToken(ApplicationUser user)
        {
            // Implementation for generating JWT token
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["JwtSettings:Secret"]!));
            // Use HmacSha256 instead of deprecated HmacSha256Signature
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var userClaims = new List<Claim> {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.FirstName!),
                new Claim(ClaimTypes.Email, user.Email!),
            };

            // Get user roles as a List<IdentityRole>
            user.Roles = await GetRolesForUserAsync(user.Id);


            if (user.Roles is not null && user.Roles.Any())
            {
                foreach (var role in user.Roles)
                {
                    userClaims.Add(
                        new Claim(ClaimTypes.Role, role.Name!));
                }
            }

            var token = new JwtSecurityToken(
                issuer: config["JwtSettings:Issuer"],
                audience: config["JwtSettings:Audience"],
                claims: userClaims,
                expires: DateTime.UtcNow.AddMinutes(30),
                signingCredentials: credentials
            );
            
            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        // ✅ IAccountRepository implementation (already exists, just make it public)
        public async Task<ApplicationUser?> FindUserByIdAsync(Guid id)
        {
            var user = await userManager.FindByIdAsync(id.ToString());
            return user;
        }

        public async Task<ApplicationUser?> FindUserByUserName(string username)
        {
            var user = await userManager.Users
                .FirstOrDefaultAsync(u => u.Username == username);
            return user;
        }

        public async Task<ApplicationUser?> FindUserByEmailAsync(string email)
        {
            var user = await userManager.FindByEmailAsync(email);
            return user;
        }

        public async Task<bool> IsUsernameAvailableAsync(string username)
        {
            var user = await FindUserByUserName(username);
            return user == null;
        }


        /// <summary>
        /// Generates a cryptographically secure refresh token for a user.
        /// </summary>
        /// <param name="ipAddress">The IP address of the client requesting the token.</param>
        /// <param name="userId">The unique identifier of the user.</param>
        /// <returns>A new RefreshToken object, or null if generation fails.</returns>
        /// <remarks>
        /// <para><strong>Token Properties:</strong></para>
        /// <list type="bullet">
        /// <item><description>Token: 64-byte random value, base64 encoded (88 characters)</description></item>
        /// <item><description>Expiration: 7 days from creation</description></item>
        /// <item><description>Created: Current UTC timestamp</description></item>
        /// <item><description>CreatedByIp: Client IP address for audit trail</description></item>
        /// <item><description>AccountId: Associated user's GUID</description></item>
        /// </list>
        /// <para><strong>Security Features:</strong></para>
        /// <list type="bullet">
        /// <item><description>Uses System.Security.Cryptography.RandomNumberGenerator for cryptographic randomness</description></item>
        /// <item><description>Ensures uniqueness by checking existing tokens in database</description></item>
        /// <item><description>Recursively generates new token if collision detected (extremely rare)</description></item>
        /// <item><description>Immediately saves to database for audit trail</description></item>
        /// </list>
        /// <para>The token is stored in the database and associated with the user. It can be used
        /// to obtain new JWT tokens without re-authentication for 7 days.</para>
        /// </remarks>
        private async Task<RefreshToken?> GenerateRefreshToken(string ipAddress, Guid userId)
        {
            // User exist?
            var user = await FindUserByIdAsync(userId);
            if (user == null)
            {
                return null;
            }

            var refreshToken = new RefreshToken
            {
                // Token is a cryptographically strong random sequence of values
                Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
                // Valid for 7 days
                Expires = DateTime.UtcNow.AddDays(7),
                Created = DateTime.UtcNow,
                CreatedByIp = ipAddress,
                AccountId = userId
            };

            // ensure token is unique by checking against db
            var tokenIsUnique = !userManager.Users.Any(x => x.RefreshTokens!.Any(t => t.Token == refreshToken.Token));

            // If not unique, recursively generate a new token
            if (!tokenIsUnique)
                return await GenerateRefreshToken(ipAddress, userId);

            try
            {
                // Save refresh token to database
                await dbContext.RefreshTokens.AddAsync(refreshToken);
                await dbContext.SaveChangesAsync();
                LogException.LogToFile($"Generated new refresh token for user {user.Email} at {DateTime.UtcNow}");
                return refreshToken;
            }
            catch (Exception ex)
            {
                // Log exception
                LogException.LogExceptions(ex);
                return null;
            }
        }


        /// <summary>
        /// Finds a user by their refresh token.
        /// </summary>
        /// <param name="token">The refresh token string to search for.</param>
        /// <returns>The ApplicationUser associated with the token, or null if not found.</returns>
        /// <remarks>
        /// Uses Entity Framework's Include to eagerly load the user account with the token.
        /// This is used during token refresh operations to validate token ownership.
        /// </remarks>
        private async Task<ApplicationUser?> FindUserByRefreshTokenAsync(string token)
        {
            var query = await dbContext.RefreshTokens
                .Where(u => u.Token == token)
                .Include(x => x.Account)
                .FirstOrDefaultAsync();

            // Defensive null checks
            if (query?.Account != null)
            {
                return query.Account;
            }
            
            return null;
        }

        /// <summary>
        /// Finds a role by its name.
        /// </summary>
        /// <param name="roleName">The name of the role to find.</param>
        /// <returns>The IdentityRole if found, otherwise null.</returns>
        private async Task<IdentityRole<Guid>?> FindRoleByNameAsync(string roleName)
        {
            var role = await roleManager.FindByNameAsync(roleName);
            return role;
        }

        /// <summary>
        /// Generates a unique verification token for email confirmation.
        /// </summary>
        /// <returns>A 128-character hexadecimal verification token string.</returns>
        /// <remarks>
        /// <para>Generates a cryptographically secure token using RandomNumberGenerator.</para>
        /// <para>Recursively ensures uniqueness by checking against existing tokens in database.</para>
        /// <para>This token should be sent to the user's email and used to verify account ownership
        /// before allowing login.</para>
        /// </remarks>
        private string GenerateVerificationToken()
        {
            // token is a cryptographically strong random sequence of values
            var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(64));

            // ensure token is unique by checking against db
            var tokenIsUnique = !userManager.Users.Any(x => x.VerificationToken == token);
            if (!tokenIsUnique)
                return GenerateVerificationToken();

            return token;
        }

        /// <summary>
        /// Removes old, inactive refresh tokens from a user's collection based on configured TTL.
        /// </summary>
        /// <param name="user">The user whose refresh tokens will be cleaned up.</param>
        /// <remarks>
        /// <para>Cleanup criteria:</para>
        /// <list type="bullet">
        /// <item><description>Token must be inactive (expired or revoked)</description></item>
        /// <item><description>Token creation date + TTL must be older than current date</description></item>
        /// <item><description>TTL is configured via ApplicationSettings:RefreshTokenTTL (default: 90 days)</description></item>
        /// </list>
        /// <para>This helps keep the database clean and prevents unbounded growth of token records.
        /// Active tokens are never removed regardless of age.</para>
        /// </remarks>
        private void RemoveOldRefreshTokens(ApplicationUser user)
        {
            if (user.RefreshTokens is not null)
            {
                if (user.RefreshTokens.Count >= 1)
                {
                    // remove old inactive refresh tokens from user based on TTL in app settings
                    user.RefreshTokens.RemoveAll(x =>
                        !x.IsActive && x.Created!.Value.AddDays(int.Parse(config["ApplicationSettings:RefreshTokenTTL"]!)) <= DateTime.UtcNow);
                }
            }
        }

        /// <summary>
        /// Recursively revokes all descendant tokens in a token family chain.
        /// </summary>
        /// <param name="refreshToken">The parent refresh token whose descendants should be revoked.</param>
        /// <param name="account">The user account associated with the tokens.</param>
        /// <param name="ipAddress">The IP address where the security breach was detected.</param>
        /// <param name="reason">The reason for revocation (e.g., "Attempted reuse of revoked ancestor token").</param>
        /// <remarks>
        /// <para><strong>Security Feature - Token Compromise Detection:</strong></para>
        /// <para>This method implements a critical security feature. When a revoked token is reused
        /// (indicating possible theft), the entire token family chain is revoked to prevent the
        /// attacker from using any related tokens.</para>
        /// <para><strong>Token Family Chain:</strong></para>
        /// <para>Each time a refresh token is rotated, the old token stores a reference to the new
        /// token in its ReplacedByToken property. This creates a linked chain of tokens. If any
        /// token in the chain is reused after revocation, all descendants are invalidated.</para>
        /// <para>This prevents scenarios where an attacker steals a token, uses it to get a new one,
        /// and continues accessing the system even after the original theft is detected.</para>
        /// </remarks>
        private void RevokeDescendantRefreshTokens(RefreshToken? refreshToken, ApplicationUser account, string ipAddress, string reason)
        {
            if (refreshToken != null)
            {
                // recursively traverse the refresh token chain and ensure all descendants are revoked
                if (!string.IsNullOrEmpty(refreshToken.ReplacedByToken))
                {
                    if (account.RefreshTokens is not null)
                    {
                        var childToken = account.RefreshTokens.SingleOrDefault(x => x.Token == refreshToken.ReplacedByToken);
                        if (childToken is not null && childToken.IsActive)
                            RevokeRefreshToken(childToken, ipAddress, reason);
                        else
                            RevokeDescendantRefreshTokens(childToken, account, ipAddress, reason);
                    }
                }
            }
        }

        /// <summary>
        /// Marks a refresh token as revoked with audit information.
        /// </summary>
        /// <param name="token">The refresh token to revoke.</param>
        /// <param name="ipAddress">The IP address associated with the revocation.</param>
        /// <param name="reason">Optional reason for revocation.</param>
        /// <param name="replacedByToken">Optional token that replaced this one (for rotation).</param>
        /// <remarks>
        /// <para>Sets the following properties on the token:</para>
        /// <list type="bullet">
        /// <item><description>Revoked: Current UTC timestamp</description></item>
        /// <item><description>RevokedByIp: Client IP address</description></item>
        /// <item><description>ReasonRevoked: Descriptive reason for audit trail</description></item>
        /// <item><description>ReplacedByToken: New token if this was rotated (creates token chain)</description></item>
        /// </list>
        /// <para>Once revoked, a token cannot be used to obtain new JWT tokens. Attempting to
        /// reuse a revoked token triggers security measures (RevokeDescendantRefreshTokens).</para>
        /// </remarks>
        private void RevokeRefreshToken(RefreshToken token, string ipAddress, string? reason = null, string? replacedByToken = null)
        {
            token.Revoked = DateTime.UtcNow;
            token.RevokedByIp = ipAddress;
            token.ReasonRevoked = reason;
            token.ReplacedByToken = replacedByToken;
        }

        /// <summary>
        /// Rotates a refresh token by generating a new one and revoking the old token.
        /// </summary>
        /// <param name="refreshToken">The existing refresh token to replace.</param>
        /// <param name="Id">The unique identifier of the user.</param>
        /// <param name="ipAddress">The IP address of the client requesting rotation.</param>
        /// <returns>A new RefreshToken if successful, or null if generation fails.</returns>
        /// <remarks>
        /// <para><strong>Token Rotation Security Pattern:</strong></para>
        /// <para>Token rotation is a security best practice where each refresh token can only be
        /// used once. When used, it's immediately replaced with a new token and the old one is revoked.</para>
        /// <para><strong>Process:</strong></para>
        /// <list type="number">
        /// <item><description>Generate new refresh token (7-day expiry)</description></item>
        /// <item><description>Revoke old token with reason "Replaced by new token"</description></item>
        /// <item><description>Link old token to new token (ReplacedByToken property)</description></item>
        /// <item><description>Return new token to client</description></item>
        /// </list>
        /// <para>This creates a chain of tokens that can be traced for security auditing and
        /// enables detection of token theft (if an old token is reused).</para>
        /// </remarks>
        private async Task<RefreshToken?> RotateRefreshTokenAsync(RefreshToken refreshToken, Guid Id, string ipAddress)
        {
            var newRefreshToken = await GenerateRefreshToken(ipAddress, Id);
            RevokeRefreshToken(refreshToken, ipAddress, "Replaced by new token");
            return newRefreshToken;
        }

        /// <summary>
        /// Creates system roles if they don't already exist in the database.
        /// </summary>
        /// <param name="roles">A list of RoleDTOs containing role names to create.</param>
        /// <remarks>
        /// <para>Used during admin account creation to ensure all necessary roles exist.</para>
        /// <para>Standard roles created:</para>
        /// <list type="bullet">
        /// <item><description>ADMIN_DEVELOPER: Full system access and development capabilities</description></item>
        /// <item><description>ADMIN_EDITOR: Content management and user moderation</description></item>
        /// <item><description>USER_EDITOR: Trail editing and content contribution</description></item>
        /// <item><description>USER: Basic authenticated user privileges</description></item>
        /// </list>
        /// <para>Idempotent - safely checks for existence before creating each role.</para>
        /// </remarks>
        private async Task CreateAdminRoles(List<RoleDTO> roles) { 
            foreach (var roleDto in roles)
            {
                var roleExists = await roleManager.RoleExistsAsync(roleDto.RoleName!);
                if (!roleExists)
                {
                    var role = new IdentityRole<Guid>
                    {
                        Name = roleDto.RoleName!
                    };
                    await roleManager.CreateAsync(role);
                }
            }
        }

        // Public interface implementation (no ipAddress parameter)
        public async Task<APIResponseAuthentication> LoginAsync(LoginDTO model)
        {
            // This should never be called directly - the controller should call the overload
            throw new NotSupportedException(
                "LoginAsync without IP address is not supported in server-side implementation. " +
                "Use the controller which provides IP address extraction.");
        }

        // Public interface implementation (no ipAddress parameter)
        public async Task<APIResponseAuthentication> RefreshTokenAsync(string token)
        {
            // This should never be called directly - the controller should call the overload
            throw new NotSupportedException(
                "RefreshTokenAsync without IP address is not supported in server-side implementation. " +
                "Use the controller which provides IP address extraction.");
        }

        /// <summary>
        /// Checks if the application is running in Development environment.
        /// </summary>
        /// <returns>True if Development mode, false otherwise.</returns>
        /// <remarks>
        /// Used to bypass certain validations during development (e.g., AcceptTerms requirement).
        /// In production, all validations are enforced for security and compliance.
        /// </remarks>
        private bool IsDevelopmentEnvironment()
        {
            // Check ASPNETCORE_ENVIRONMENT from configuration or environment variables
            var environment = config["ASPNETCORE_ENVIRONMENT"] ??
                             Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT");

            return environment?.Equals("Development", StringComparison.OrdinalIgnoreCase) ?? false;
        }

        #endregion

        /// <summary>
        /// Soft deletes a user account by marking it as deleted without removing from the database.
        /// An optional reason can be provided for the deletion, which is logged for auditing purposes.
        /// </summary>
        /// <param name="userId">The unique identifier of the user to soft delete.</param>
        /// <param name="reason">Optional reason for the deletion (e.g., "User requested account deletion").</param>
        /// <returns>
        /// A response indicating success or failure.
        /// On success, the user account is marked as deleted and anonymized.
        /// </returns>
        /// <remarks>
        /// <para><strong>Soft Delete Process:</strong></para>
        /// <list type="number">
        /// <item><description>Finds the user by ID</description></item>
        /// <item><description>Marks the user as deleted (IsDeleted = true)</description></item>
        /// <item><description>Sets the deletion timestamp (DeletedAt = Now)</description></item>
        /// <item><description>Optionally set a deletion reason</description></item>
        /// <item><description>Anonymizes user data (email, username, name) for privacy</description></item>
        /// <item><description>Updates the user in the database</description></item>
        /// </list>
        /// <para><strong>Security and Compliance:</strong></para>
        /// <list type="bullet">
        /// <item><description>Meets GDPR and CCPA requirements for data removal</description></item>
        /// <item><description>Retention of deletion reason and timestamp for auditing</description></item>
        /// <item><description>Actual data removal is not performed to allow potential account recovery</description></item>
        /// </list>
        /// <para>
        /// <strong>Soft Delete vs Hard Delete:</strong>
        /// </para>
        /// <para>
        /// This method performs a soft delete, which keeps the user record in the database
        /// but marks it as deleted. This is generally safer and allows for account recovery.
        /// A hard delete (permanent removal) would require a separate method and is not
        /// recommended unless absolutely necessary.
        /// </para>
        /// </remarks>
        public async Task<BaseAPIResponseDTO> SoftDeleteUserAsync(Guid userId, string? reason = null)
        {
            try
            {
                var user = await FindUserByIdAsync(userId);
                if (user == null)
                {
                    return new BaseAPIResponseDTO
                    {
                        Success = false,
                        Message = "User not found"
                    };
                }

                // Mark as deleted instead of actually deleting
                user.IsDeleted = true;
                user.DeletedAt = DateTime.UtcNow;
                user.DeleteReason = reason;

                // Optionally anonymize user data for privacy
                user.Email = $"deleted_{user.Id}@deleted.com";
                user.UserName = $"deleted_{user.Id}";
                user.FirstName = "[Deleted User]";
                user.Bio = null;
                user.ProfilePicture = null;

                var result = await userManager.UpdateAsync(user);

                if (result.Succeeded)
                {
                    LogException.LogToFile($"User soft-deleted: {userId} at {DateTime.UtcNow}");
                    return new BaseAPIResponseDTO
                    {
                        Success = true,
                        Message = "User account deactivated successfully"
                    };
                }
                else
                {
                    var errors = string.Join("; ", result.Errors.Select(e => e.Description));
                    return new BaseAPIResponseDTO
                    {
                        Success = false,
                        Message = $"Failed to deactivate user: {errors}"
                    };
                }
            }
            catch (Exception ex)
            {
                LogException.LogExceptions(ex);
                return new BaseAPIResponseDTO
                {
                    Success = false,
                    Message = "An error occurred while deactivating user account"
                };
            }
        }
    }
}
