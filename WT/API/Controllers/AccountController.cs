using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using System.Security.Claims;
using System.ComponentModel.DataAnnotations;
using WT.Application.APIServiceLogs;
using WT.Application.Contracts;
using WT.Application.DTO.Request.Account;
using WT.Application.DTO.Response;
using WT.Application.Services;
using WT.Domain.Entity;
using WT.Infrastructure.Data;
using WT.Infrastructure.Repositories;
using static WT.Application.Extensions.Constants;

namespace API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly IAccountRepository _accountRepository; // ✅ Use IAccountRepository
        private readonly AppDbContext _dbContext;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IFileStorageService _fileStorageService;
        private readonly IConfiguration _configuration;
        private readonly IMemoryCache _cache;
        private readonly IEmailService _emailService;

        public AccountController(
            IAccountRepository accountRepository, // ✅ Inject IAccountRepository
            AppDbContext dbContext,
            IFileStorageService fileStorageService,
            IConfiguration configuration,
            UserManager<ApplicationUser> userManager,
            IMemoryCache cache,
            IEmailService emailService)
        {
            _accountRepository = accountRepository;
            _dbContext = dbContext;
            _userManager = userManager;
            _fileStorageService = fileStorageService;
            _configuration = configuration;
            _cache = cache;
            _emailService = emailService;
        }

        [HttpGet]
        public async Task<ActionResult> CreateAdmin()
        {
            await _accountRepository.CreateAdmin();
            return Ok();
        }

        // Diagnostic endpoint to send a test email via configured email provider (SendGrid)
        // Example request body: { "to": "you@example.com", "type": "verification" }
        [HttpPost("diagnostic/send-test-email")]
        [AllowAnonymous]
        public async Task<IActionResult> SendTestEmail([FromBody] TestEmailRequest? model)
        {
            if (model == null || string.IsNullOrWhiteSpace(model.To))
            {
                return BadRequest(new { Success = false, Message = "Recipient (to) is required" });
            }

            try
            {
                bool sent = false;

                // Use the configured email service to send a simple verification or reset email
                if (string.Equals(model.Type, "reset", StringComparison.OrdinalIgnoreCase))
                {
                    var token = model.Token ?? "test-reset-token";
                    sent = await _emailService.SendPasswordResetEmailAsync(model.To, model.FirstName ?? "Tester", token);
                }
                else
                {
                    var token = model.Token ?? "test-verification-token";
                    sent = await _emailService.SendVerificationEmailAsync(model.To, model.FirstName ?? "Tester", token);
                }

                if (sent)
                    return Ok(new { Success = true, Message = "Test email queued/sent" });

                return StatusCode(500, new { Success = false, Message = "Failed to send test email (provider error)" });
            }
            catch (Exception ex)
            {
                LogException.LogExceptions(ex);
                return StatusCode(500, new { Success = false, Message = "Exception while sending test email" });
            }
        }

        [AllowAnonymous]
        [HttpPost("identity/create")]
        public async Task<ActionResult<BaseAPIResponseDTO>> CreateAccount(RegisterDTO model)
        {
            if(!ModelState.IsValid)
                return BadRequest(new BaseAPIResponseDTO { Success = false, Message = "Invalid Registration Form" });


            return await _accountRepository.RegisterAsync(model);
        }

        [AllowAnonymous]
        [HttpPost("identity/login")]
        public async Task<ActionResult<APIResponseAuthentication>> LoginAccount(LoginDTO model)
        {
            if(!ModelState.IsValid)
                return BadRequest(new APIResponseAuthentication { Success = false, Message = "Password or Email Address is incorrect" });
            
            // Cast to concrete type to access internal method
            var wtAccount = _accountRepository as WTAccount;
            if (wtAccount == null)
            {
                return StatusCode(500, new APIResponseAuthentication 
                { 
                    Success = false, 
                    Message = "Service configuration error" 
                });
            }

            var result = await wtAccount.LoginWithIpAsync(model, ipAddress());
            if (result.Success) {
                SetTokenCookie(result.RefreshToken!);
                return Ok(result);
            }
            else
            {
                return BadRequest(result);
            }
        }

        [HttpPost("identity/refresh-token")]
        [AllowAnonymous] // ✅ IMPORTANT: Must allow anonymous access
        public async Task<ActionResult<APIResponseAuthentication>> RefreshToken(RefreshTokenDTO model)
        {
            Console.WriteLine($"🔄 Refresh token request received. Token: {model?.Token?.Substring(0, Math.Min(20, model?.Token?.Length ?? 0))}...");
            
            if (string.IsNullOrEmpty(model.Token))
            {
                Console.WriteLine("❌ Refresh token is empty");
                return BadRequest(new APIResponseAuthentication()
                {
                    JwtToken = string.Empty,
                    RefreshToken = null!,
                    Success = false,
                    User = null!,
                    Message = "RefreshToken not found."
                });
            }

            // Cast to concrete type to access internal method
            var wtAccount = _accountRepository as WTAccount;
            if (wtAccount == null)
            {
                Console.WriteLine("❌ Service configuration error");
                return StatusCode(500, new APIResponseAuthentication 
                { 
                    Success = false, 
                    Message = "Service configuration error" 
                });
            }

            var result = await wtAccount.RefreshTokenWithIpAsync(model.Token, ipAddress());
            
            if (result.Success)
            {
                Console.WriteLine($"✅ Token refreshed successfully for user: {result.User?.Email}");
                SetTokenCookie(result.RefreshToken!);
                return Ok(result);
            }
            else
            {
                Console.WriteLine($"❌ Token refresh failed: {result.Message}");
                return BadRequest(new APIResponseAuthentication()
                {
                    JwtToken = string.Empty,
                    RefreshToken = null!,
                    Success = false,
                    User = null!,
                    Message = result.Message ?? "Refresh token request failed."
                });
            }
        }

        [AllowAnonymous]
        [HttpPost("varify-email")]
        public async Task<ActionResult<BaseAPIResponseDTO>> VarifyEmail(VerifyEmailDTO model)
        {
            if (!ModelState.IsValid) { return BadRequest(); }

            if (!ModelState.IsValid)
                return BadRequest(new BaseAPIResponseDTO { Success = false, Message = "Invalid Varification Form" });
            return await _accountRepository.VerifyEmailAsync(model.Token!);
        }

        // add register route
        [AllowAnonymous]
        [HttpPost("register")]
        [EnableRateLimiting("AuthPolicy")] // ✅ Strict rate limit
        public async Task<ActionResult<BaseAPIResponseDTO>> Register(RegisterDTO model)
        {
            if (!ModelState.IsValid)
                return BadRequest(new BaseAPIResponseDTO { Success = false, Message = "Invalid Registration Form" });
            return await _accountRepository.RegisterAsync(model);
        }

        /// <summary>
        /// Initiates password reset process.
        /// </summary>
        [HttpPost("forgot-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordDTO model)
        {
            var result = await _accountRepository.ForgotPasswordAsync(model);
            return result.Success ? Ok(result) : BadRequest(result);
        }

        /// <summary>
        /// Resets user password with valid token.  This method is for unauthenticated users.
        /// </summary>
        [HttpPost("reset-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordDTO model)
        {
            var result = await _accountRepository.ResetPasswordAsync(model);
            return result.Success ? Ok(result) : BadRequest(result);
        }

        // method to reset password for authenticated users
        [HttpPost("identity/reset-password-authenticated")]
        [Authorize]
        public async Task<IActionResult> AuthenticatedResetPassword([FromBody] AuthenticatedResetPasswordDTO model)
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId) || !Guid.TryParse(userId, out var userGuid))
            {
                return Unauthorized();
            }
            var result = await _accountRepository.AuthenticatedResetPasswordAsync(model, userId, ipAddress());
            return result.Success ? Ok(result) : BadRequest(result);
        }

        /// <summary>
        /// Uploads and sets a user's profile picture.
        /// 
        /// Flow and guarantees:
        ///1. Validate the incoming file using <see cref="ValidateUploadProfilePicture"/>.
        ///2. Upload the new image to the configured file storage (streamed).
        ///3. If upload succeeds, update the user's profile picture URL in the database.
        ///4. If the DB update succeeds, attempt to delete the previous profile picture (best-effort).
        ///5. If the DB update fails after a successful upload, attempt to delete the newly uploaded object
        /// to avoid orphaned files (compensating action).
        /// 
        /// Notes:
        /// - Uses a using-scoped stream for the uploaded file to avoid leaking resources.
        /// - Honors client disconnects via <c>HttpContext.RequestAborted</c> where feasible.
        /// - Does not delete the old file until the new URL is persisted to keep user data safe if upload fails.
        /// </summary>
        /// <param name="model">The upload DTO containing the file.</param>
        /// <returns>API response indicating success or failure.</returns>
        [HttpPost("upload-profile-picture")]
        [RequestFormLimits(MultipartBodyLengthLimit = FirebaseUploadConstants.MaxProfilePictureSize)]
        [Authorize]
        public async Task<IActionResult> UploadProfilePicture([FromForm] UpdateProfilePhotoDTO? model, CancellationToken cancellationToken)
        {
            string oldProfilePhotoUrl = string.Empty;

            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId) || !Guid.TryParse(userId, out var userGuid))
            {
                return Unauthorized();
            }

            // Validate file first
            var validationResponse = ValidateUploadProfilePicture(model);
            if (!validationResponse.Success)
            {
                // must be consistent with APIResponseUploadPhoto
                return BadRequest(new APIResponseUploadPhoto { Success = false, Message = validationResponse.Message });
            }

            // Cancellation token: prefer the explicit token from the client, but also observe HttpContext.RequestAborted
            var ct = cancellationToken.CanBeCanceled ? cancellationToken : HttpContext.RequestAborted;

            // Remember previous URL but don't delete it yet. We'll delete after new URL is persisted.
            var user = await _accountRepository.FindUserByIdAsync(userGuid);
            if (user != null && !string.IsNullOrEmpty(user.ProfilePicture))
            {
                oldProfilePhotoUrl = user.ProfilePicture;
            }

            //  TODO: If the user is null here should we be proceeding? Mind you, if we
            //  successfully retrieved the userId from the token, this should not happen.

            // Upload -> Persist -> Cleanup (delete old)
            string? newFileUrl = null;
            try
            {
                // Stream the file to the storage service. Ensure the stream is disposed.
                using var stream = model!.ProfilePhoto!.OpenReadStream();

                // If the client disconnected, abort early
                if (ct.IsCancellationRequested)
                {
                    return StatusCode(499, new APIResponseUploadPhoto { Success = false, Message = "Client disconnected" }); //499 Client Closed Request (non-standard)
                }

                newFileUrl = await _fileStorageService.UploadProfilePictureAsync(stream, model.ProfilePhoto.FileName, userGuid);

                if (string.IsNullOrEmpty(newFileUrl))
                {
                    return StatusCode(500, new APIResponseUploadPhoto { Success = false, Message = "Failed to upload profile picture" });
                }

                // Update DB with new URL
                var status = await _accountRepository.UpdateProfilePictureUrlAsync(userGuid, newFileUrl);
                if (!status.Success)
                {
                    // Compensating action: try to delete the newly uploaded file to avoid orphaned files
                    try
                    {
                        if (!string.IsNullOrEmpty(newFileUrl))
                        {
                            await _fileStorageService.DeleteFileAsync(newFileUrl);
                        }
                    }
                    catch (Exception ex)
                    {
                        // Log but don't mask the original failure
                        LogException.LogExceptions(ex);
                    }

                    return BadRequest(new APIResponseUploadPhoto { Success = false, Message = "Failed to update profile picture URL" });
                }

                // Invalidate navbar cache for this user so next request gets fresh profile picture
                try
                {
                    var cacheKey = $"navbarinfo:{userGuid}";
                    _cache.Remove(cacheKey);
                }
                catch (Exception ex)
                {
                    // Log but do not fail the request
                    LogException.LogExceptions(ex);
                }
                
                // At this point newFileUrl persisted. Attempt best-effort deletion of old file.
                if (!string.IsNullOrEmpty(oldProfilePhotoUrl))
                {
                    try
                    {
                        await _fileStorageService.DeleteFileAsync(oldProfilePhotoUrl);
                    }
                    catch (Exception ex)
                    {
                        // Log failure but do not block the successful response
                        LogException.LogExceptions(ex);
                    }
                }

                return Ok(new APIResponseUploadPhoto { Success = true, Message = "Profile picture updated successfully", PhotoUrl = newFileUrl });
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                // Client disconnected or request cancelled
                return StatusCode(499, new APIResponseUploadPhoto { Success = false, Message = "Request canceled" });
            }
            catch (Exception ex)
            {
                // If upload succeeded but we ended up here, attempt to delete new file
                if (!string.IsNullOrEmpty(newFileUrl))
                {
                    try
                    {
                        await _fileStorageService.DeleteFileAsync(newFileUrl);
                    }
                    catch (Exception cleanupEx)
                    {
                        LogException.LogExceptions(cleanupEx);
                    }
                }

                LogException.LogExceptions(ex);
                return StatusCode(500, new APIResponseUploadPhoto { Success = false, Message = "An error occurred while uploading profile picture" });
            }
        }


        /// <summary>
        /// Check if a profile username is available
        /// </summary>
        [HttpGet("profile-username/check/{profileUsername}")]
        [AllowAnonymous]
        public async Task<IActionResult> CheckProfileUsernameAvailability(string profileUsername)
        {
            if (string.IsNullOrWhiteSpace(profileUsername) || profileUsername.Length < 3)
            {
                return BadRequest(new { isAvailable = false, message = "Profile username must be at least 3 characters" });
            }

            // ✅ Call IAccountRepository method
            var isAvailable = await _accountRepository.IsProfileUsernameAvailableAsync(profileUsername);
            
            return Ok(new { isAvailable });
        }

        /// <summary>
        /// Get user profile by ProfileUsername (for profile URLs).  This is public info metadata. To
        /// keep the response ligth, we only return profile meta + counts (i.e. follower count, trail count, etc).
        /// The user's navigation properties (e.g., Trails, Comments) will be handled in other endpoints as needed.
        /// </summary>
        [HttpGet("user/{profileUsername}")]
        [AllowAnonymous]
        public async Task<IActionResult> GetUserByProfileUsername(string profileUsername, CancellationToken cancellationToken)
        {
            try 
            { 
                // Cancellation token: prefer the explicit token from the client, but also observe HttpContext.RequestAborted
                var ct = cancellationToken.CanBeCanceled ? cancellationToken : HttpContext.RequestAborted;

                // ✅ Call IAccountRepository method
                var user = await _accountRepository.GetUserProfileByUsernameAsync(profileUsername, ct);

                if (user == null)
                {
                    return NotFound(new BaseAPIResponseDTO { Success = false, Message = "User not found" });
                }

                if (user.FailuerCode.HasValue)
                {
                    if (user.FailuerCode == 404)
                    {
                        return NotFound(new BaseAPIResponseDTO { Success = false, Message = "User not found" });
                    }
                }

                // handle operations cancellation
                if (user.FailuerCode.HasValue) {
                    if (user.FailuerCode == 499)
                    {
                        return StatusCode(499, new BaseAPIResponseDTO { Success = false, Message = "Request canceled" });
                    }
                }

                return Ok(user);

            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return StatusCode(499, new BaseAPIResponseDTO { Success = false, Message = "Request canceled" });
            }
            catch (Exception ex)
            {
                LogException.LogExceptions(ex);
                return StatusCode(500, new BaseAPIResponseDTO { Success = false, Message = "An error occurred while retrieving user profile" });
            }

        }

        /// <summary>
        /// Validate profile username for availability and content
        /// </summary>
        [HttpGet("profile-username/validate/{profileUsername}")]
        public async Task<IActionResult> ValidateProfileUsername(string profileUsername)
        {
            try
            {
                // Check if username is available (not taken)
                var isAvailable = await _accountRepository.IsProfileUsernameAvailableAsync(profileUsername);
                
                if (!isAvailable)
                {
                    return Ok(new { 
                        IsValid = false, 
                        IsAvailable = false,
                        Message = "Username is already taken" 
                    });
                }
                
                // Check if username is allowed (no profanity)
                var usernameValidator = HttpContext.RequestServices.GetRequiredService<IUsernameValidator>();
                var isAllowed = usernameValidator.IsUsernameAllowed(profileUsername);
                
                if (!isAllowed)
                {
                    var reason = usernameValidator.GetRejectionReason(profileUsername);
                    return Ok(new { 
                        IsValid = false, 
                        IsAvailable = true,
                        Message = reason ?? "Username contains inappropriate content" 
                    });
                }
                
                return Ok(new { 
                    IsValid = true, 
                    IsAvailable = true,
                    Message = "Username is available!" 
                });
            }
            catch (Exception ex)
            {
                LogException.LogExceptions(ex);
                return StatusCode(500, new { 
                    IsValid = false, 
                    Message = "Unable to validate username" 
                });
            }
        }

        // We need to set up an enpoint for "api/identiry/settings".  For security
        // It should not take any parameters, but should use the JWT token to identify the user.
        // It should return a APIResponseViewAccountSettings object.
        [HttpGet("identity/settings")]
        [Authorize]
        public async Task<ActionResult<APIResponseViewAccountSettings>> GetAccountSettings()
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId))
            {
                return Unauthorized(new APIResponseViewAccountSettings
                {
                    Success = false,
                    Message = "User not authorized."
                });
            }
            return await _accountRepository.GetAccountSettingsAsync(userId);
        }

        // Get method to retrieve user information for the authenticated user navigation bar (e.g., profile picture, name)
        [HttpGet("identity/navbar-info")]
        [Authorize]
        public async Task<ActionResult<APIResponseViewAccountSettings?>> GetNavbarUserInfo()
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId))
            {
                return Unauthorized(new APIResponseViewAccountSettings
                {
                    Success = false,
                    Message = "User not authorized."
                });
            }
            // Try parse userId to Guid to ensure validity
            var parsedUserId = Guid.Empty;
            if (!Guid.TryParse(userId, out parsedUserId))
            {
                return Unauthorized(new APIResponseViewAccountSettings
                {
                    Success = false,
                    Message = "Invalid user identifier."
                });
            }

            var cacheKey = $"navbarinfo:{parsedUserId}";

            try
            {
                if (_cache.TryGetValue(cacheKey, out APIResponseViewAccountSettings? cached))
                {
                    return Ok(cached);
                }

                var result = await _accountRepository.GetNavbarUserInfoAsync(parsedUserId);

                if (result != null)
                {
                    var cacheEntryOptions = new MemoryCacheEntryOptions
                    {
                        AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(10),
                        Priority = CacheItemPriority.Normal
                    };

                    // Cache the result
                    _cache.Set(cacheKey, result, cacheEntryOptions);
                }
        
                return Ok(result);
            }
            catch (Exception ex)
            {
                LogException.LogExceptions(ex);
                return StatusCode(500, new APIResponseViewAccountSettings { Success = false, Message = "Unable to retrieve navbar info" });
            }
        }

        #region Helpers
        /// <summary>
        /// Get the IP address of the user. 
        /// </summary>
        /// <returns></returns>
        private string ipAddress()
        {
            if (Request.Headers.ContainsKey("X-Forwarded-For") &&
                !string.IsNullOrEmpty(Request.Headers["X-Forwarded-For"].ToString()))
            {
                return Request.Headers["X-Forwarded-For"].ToString();
            }
            else
            {
                return HttpContext.Connection.RemoteIpAddress?.MapToIPv4().ToString() ?? "0.0.0.0";
            }
        }


        /// <summary>
        /// Helper method to validate uploaded profile picture. Method performs null checks,
        /// for model and ProfilePhoto, size checks, content type validation, and filename validation.
        /// It uses FirebaseUploadConstants for max size limit. More tolerant content type checks and
        /// falls back to IFormFile.ContentType, accepts common image types(.png, .jpeg, .jpg, .webp) 
        /// and any image/* MIME type. Validates the uploaded file's name to avoid empty or 
        /// path-traversal names. Consistent <see cref="APIResponseUploadPhoto"/> responses indicate success or failure"/>
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        private APIResponseUploadPhoto ValidateUploadProfilePicture(UpdateProfilePhotoDTO? model) {
            // ✅ Server-side validation is mandatory

            if (model is null || model.ProfilePhoto is null)
                return new APIResponseUploadPhoto { Success = false, Message = "File is missing" };

            var file = model.ProfilePhoto;

            // Basic size checks
            if (file.Length <=0)
                return new APIResponseUploadPhoto { Success = false, Message = "File is empty" };

            if (file.Length > FirebaseUploadConstants.MaxProfilePictureSize)
                return new APIResponseUploadPhoto { Success = false, Message = $"Profile photo exceeds maximum size of {FirebaseUploadConstants.MaxProfilePictureSize / (1024 *1024)} MB" };

            // Determine content type in a tolerant way (prefer DTO, fall back to IFormFile)
            var contentType = (model.ContentType ?? file.ContentType ?? string.Empty).Trim().ToLowerInvariant();

            // Allow common image types; allow any image/* MIME as a fallback
            var allowedTypes = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "image/png", "image/jpeg", "image/jpg", "image/webp" };
            if (!allowedTypes.Contains(contentType) && !contentType.StartsWith("image/"))
                return new APIResponseUploadPhoto { Success = false, Message = "Invalid file type" };

            // Validate filename (avoid empty or path-traversal names)
            var fileName = System.IO.Path.GetFileName(file.FileName ?? string.Empty);
            if (string.IsNullOrWhiteSpace(fileName))
                return new APIResponseUploadPhoto { Success = false, Message = "Invalid file name" };

            return new APIResponseUploadPhoto { Success = true, Message = "File is valid" };
        }

        private void SetTokenCookie(string token)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = DateTime.UtcNow.AddDays(7)
            };
            Response.Cookies.Append("refreshToken", token, cookieOptions);
        }

        #endregion

        public class TestEmailRequest
        {
            [Required]
            public string To { get; set; } = string.Empty;
            public string? FirstName { get; set; }
            public string? Token { get; set; }
            public string? Type { get; set; } // "verification" (default) or "reset"
        }
    }
}
