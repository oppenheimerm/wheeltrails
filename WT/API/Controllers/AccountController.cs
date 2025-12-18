using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using WT.Application.APIServiceLogs;
using WT.Application.Contracts;
using WT.Application.DTO.Request.Account;
using WT.Application.DTO.Response;
using WT.Application.Services;
using WT.Domain.Entity;
using WT.Infrastructure.Data;
using WT.Infrastructure.Repositories;

namespace API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly IAccountRepository _accountRepository; // ✅ Use IAccountRepository
        private readonly AppDbContext _dbContext;
        private readonly UserManager<ApplicationUser> _userManager;

        public AccountController(
            IAccountRepository accountRepository, // ✅ Inject IAccountRepository
            AppDbContext dbContext, 
            UserManager<ApplicationUser> userManager)
        {
            _accountRepository = accountRepository;
            _dbContext = dbContext;
            _userManager = userManager;
        }

        [HttpGet]
        public async Task<ActionResult> CreateAdmin()
        {
            await _accountRepository.CreateAdmin();
            return Ok();
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
        /// Resets user password with valid token.
        /// </summary>
        [HttpPost("reset-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordDTO model)
        {
            var result = await _accountRepository.ResetPasswordAsync(model);
            return result.Success ? Ok(result) : BadRequest(result);
        }

        // ✅ ALWAYS validate server-side (client validation can be bypassed)
        [HttpPost("upload-profile-picture")]
        public async Task<IActionResult> UploadProfilePicture([FromForm] IFormFile file)
        {
            const long maxFileSize = 5 * 1024 * 1024;
            
            // ✅ Server-side validation is mandatory
            if (file.Length > maxFileSize)
                return BadRequest("File size exceeds 5MB limit");

            var allowedTypes = new[] { "image/png", "image/jpeg", "image/jpg" };
            if (!allowedTypes.Contains(file.ContentType.ToLower()))
                return BadRequest("Invalid file type");

            return Ok();
        }

        /*[HttpPost("set-username")]
        [Authorize] // Must be logged in
        public async Task<IActionResult> SetUsername(
            [FromBody] SetUsernameDTO model,
            [FromServices] IUsernameValidator usernameValidator)
        {
            try
            {
                // Get current user
                var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                if (string.IsNullOrEmpty(userId) || !Guid.TryParse(userId, out var userGuid))
                {
                    return Unauthorized();
                }

                var user = await _userManager.FindByIdAsync(userId);
                if (user == null)
                {
                    return NotFound(new { success = false, message = "User not found" });
                }


                // Validate username
                if (!usernameValidator.IsUsernameAllowed(model.Username))
                {
                    var reason = usernameValidator.GetRejectionReason(model.Username);
                    return BadRequest(new { success = false, message = reason ?? "Invalid username" });
                }

                // Check if username is already taken
                var existingUser = await _dbContext.Users.FirstOrDefaultAsync(u => u.Username == model.Username);
                if (existingUser != null)
                {
                    return BadRequest(new { success = false, message = "Username is already taken" });
                }

                // Set username (one-time only)
                user.Username = model.Username;
                user.UsernameIsSet = true;

                var result = await _userManager.UpdateAsync(user);

                if (result.Succeeded)
                {
                    LogException.LogToFile($"Username set for user {user.Email}: {model.Username} at {DateTime.UtcNow}");
                    return Ok(new { success = true, message = "Username set successfully", username = user.Username });
                }
                else
                {
                    var errors = string.Join("; ", result.Errors.Select(e => e.Description));
                    return BadRequest(new { success = false, message = $"Failed to set username: {errors}" });
                }
            }
            catch (Exception ex)
            {
                LogException.LogExceptions(ex);
                return StatusCode(500, new { success = false, message = "An error occurred while setting username" });
            }
        }*/

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
        /// Get user profile by ProfileUsername (for profile URLs)
        /// </summary>
        [HttpGet("user/{profileUsername}")]
        [AllowAnonymous]
        public async Task<IActionResult> GetUserByProfileUsername(string profileUsername)
        {
            // ✅ Call IAccountRepository method
            var user = await _accountRepository.FindUserByProfileUsernameAsync(profileUsername);
            
            if (user == null || user.IsDeleted)
            {
                return NotFound(new BaseAPIResponseDTO { Success = false, Message = "User not found" });
            }

            var userDto = new ApplicationUserDTO
            {
                Id = user.Id,
                FirstName = user.FirstName,
                ProfileUsername = user.ProfileUsername,
                Bio = user.Bio,
                ProfilePicture = user.ProfilePicture,
                RegistrationDate = user.ProfileUsernameCreatedAt
            };

            return Ok(new { Success = true, User = userDto });
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
    }
}
