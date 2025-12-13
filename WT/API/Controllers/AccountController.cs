using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using WT.Application.APIServiceLogs;
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
        private readonly IAccountService _accountService;
        private readonly AppDbContext _dbContext;
        private readonly UserManager<ApplicationUser> _userManager;

        public AccountController(IAccountService accountService, AppDbContext dbContext, 
            UserManager<ApplicationUser> userManager)
        {
            _accountService = accountService;
            _dbContext = dbContext;
        }

        [HttpGet]
        public async Task<ActionResult> CreateAdmin()
        {
            await _accountService.CreateAdmin();
            return Ok();
        }

          [AllowAnonymous]
        [HttpPost("identity/create")]
        public async Task<ActionResult<BaseAPIResponseDTO>> CreateAccount(RegisterDTO model)
        {
            if(!ModelState.IsValid)
                return BadRequest(new BaseAPIResponseDTO { Success = false, Message = "Invalid Registration Form" });


            return await _accountService.RegisterAsync(model);
        }

        [AllowAnonymous]
        [HttpPost("identity/login")]
        public async Task<ActionResult<APIResponseAuthentication>> LoginAccount(LoginDTO model)
        {
            if(!ModelState.IsValid)
                return BadRequest(new APIResponseAuthentication { Success = false, Message = "Password or Email Address is incorrect" });
            
            // Cast to concrete type to access internal method
            var wtAccount = _accountService as WTAccount;
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
        public async Task<ActionResult<APIResponseAuthentication>> RefreshToken(RefreshTokenDTO model)
        {
            if (string.IsNullOrEmpty(model.Token))
            {
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
            var wtAccount = _accountService as WTAccount;
            if (wtAccount == null)
            {
                return StatusCode(500, new APIResponseAuthentication 
                { 
                    Success = false, 
                    Message = "Service configuration error" 
                });
            }

            var result = await wtAccount.RefreshTokenWithIpAsync(model.Token, ipAddress());
            if (result.Success)
            {
                SetTokenCookie(result.RefreshToken!);
                return Ok(result);
            }
            else
            {
                return BadRequest(new APIResponseAuthentication()
                {
                    JwtToken = string.Empty,
                    RefreshToken = null!,
                    Success = false,
                    User = null!,
                    Message = "Refresh token request failed."
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
            return await _accountService.VerifyEmailAsync(model.Token!);
        }

        // add register route
        [AllowAnonymous]
        [HttpPost("register")]
        [EnableRateLimiting("AuthPolicy")] // ✅ Strict rate limit
        public async Task<ActionResult<BaseAPIResponseDTO>> Register(RegisterDTO model)
        {
            if (!ModelState.IsValid)
                return BadRequest(new BaseAPIResponseDTO { Success = false, Message = "Invalid Registration Form" });
            return await _accountService.RegisterAsync(model);
        }

        /// <summary>
        /// Initiates password reset process.
        /// </summary>
        [HttpPost("forgot-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordDTO model)
        {
            var result = await _accountService.ForgotPasswordAsync(model);
            return result.Success ? Ok(result) : BadRequest(result);
        }

        /// <summary>
        /// Resets user password with valid token.
        /// </summary>
        [HttpPost("reset-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordDTO model)
        {
            var result = await _accountService.ResetPasswordAsync(model);
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

        [HttpPost("set-username")]
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

                //  Check if the username was set in the last 90 days
                if (user.UsernameSetDate.HasValue && 
                    (DateTime.UtcNow - user.UsernameSetDate.Value).TotalDays < 90)
                {
                    return BadRequest(new { success = false, message = "Username can only be changed once every 90 days" });
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
