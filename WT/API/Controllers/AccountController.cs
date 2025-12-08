using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using WT.Application.DTO.Request.Account;
using WT.Application.DTO.Response;
using WT.Application.Services;
using WT.Infrastructure.Repositories;

namespace API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly IAccountService _accountService;

        public AccountController(IAccountService accountService)
        {
            _accountService = accountService;
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
