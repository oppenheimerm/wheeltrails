using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using WT.Application.Contracts;
using WT.Application.DTO.Request.Account;
using WT.Application.DTO.Response;

namespace API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController(IWTAccount account) : ControllerBase
    {
        [HttpGet]
        public async Task<ActionResult> CreateAdmin()
        {
            await account.CreateAdmin();
            return Ok();
        }

        [HttpPost("identity/create")]
        public async Task<ActionResult<BaseAPIResponseDTO>> CreateAccount(RegisterDTO model)
        {
            if(!ModelState.IsValid)
                return BadRequest(new BaseAPIResponseDTO { Success = false, Message = "Invalid Registration Form" });


            return await account.RegisterAsync(model);
        }

        [HttpPost("identity/login")]
        public async Task<ActionResult<APIResponseAuthentication>> LoginAccount(LoginDTO model)
        {
            if(!ModelState.IsValid)
                return BadRequest(new APIResponseAuthentication { Success = false, Message = "Password or Email Address is incorrect" });
            
            var result = await account.LoginAsync(model, ipAddress());
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
            if (!string.IsNullOrEmpty(model.Token))
            { 
                var result = await account.RefreshTokenAsync(model.Token, ipAddress());
                if (result.Success)
                {
                    SetTokenCookie(result.RefreshToken!);
                    return Ok(result);
                }
                else
                {
                    var nullResult = new APIResponseAuthentication()
                    {
                        JwtToken = string.Empty,
                        RefreshToken = null!,
                        Success = false,
                        User = null!,
                        Message = "Refresh token request failed."
                    };
                    return BadRequest(nullResult);
                }
            }
            else {
                var result = new APIResponseAuthentication()
                {
                    JwtToken = string.Empty,
                    RefreshToken = null!,
                    Success = false,
                    User = null!,
                    Message = "RefreshToken not found."
                };
                return BadRequest(result);
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
