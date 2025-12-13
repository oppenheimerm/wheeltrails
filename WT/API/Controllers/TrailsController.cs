using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using WT.Application.APIServiceLogs;
using WT.Application.DTO.Request.Trail;
using WT.Application.DTO.Response;
using WT.Application.Services;
using WT.Domain.Entity;
using WT.Infrastructure.Data;
using WT.Infrastructure.Repositories;

namespace API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class TrailsController : ControllerBase
    {
        private readonly AppDbContext _context;
        private readonly IWTTrailRepository _trailRepository;

        public TrailsController(AppDbContext context, IWTTrailRepository trailRepository)
        {
            _context = context;
            _trailRepository = trailRepository;
        }

        [HttpPost]
        [Authorize]// ✅ Requires valid JWT token
        public async Task<IActionResult> CreateTrail([FromBody] CreateTrailDTO model)
        {
            try
            {
                // ✅ SECURITY: Extract userId from authenticated JWT claims
                // Client CANNOT fake this
                var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

                if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
                {
                    return Unauthorized(new { success = false, message = "Invalid user authentication" });
                }

                // ✅ Pass trusted userId to repository
                var response = await _trailRepository.CreateTrailAsync(model, userId);

                if (response.Success == false)
                {
                    return BadRequest(response);
                }

                // Log trail creation
                LogException.LogToFile($"Creating trail: {model.Title} by User ID: {userId} at time: {DateTime.UtcNow}");

                return Ok(new APIResponseCreateTrail()
                {
                    Success = true,
                    Message = "Trail created successfully",
                    TrailId = response.TrailId,
                    TrailTitle = response.TrailTitle
                });
            }
            catch (Exception ex)
            {
                LogException.LogExceptions(ex);
                return StatusCode(500, new APIResponseCreateTrail()
                {
                    Success = false,
                    Message = "An error occurred while creating the trail"
                });
            }
        }

        [HttpPost("{trailId:guid}/like")]
        [Authorize]
        public async Task<IActionResult> LikeTrail(Guid trailId, [FromBody] AddTrailLikeDTO model)
        {
            try {
                // ✅ SECURITY: Extract userId from authenticated JWT claims
                // Client CANNOT fake this
                var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

                if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
                {
                    return Unauthorized(new { success = false, message = "Invalid user authentication" });
                }

                // ✅ Pass trusted userId to repository
                var response = await _trailRepository.AddTrailLikeAsync(model, userId);

                if (response.Success == false)
                {
                    return BadRequest(response);
                }

                // Log trail like creation
                LogException.LogToFile($"User ID: {userId} liked Trail ID: {trailId} at time: {DateTime.UtcNow}");

                // Return success response
                return Ok( response);

            }
            catch (Exception ex)
            {
                LogException.LogExceptions(ex);
                return StatusCode(500, new BaseAPIResponseDTO()
                {
                    Success = false,
                    Message = "An error occurred while liking the trail"
                });
            }
        }

        [HttpDelete("{trailId:guid}/unlike")]
        [Authorize]
        public async Task<IActionResult> UnlikeTrail(Guid trailId)
        {
            try {
                // ✅ SECURITY: Extract userId from authenticated JWT claims
                // Client CANNOT fake this
                var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

                if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
                {
                    return Unauthorized(new { success = false, message = "Invalid user authentication" });
                }

                // ✅ Pass trusted userId to repository
                var response = await _trailRepository.UnlikeTraiAsync(trailId, userId);

                if (response.Success == false)
                {
                    return BadRequest(response);
                }

                // Log trail unlike creation
                LogException.LogToFile($"User ID: {userId} unliked Trail ID: {trailId} at time: {DateTime.UtcNow}");

                // Return success response
                return Ok(response);
            }
            catch (Exception ex) {
                LogException.LogExceptions(ex);
                return StatusCode(500, new BaseAPIResponseDTO()
                {
                    Success = false,
                    Message = "An error occurred while unliking the trail"
                });
            }

        }

        [HttpGet("{trailId:guid}/likes")]
        public async Task<IActionResult> GetTrailLikes(Guid trailId)
        {
            var likes = await _context.TrailLikes
                .Where(tl => tl.TrailId == trailId)
                .Include(tl => tl.User)
                .Select(tl => new
                {
                    UserId = tl.UserId,
                    Username = tl.User.Username ?? tl.User.FirstName,
                    ProfilePicture = tl.User.ProfilePicture,
                    LikedAt = tl.LikedAt,
                    Rating = tl.Rating
                })
                .OrderByDescending(tl => tl.LikedAt)
                .ToListAsync();

            return Ok(new { success = true, likes, count = likes.Count });
        }
    }
}
