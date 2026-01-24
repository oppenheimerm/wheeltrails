using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using WT.Application.APIServiceLogs;
using WT.Application.Common.Paging;
using WT.Application.Contracts;
using WT.Application.DTO.Request.Account;
using WT.Application.DTO.Request.Trail;
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
    [Authorize]
    public class TrailsController : ControllerBase
    {
        private readonly AppDbContext _context;
        private readonly IWTTrailRepository _trailRepository;
        private readonly IFileStorageService _fileStorageService;

        public TrailsController(AppDbContext context, IWTTrailRepository trailRepository, IFileStorageService fileStorageService)
        {
            _context = context;
            _trailRepository = trailRepository;
            _fileStorageService = fileStorageService;
        }

        [HttpGet("all")]
        [AllowAnonymous]
        public async Task<ActionResult<PagedList<TrailDTO>>>GetTrailsAll([FromQuery] PagingParameters pagingParameters, CancellationToken cancellationToken)
        {
            try
            {
                var trails = await _trailRepository.GetAllTrailsAsync(pagingParameters,cancellationToken);
                return Ok(trails);
            }
            catch (Exception ex)
            {
                LogException.LogExceptions(ex);
                return StatusCode(500, new { success = false, message = "An error occurred while retrieving trails" });
            }
        }

        // Controller to get a trail by its ID
        [HttpGet("{trailId:guid}")]
        [AllowAnonymous]
        public async Task<ActionResult<TrailDTO?>> GetTrailById(Guid trailId, CancellationToken cancellationToken)
        {
            try
            {
                var trail = await _trailRepository.GetTrailByIdAsync(trailId, cancellationToken);
                if (trail == null)
                {
                    return NotFound(new { success = false, message = "Trail not found" });
                }
                return Ok(new { success = true, trail });
            }
            catch (Exception ex)
            {
                LogException.LogExceptions(ex);
                return StatusCode(500, new { success = false, message = "An error occurred while retrieving the trail" });
            }
        }

        [HttpPost]
        [Authorize] // ✅ Requires valid JWT token
        public async Task<IActionResult> CreateTrail([FromBody] CreateTrailDTO model, CancellationToken cancellationToken)
        {
            try
            {
                // ✅ SECURITY: Extract userId from authenticated JWT claims
                var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
                {
                    var UnauthorizedResponse = new APIResponseCreateTrail
                    {
                        Success = false,
                        Message = "Invalid user authentication"
                    };
                    return Unauthorized(UnauthorizedResponse);
                }

                // Cancellation token: prefer the explicit token from the client, but also observe HttpContext.RequestAborted
                var ct = cancellationToken.CanBeCanceled ? cancellationToken : HttpContext.RequestAborted;

                // ✅ Pass trusted userId to repository
                var response = await _trailRepository.CreateTrailAsync(model, userId, cancellationToken);

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
                    Trail = response.Trail
                });
            }
            // hangle cancellation separately
            catch (OperationCanceledException)
            {
                LogException.LogToFile("Trail creation operation was canceled by the client.");
                return StatusCode(StatusCodes.Status499ClientClosedRequest, new APIResponseCreateTrail()
                {
                    Success = false,
                    Message = "Trail creation was canceled"
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
            try 
            {
                // ✅ SECURITY: Extract userId from authenticated JWT claims
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

                return Ok(response);
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
            try 
            {
                // ✅ SECURITY: Extract userId from authenticated JWT claims
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

                // Log trail unlike
                LogException.LogToFile($"User ID: {userId} unliked Trail ID: {trailId} at time: {DateTime.UtcNow}");

                return Ok(response);
            }
            catch (Exception ex)
            {
                LogException.LogExceptions(ex);
                return StatusCode(500, new BaseAPIResponseDTO()
                {
                    Success = false,
                    Message = "An error occurred while unliking the trail"
                });
            }
        }

        /// <summary>
        /// Gets all likes for a specific trail, including user details and ratings.
        /// Public endpoint - anyone can view who liked a trail.
        /// </summary>
        [HttpGet("{trailId:guid}/likes")]
        [AllowAnonymous] // ✅ Public endpoint
        public async Task<IActionResult> GetTrailLikes(Guid trailId)
        {
            try
            {
                var likes = await _context.TrailLikes
                    .Where(tl => tl.TrailId == trailId)
                    .Include(tl => tl.User)
                    .Select(tl => new
                    {
                        UserId = tl.UserId,
                        // ✅ UPDATED: Use ProfileUsername instead of Username (email)
                        ProfileUsername = tl.User.ProfileUsername ?? tl.User.FirstName ?? "Anonymous",
                        ProfilePicture = tl.User.ProfilePicture,
                        LikedAt = tl.LikedAt,
                        Rating = tl.Rating
                    })
                    .OrderByDescending(tl => tl.LikedAt)
                    .ToListAsync();

                return Ok(new { success = true, likes, count = likes.Count });
            }
            catch (Exception ex)
            {
                LogException.LogExceptions(ex);
                return StatusCode(500, new 
                { 
                    success = false, 
                    message = "An error occurred while retrieving trail likes" 
                });
            }
        }

        [HttpPost("upload-trail-photo")]
        [RequestFormLimits(MultipartBodyLengthLimit = FirebaseUploadConstants.MaxTrailPhotoSize)]
        [Authorize]
        public async Task<IActionResult> UploadTrailPhoto([FromForm] AddTrailPhotoRequestDTO? model, CancellationToken cancellationToken)
        {            

            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId) || !Guid.TryParse(userId, out var userGuid))
            {
                return Unauthorized();
            }

            // Cancellation token: prefer the explicit token from the client, but also observe HttpContext.RequestAborted
            var ct = cancellationToken.CanBeCanceled ? cancellationToken : HttpContext.RequestAborted;

            var trail = await _context.Trails.FindAsync(new object[] { model!.TrailId }, ct);

            if (trail == null)
            {
                return NotFound(new APIResponseUploadPhoto { Success = false, Message = "Trail not found" });
            }

            // make sure this user exist
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Id == userGuid, ct);
            if (user == null)
            {
                return NotFound(new APIResponseUploadPhoto { Success = false, Message = "User not found" });
            }


            // Validate model / metadata
            var validationResponse = ValidateTrailPhoto(model, userGuid);
            if (!validationResponse.Success)
            {
                // must be consistent with APIResponseUploadPhoto
                return BadRequest(new APIResponseUploadPhoto { Success = false, Message = validationResponse.Message });
            }
            
            // Upload -> Persist -> Cleanup (delete old)
            string? newFileUrl = null;
            try
            {
                // Stream the file to the storage service. Ensure the stream is disposed.
                // Use explicit max allowed size to protect from large uploads
                using var stream = model!.TrailPhoto!.OpenReadStream();

                // If the client disconnected, abort early
                if (ct.IsCancellationRequested)
                {
                    return StatusCode(499, new APIResponseUploadPhoto { Success = false, Message = "Client disconnected" }); //499 Client Closed Request (non-standard)
                }

                // Server-side magic-bytes check to reduce spoofed MIME uploads, which is when a file is given a
                // false extension or content-type this is not foolproof but adds a layer of protection
                try
                {
                    // Ensure stream is positioned to start
                    if (stream.CanSeek) stream.Seek(0, System.IO.SeekOrigin.Begin);
                    var isValid = WT.Application.Extensions.ImageUtils.IsValidImageStream(stream, model.TrailPhoto.ContentType);
                    if (!isValid)
                    {
                        return BadRequest(new APIResponseUploadPhoto { Success = false, Message = "Invalid image file" });
                    }
                    // Reset position for upload
                    if (stream.CanSeek) stream.Seek(0, System.IO.SeekOrigin.Begin);
                }
                catch (Exception ex)
                {
                    LogException.LogExceptions(ex);
                    return BadRequest(new APIResponseUploadPhoto { Success = false, Message = "Invalid image file" });
                }

                // Use the uploaded file's original filename for metadata only; storage service will sanitize and generate unique name
                newFileUrl = await _fileStorageService.UploadTrailPhotoAsync(stream, model.TrailPhoto.FileName, trail.Id);

                if (string.IsNullOrEmpty(newFileUrl))
                {
                    return StatusCode(500, new APIResponseUploadPhoto { Success = false, Message = "Failed to upload trail photo" });
                }

                // Create a new WTTrailPhoto db entity
                var trailPhoto = new WTTrailPhoto
                {
                    Id = Guid.NewGuid(),
                    TrailId = trail.Id,
                    PhotoUrl = newFileUrl,
                    Description = model.Description,
                    UserId = userGuid,
                    CreatedAt = DateTime.UtcNow
                };

                // Persist the new trail photo record and catch any failures
                await _context.TrailPhotos.AddAsync(trailPhoto, ct);
                await _context.SaveChangesAsync(ct);

                // We should now have a persisted newFileUrl. No rollback needed.
                // Loge sccess
                LogException.LogToFile($"Successfully added photo to trail: {trail.Id} by User ID: {userGuid} at time: {DateTime.UtcNow}");

                // Return201 Created with location to the trail resource or photo endpoint
                var location = $"/api/trails/{trail.Id}/photos/{trailPhoto.Id}";
                return Created(location, new APIResponseUploadPhoto { Success = true, Message = $"Successfully added photo to trail: {trail.Id}", PhotoUrl = newFileUrl });
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                // Client disconnected or request cancelled
                // Log cancellation
                LogException.LogToFile("Upload trail photo operation was canceled by the client.");
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
                return StatusCode(500, new APIResponseUploadPhoto { Success = false, Message = "An error occurred while uploading trail photo" });
            }
        }

        private APIResponseUploadPhoto ValidateTrailPhoto(AddTrailPhotoRequestDTO? model, Guid? userId)
        {
            // ✅ Server-side validation is mandatory

            if (model is null || model.TrailPhoto is null)
                return new APIResponseUploadPhoto { Success = false, Message = "File is missing" };

            // validate userid
            if(userId == Guid.Empty)
                return new APIResponseUploadPhoto { Success = false, Message = "Invalid user Id" };

            // validate trailid
            if (model.TrailId == Guid.Empty)
                return new APIResponseUploadPhoto { Success = false, Message = "Invalid trail Id" };

            var file = model.TrailPhoto;

            // Basic size checks
            if (file.Length <= 0)
                return new APIResponseUploadPhoto { Success = false, Message = "File is empty" };

            if (file.Length > FirebaseUploadConstants.MaxTrailPhotoSize)
                return new APIResponseUploadPhoto { Success = false, Message = $"Trail photo exceeds maximum size of {FirebaseUploadConstants.MaxTrailPhotoSize / (1024 *1024)} MB" };

            // Determine content type in a tolerant way (prefer DTO, fall back to IFormFile)
            var contentType = (model?.ContentType ?? file.ContentType ?? string.Empty).Trim().ToLowerInvariant();

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


    }
}
