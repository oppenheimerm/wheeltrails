using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using WT.Application.APIServiceLogs;
using WT.Application.Contracts;
using WT.Application.DTO.Request.Trail;
using WT.Application.Services;
using WT.Infrastructure.Repositories;

namespace API.Controllers
{
    //[Authorize]
    [Route("api/[controller]")]
    [ApiController]
    [Authorize] // Require authentication for all file operations
    public class FilesController : ControllerBase
    {
        private readonly IFileStorageService _fileStorageService;
        private readonly ILogger<FilesController> _logger;
        private readonly IWTTrailRepository _trailRepository; // Added repository for trail photos

        public FilesController(IFileStorageService fileStorageService, ILogger<FilesController> logger, WTTrailRepository trailRepository)
        {
            _fileStorageService = fileStorageService;
            _logger = logger;
            _trailRepository = trailRepository;
        }

        /// <summary>
        /// Uploads a profile picture for the authenticated user.
        /// </summary>
        [HttpPost("upload-profile-picture")]
        public async Task<IActionResult> UploadProfilePicture([FromForm] IFormFile file, [FromForm] Guid userId)
        {
            try
            {
                if (file == null || file.Length == 0)
                    return BadRequest("No file uploaded");

                // Validate file size (5MB max)
                const long maxFileSize = 5 * 1024 * 1024;
                if (file.Length > maxFileSize)
                    return BadRequest("File size exceeds 5MB limit");

                // Validate file type
                var allowedTypes = new[] { "image/png", "image/jpeg", "image/jpg" };
                if (!allowedTypes.Contains(file.ContentType.ToLower()))
                    return BadRequest("Only PNG and JPEG images are allowed");

                // Upload to Firebase Storage
                using var stream = file.OpenReadStream();
                var downloadUrl = await _fileStorageService.UploadProfilePictureAsync(stream, file.FileName, userId);

                _logger.LogInformation($"Profile picture uploaded for user {userId}");

                return Ok(downloadUrl);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error uploading profile picture");
                return StatusCode(500, $"Upload failed: {ex.Message}");
            }
        }

        /// <summary>
        /// Uploads a trail photo.
        /// </summary>
        [HttpPost("upload-trail-photo")]
        [Authorize]
        public async Task<IActionResult> UploadTrailPhoto(
            [FromForm] IFormFile file,
            [FromForm] Guid trailId,
            [FromForm] string? description) // ✅ Add optional description
        {
            try
            {
                // Validate file
                const long maxFileSize = 10 * 1024 * 1024; // 10MB
                if (file.Length > maxFileSize)
                    return BadRequest(new { success = false, message = "File size exceeds 10MB limit" });

                var allowedTypes = new[] { "image/png", "image/jpeg", "image/jpg" };
                if (!allowedTypes.Contains(file.ContentType.ToLower()))
                    return BadRequest(new { success = false, message = "Invalid file type" });

                // ✅ Step 1: Upload to Firebase
                using var stream = file.OpenReadStream();
                var photoUrl = await _fileStorageService.UploadTrailPhotoAsync(stream, file.FileName, trailId);

                if (string.IsNullOrEmpty(photoUrl))
                {
                    return StatusCode(500, new { success = false, message = "Firebase upload failed" });
                }

                // ✅ Step 2: Save metadata to database
                var addPhotoDto = new AddTrailPhotoDbEntityDTO
                {
                    PhotoName = photoUrl,
                    TrailId = trailId,
                    Description = description
                };

                var dbResult = await _trailRepository.AddTrailPhotoAsync(addPhotoDto);

                if (!dbResult.Success)
                {
                    // TODO: Delete from Firebase since DB save failed
                    // await _fileStorageService.DeleteFileAsync(photoUrl);

                    return StatusCode(500, new
                    {
                        success = false,
                        message = "Photo uploaded but database save failed"
                    });
                }

                return Ok(new
                {
                    success = true,
                    url = photoUrl,
                    message = "Photo uploaded and saved successfully"
                });
            }
            catch (Exception ex)
            {
                LogException.LogExceptions(ex);
                return StatusCode(500, new { success = false, message = "Upload failed" });
            }
        }

        /// <summary>
        /// Deletes a file from Firebase Storage.
        /// </summary>
        [HttpDelete("delete")]
        public async Task<IActionResult> DeleteFile([FromQuery] string fileUrl)
        {
            try
            {
                if (string.IsNullOrEmpty(fileUrl))
                    return BadRequest("File URL is required");

                var success = await _fileStorageService.DeleteFileAsync(fileUrl);

                if (success)
                {
                    _logger.LogInformation($"File deleted: {fileUrl}");
                    return Ok(new { success = true });
                }
                else
                {
                    return StatusCode(500, "Failed to delete file");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting file");
                return StatusCode(500, $"Delete failed: {ex.Message}");
            }
        }

        /// <summary>
        /// Tests Firebase configuration.
        /// </summary>
        [HttpGet("test-firebase")]
        [AllowAnonymous]
        public IActionResult TestFirebase()
        {
            try
            {
                // Service will throw exception if Firebase not configured
                return Ok(new
                {
                    status = "Firebase configured successfully",
                    bucket = _fileStorageService.GetType().GetProperty("BucketName")?.GetValue(_fileStorageService)
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { error = ex.Message });
            }
        }
    }
}
