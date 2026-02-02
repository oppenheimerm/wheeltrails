using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json;
using WT.Application.APIServiceLogs;
using WT.Application.DTO.Request.Dev;
using WT.Application.DTO.Request.Trail;
using WT.Application.Services;
using Microsoft.AspNetCore.Hosting;
using WT.Application.Common.Paging;

namespace API.Controllers
{
    [ApiController]
    [Route("api/dev")]
    [Authorize] // Require authentication for access to these dev endpoints
    public class DevController : ControllerBase
    {
        private readonly IDevLogRepository _devLogRepository;
        private readonly IWebHostEnvironment _env;
        private readonly JsonSerializerOptions _jsonOptions = new(JsonSerializerDefaults.Web) { WriteIndented = true };

        public DevController(IDevLogRepository devLogRepository, IWebHostEnvironment env)
        {
            _devLogRepository = devLogRepository;
            _env = env;
        }

        // WARNING: Intended for testing by authenticated developers. Keep protected.
        [HttpPost("log-trail")]
        [Authorize]
        public async Task<IActionResult> LogTrail([FromBody] DevLogEntryDTO? model, CancellationToken cancellationToken)
        {
            if (model == null)
                return BadRequest(new { success = false, message = "No payload supplied" });

            try
            {                            
                // Persist using repository and observe the cancellation token
                var repoResult = await _devLogRepository.CreateDevLogAsync(model, cancellationToken);

                if (repoResult == null || !repoResult.Success)
                {
                    LogException.LogToFile($"Failed to create dev log entry via repository: {repoResult?.Message}");
                    return StatusCode(500, new { success = false, message = "Failed to save submission" });
                }

                return Ok(new { success = true });
            }
            catch (OperationCanceledException)
            {
                LogException.LogToFile($"Dev submission cancelled at {DateTime.UtcNow}");
                return StatusCode(499, new { success = false, message = "Request cancelled" });
            }
            catch (Exception ex)
            {
                LogException.LogExceptions(ex);
                return StatusCode(500, new { success = false, message = "Failed to save submission" });
            }
        }

        // List saved submissions (now reads from DB via repository with paging)
        [HttpGet("list")]
        [AllowAnonymous]
        public async Task<IActionResult> ListSubmissions([FromQuery] PagingParameters? pagingParameters, CancellationToken cancellationToken)
        {
            try
            {
                var paging = pagingParameters ?? new PagingParameters();
                var result = await _devLogRepository.GetAllDevLogsAsync(paging, cancellationToken);
                return Ok(result);
            }
            catch (OperationCanceledException)
            {
                LogException.LogToFile($"ListSubmissions cancelled at {DateTime.UtcNow}");
                return StatusCode(499, new { success = false, message = "Request cancelled" });
            }
            catch (Exception ex)
            {
                LogException.LogExceptions(ex);
                return StatusCode(500, new { success = false, message = "Failed to list submissions" });
            }
        }

        // Download a saved submission by filename
        [HttpGet("file/{fileName}")]
        public async Task<IActionResult> GetSubmissionFile(string fileName)
        {
            try
            {
                var safeName = Path.GetFileName(fileName); // sanitize
                var folder = Path.Combine(_env.ContentRootPath, "DevSubmissions");
                var filePath = Path.Combine(folder, safeName);

                if (!System.IO.File.Exists(filePath)) return NotFound(new { success = false, message = "File not found" });

                var bytes = await System.IO.File.ReadAllBytesAsync(filePath);
                return File(bytes, "application/json", safeName);
            }
            catch (Exception ex)
            {
                LogException.LogExceptions(ex);
                return StatusCode(500, new { success = false, message = "Failed to read submission" });
            }
        }
    }
}
