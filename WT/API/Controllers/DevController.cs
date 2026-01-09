using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using WT.Application.DTO.Request.Trail;
using WT.Application.APIServiceLogs;

namespace API.Controllers
{
    [ApiController]
    [Route("api/dev")]
    [Authorize] // Require authentication for access to these dev endpoints
    public class DevController : ControllerBase
    {
        private readonly IWebHostEnvironment _env;
        private readonly JsonSerializerOptions _jsonOptions = new(JsonSerializerDefaults.Web) { WriteIndented = true };

        public DevController(IWebHostEnvironment env)
        {
            _env = env;
        }

        // WARNING: Intended for testing by authenticated developers. Keep protected.
        [HttpPost("log-trail")]
        public async Task<IActionResult> LogTrail([FromBody] CreateTrailDTO? model)
        {
            if (model == null)
                return BadRequest(new { success = false, message = "No payload supplied" });

            try
            {
                var folder = Path.Combine(_env.ContentRootPath, "DevSubmissions");
                Directory.CreateDirectory(folder);

                var fileName = $"trail_{DateTime.UtcNow:yyyyMMdd_HHmmss}_{Guid.NewGuid():N}.json";
                var filePath = Path.Combine(folder, fileName);

                var json = JsonSerializer.Serialize(model, _jsonOptions);
                await System.IO.File.WriteAllTextAsync(filePath, json);

                LogException.LogToFile($"Dev submission saved: {filePath}");
                return Ok(new { success = true, file = fileName });
            }
            catch (Exception ex)
            {
                LogException.LogExceptions(ex);
                return StatusCode(500, new { success = false, message = "Failed to save submission" });
            }
        }

        // List saved submissions
        [HttpGet("list")]
        public IActionResult ListSubmissions()
        {
            try
            {
                var folder = Path.Combine(_env.ContentRootPath, "DevSubmissions");
                if (!Directory.Exists(folder)) return Ok(Array.Empty<string>());

                var files = Directory.GetFiles(folder, "*.json")
                .Select(Path.GetFileName)
                .OrderByDescending(n => n)
                .ToArray();

                return Ok(files);
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
