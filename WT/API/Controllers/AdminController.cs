using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.Linq;
using WT.Infrastructure.Data;

namespace API.Controllers
{
    [Route("api/[controller]")]
    [Authorize]
    [ApiController]
    public class AdminController : ControllerBase
    {
        private readonly AppDbContext _db;
        private readonly IConfiguration _config;
        private readonly ILogger<AdminController> _logger;
        private readonly IWebHostEnvironment _env;

        public AdminController(AppDbContext db, IConfiguration config, ILogger<AdminController> logger, IWebHostEnvironment env)
        {
            _db = db;
            _config = config;
            _logger = logger;
            _env = env;
        }

        /// <summary>
        /// Purge all user and application data from the database.
        /// This is intentionally a dangerous operation. In Development environment this will run
        /// without additional configuration so you can run a one-off purge. In non-Development
        /// environments this remains gated by configuration and secret header as a safety measure.
        ///
        /// To run in Production/Non-Development:
        ///1) Set configuration key "Dangerous:AllowPurge" = true
        ///2) Set configuration key "Dangerous:PurgeSecret" to a long secret value
        ///3) Send the request with header "X-Purge-Confirm" equal to the secret
        ///
        /// In Development you only need to call this endpoint once.
        /// </summary>
        /*[HttpPost("purge-database")]
        public async Task<IActionResult> PurgeDatabase()
        {
            // If not development, require explicit allow + secret header
            if (!_env.IsDevelopment())
            {
                var allow = _config.GetValue<bool>("Dangerous:AllowPurge");
                if (!allow)
                {
                    return Forbid();
                }

                var secret = _config["Dangerous:PurgeSecret"];
                var header = Request.Headers["X-Purge-Confirm"].FirstOrDefault();
                if (string.IsNullOrEmpty(secret) || header != secret)
                {
                    return Unauthorized(new { success = false, message = "Missing or invalid purge confirmation header" });
                }
            }

            try
            {
                // Use a transaction so either all deletes succeed or none
                await using var tx = await _db.Database.BeginTransactionAsync();

                // Execute deletes in order to satisfy FK constraints. Use guards to avoid errors if table doesn't exist.
                var total = 0L;

                total += await _db.Database.ExecuteSqlRawAsync(@"
IF OBJECT_ID(N'dbo.DeletionQueue','U') IS NOT NULL
 DELETE FROM [dbo].[DeletionQueue];");

                total += await _db.Database.ExecuteSqlRawAsync(@"
IF OBJECT_ID(N'dbo.TrailPhotos','U') IS NOT NULL
 DELETE FROM [dbo].[TrailPhotos];");

                total += await _db.Database.ExecuteSqlRawAsync(@"
IF OBJECT_ID(N'dbo.TrailLikes','U') IS NOT NULL
 DELETE FROM [dbo].[TrailLikes];");

                total += await _db.Database.ExecuteSqlRawAsync(@"
IF OBJECT_ID(N'dbo.Comments','U') IS NOT NULL
 DELETE FROM [dbo].[Comments];");

                total += await _db.Database.ExecuteSqlRawAsync(@"
IF OBJECT_ID(N'dbo.Trails','U') IS NOT NULL
 DELETE FROM [dbo].[Trails];");

                total += await _db.Database.ExecuteSqlRawAsync(@"
IF OBJECT_ID(N'dbo.RefreshTokens','U') IS NOT NULL
 DELETE FROM [dbo].[RefreshTokens];");

                // Identity related cleanup - remove user claims/logins/roles mappings then users
                total += await _db.Database.ExecuteSqlRawAsync(@"
IF OBJECT_ID(N'dbo.AspNetUserRoles','U') IS NOT NULL
 DELETE FROM [dbo].[AspNetUserRoles];");

                total += await _db.Database.ExecuteSqlRawAsync(@"
IF OBJECT_ID(N'dbo.AspNetUserClaims','U') IS NOT NULL
 DELETE FROM [dbo].[AspNetUserClaims];");

                total += await _db.Database.ExecuteSqlRawAsync(@"
IF OBJECT_ID(N'dbo.AspNetUserLogins','U') IS NOT NULL
 DELETE FROM [dbo].[AspNetUserLogins];");

                total += await _db.Database.ExecuteSqlRawAsync(@"
IF OBJECT_ID(N'dbo.AspNetUserTokens','U') IS NOT NULL
 DELETE FROM [dbo].[AspNetUserTokens];");

                // Do NOT delete AspNetRoles by default to keep role definitions; remove if you want
                total += await _db.Database.ExecuteSqlRawAsync(@"
IF OBJECT_ID(N'dbo.AspNetUsers','U') IS NOT NULL
 DELETE FROM [dbo].[AspNetUsers];");

                await tx.CommitAsync();

                _logger.LogWarning("Database purge executed by request. Rows affected (approx): {Total}", total);
                return Ok(new { success = true, message = "Database purge completed", rowsAffected = total });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Purge failed");
                return StatusCode(500, new { success = false, message = "Purge failed", error = ex.Message });
            }
        }*/
    }
}
