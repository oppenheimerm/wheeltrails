using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using WT.Infrastructure.Data;
using WT.Domain.Entity;
using WT.Application.Extensions;

namespace API.Controllers.Admin
{
    /// <summary>
    /// Admin endpoints for inspecting and managing the persistent deletion queue.
    /// Requires admin role.
    /// </summary>
    [ApiController]
    [Route("api/admin/deletions")]
    [Authorize(Roles = Constants.Role.ADMIN_DEVELOPER)]
    public class DeletionQueueController : ControllerBase
    {
        private readonly AppDbContext _db;

        public DeletionQueueController(AppDbContext db)
        {
            _db = db;
        }

        /// <summary>
        /// List deletion queue items. Optional filter by status.
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> List([FromQuery] DeletionQueueStatus? status = null, [FromQuery] int take = 100)
        {
            var query = _db.DeletionQueue.AsNoTracking().OrderBy(d => d.NextAttemptAt).AsQueryable();
            if (status.HasValue) query = query.Where(d => d.Status == status.Value);
            var items = await query.Take(Math.Clamp(take, 1, 1000)).ToListAsync();
            return Ok(items);
        }

        /// <summary>
        /// Get a single queue item by id.
        /// </summary>
        [HttpGet("{id}")]
        public async Task<IActionResult> Get([FromRoute] Guid id)
        {
            var item = await _db.DeletionQueue.FindAsync(id);
            if (item == null) return NotFound();
            return Ok(item);
        }

        /// <summary>
        /// Requeue a failed or pending item to retry immediately.
        /// </summary>
        [HttpPost("{id}/requeue")]
        public async Task<IActionResult> Requeue([FromRoute] Guid id)
        {
            var item = await _db.DeletionQueue.FindAsync(id);
            if (item == null) return NotFound();
            item.Status = DeletionQueueStatus.Pending;
            item.AttemptCount = 0;
            item.NextAttemptAt = DateTime.UtcNow;
            item.LastError = null;
            item.UpdatedAt = DateTime.UtcNow;
            await _db.SaveChangesAsync();
            return Ok(item);
        }

        /// <summary>
        /// Delete a queue item (remove from queue). Use with caution.
        /// </summary>
        [HttpDelete("{id}")]
        public async Task<IActionResult> Delete([FromRoute] Guid id)
        {
            var item = await _db.DeletionQueue.FindAsync(id);
            if (item == null) return NotFound();
            _db.DeletionQueue.Remove(item);
            await _db.SaveChangesAsync();
            return NoContent();
        }
    }
}
