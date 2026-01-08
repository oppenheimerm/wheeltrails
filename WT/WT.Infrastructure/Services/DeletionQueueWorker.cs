using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;
using System.Threading;
using System.Threading.Tasks;
using WT.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using WT.Application.Contracts;
using System;
using WT.Domain.Entity;
using System.Linq;
using System.Diagnostics;

namespace WT.Infrastructure.Services
{
    /// <summary>
    /// Hosted background worker that processes persistent deletion queue items.
    /// - Picks Pending items whose NextAttemptAt <= now
    /// - Marks InProgress and attempts deletion using IFileStorageService
    /// - Uses configurable short in-memory retry attempts before persisting failure
    /// - Uses exponential backoff and records AttemptCount/NextAttemptAt in the DB
    /// - Records metrics via ILogger (can be replaced with a metrics provider)
    /// </summary>
    public class DeletionQueueWorker : BackgroundService
    {
        private readonly IServiceProvider _services;
        private readonly ILogger<DeletionQueueWorker> _logger;
        private readonly TimeSpan _pollInterval = TimeSpan.FromSeconds(10);
        private readonly int _maxAttempts = 5;
        private readonly int[] _inlineRetries = new[] { 1, 2, 4 }; // seconds between immediate retries

        public DeletionQueueWorker(IServiceProvider services, ILogger<DeletionQueueWorker> logger)
        {
            _services = services;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("DeletionQueueWorker started.");
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await ProcessPendingItemsAsync(stoppingToken);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Unexpected error in DeletionQueueWorker");
                }
                await Task.Delay(_pollInterval, stoppingToken);
            }
        }

        private async Task ProcessPendingItemsAsync(CancellationToken ct)
        {
            using var scope = _services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var storage = scope.ServiceProvider.GetRequiredService<IFileStorageService>();

            // Fetch one item to process (Pending && NextAttemptAt <= now)
            var item = await db.DeletionQueue
            .Where(d => d.Status == DeletionQueueStatus.Pending && d.NextAttemptAt <= DateTime.UtcNow)
            .OrderBy(d => d.CreatedAt)
            .FirstOrDefaultAsync(ct);

            if (item == null) return;

            // Mark InProgress
            item.Status = DeletionQueueStatus.InProgress;
            item.UpdatedAt = DateTime.UtcNow;
            await db.SaveChangesAsync(ct);

            _logger.LogInformation("Processing deletion item {Id} (attempt {Attempt}) for {Url}", item.Id, item.AttemptCount + 1, item.FileUrl);

            var sw = Stopwatch.StartNew();

            bool success = false;
            string? lastError = null;

            // Inline short retries to handle transient errors quickly without incrementing persisted AttemptCount
            foreach (var delaySec in _inlineRetries)
            {
                try
                {
                    success = await storage.DeleteFileAsync(item.FileUrl);
                    if (success) break;
                    lastError = "DeleteFileAsync returned false";
                }
                catch (Exception ex)
                {
                    lastError = ex.Message;
                    _logger.LogWarning(ex, "Inline delete attempt failed for {Url}", item.FileUrl);
                }

                // wait before next inline retry
                await Task.Delay(TimeSpan.FromSeconds(delaySec), ct);
            }

            if (success)
            {
                item.Status = DeletionQueueStatus.Succeeded;
                item.UpdatedAt = DateTime.UtcNow;
                await db.SaveChangesAsync(ct);
                _logger.LogInformation("Successfully deleted file {Url} (queue id {Id})", item.FileUrl, item.Id);

                sw.Stop();
                _logger.LogInformation("DeletionQueue processed {Id} in {Ms}ms", item.Id, sw.Elapsed.TotalMilliseconds);
            }
            else
            {
                // Failure - increase attempt count and reschedule (exponential backoff)
                item.AttemptCount += 1;
                item.LastError = lastError ?? "Unknown error";
                item.UpdatedAt = DateTime.UtcNow;
                if (item.AttemptCount >= _maxAttempts)
                {
                    item.Status = DeletionQueueStatus.Failed;
                    _logger.LogWarning("Marking deletion item {Id} as Failed after {AttemptCount} attempts", item.Id, item.AttemptCount);

                    sw.Stop();
                    _logger.LogWarning("DeletionQueue item {Id} permanently failed: {Error}", item.Id, item.LastError);
                }
                else
                {
                    // Exponential backoff:2^attempt seconds
                    var delaySeconds = Math.Pow(2, item.AttemptCount);
                    item.NextAttemptAt = DateTime.UtcNow.AddSeconds(delaySeconds);
                    item.Status = DeletionQueueStatus.Pending;
                    _logger.LogWarning("Deletion failed for {Url}. Will retry at {NextAttempt} (attempt {AttemptCount})", item.FileUrl, item.NextAttemptAt, item.AttemptCount);

                    sw.Stop();
                    _logger.LogInformation("DeletionQueue item {Id} scheduled retry at {NextAttempt}", item.Id, item.NextAttemptAt);
                }
                await db.SaveChangesAsync(ct);
            }
        }
    }
}
