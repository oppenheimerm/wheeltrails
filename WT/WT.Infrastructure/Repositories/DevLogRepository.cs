using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using WT.Application.APIServiceLogs;
using WT.Application.Common.Paging;
using WT.Application.DTO.Request.Dev;
using WT.Application.DTO.Request.Trail;
using WT.Application.DTO.Response;
using WT.Application.DTO.Response.Account;
using WT.Application.DTO.Response.Dev;
using WT.Application.Services;
using WT.Domain.Entity;
using WT.Infrastructure.Data;

namespace WT.Infrastructure.Repositories
{
    public class DevLogRepository : IDevLogRepository
    {
        private readonly AppDbContext _context;

        int DefaultPageSize = 20;

        public DevLogRepository(AppDbContext context)
        {
            _context = context;
        }

        public async Task<BaseAPIResponseDTO> CreateDevLogAsync(DevLogEntryDTO model, CancellationToken cancellationToken = default)
        {
            if (model == null) throw new ArgumentNullException(nameof(model));

            // Observe cancellation early
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                // Ensure message is present and trim to reasonable length for DB column
                var message = (model.Message ?? string.Empty).Trim();
                if (message.Length > 5000)
                {
                    message = message.Substring(0, 5000);
                }

                var newLogEntry = new DevLogEntry
                {
                    Message = message,
                    CreatedAt = DateTime.UtcNow
                };

                // Use EF Core async APIs with the cancellation token
                await _context.DevLogEntries.AddAsync(newLogEntry, cancellationToken).ConfigureAwait(false);
                await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

                LogException.LogToFile($"Creating dev log entry: {message} at time: {DateTime.UtcNow}");

                return new BaseAPIResponseDTO(true, "Dev log entry created successfully");
            }
            catch (OperationCanceledException)
            {
                // Log cancellation
                LogException.LogToFile($"Dev log entry creation cancelled at time: {DateTime.UtcNow}");
                return new BaseAPIResponseDTO(false, "Dev log entry creation was cancelled");
            }
            catch (Exception ex)
            {
                LogException.LogExceptions(ex);
                return new BaseAPIResponseDTO(false, $"Error creating dev log entry: {ex.Message}");
            }
        }


        public async Task<PagedList<DevLogEntryReplyDTO>> GetAllDevLogsAsync(PagingParameters pagingParameters, CancellationToken cancellationToken = default)
        {
            if (pagingParameters == null) throw new ArgumentNullException(nameof(pagingParameters));

            if (pagingParameters.PageNumber <= 0)
                pagingParameters.PageNumber = 1;

            if (pagingParameters.PageSize <= 0)
                pagingParameters.PageSize = DefaultPageSize;

            // Project at database level into DTO so EF can translate to SQL
            var projected = _context.DevLogEntries
                .AsNoTracking()
                .Select(t => new DevLogEntryReplyDTO
                {
                    Id = t.Id,
                    Message = t.Message,
                    DateTime = t.CreatedAt
                });

            // Observe cancellation before starting the database work
            cancellationToken.ThrowIfCancellationRequested();

            // Use EF Core async creation which accepts a cancellation token
            return await PagedList<DevLogEntryReplyDTO>.CreateAsync(projected, pagingParameters.PageNumber, pagingParameters.PageSize, cancellationToken).ConfigureAwait(false);
        }
    }
}
