
using WT.Application.Common.Paging;
using WT.Application.DTO.Request.Dev;
using WT.Application.DTO.Response;
using WT.Application.DTO.Response.Dev;

namespace WT.Application.Services
{
    public interface IDevLogRepository
    {
        Task<BaseAPIResponseDTO> CreateDevLogAsync(DevLogEntryDTO model, CancellationToken cancellationToken = default);
        Task<PagedList<DevLogEntryReplyDTO>> GetAllDevLogsAsync(PagingParameters pagingParameters, CancellationToken cancellationToken = default);
    }
}
