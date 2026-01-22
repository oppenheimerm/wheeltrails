#nullable enable
using System.ComponentModel.DataAnnotations;

namespace WT.Application.Common.Paging
{
    /// <summary>
    /// Parameters used for paging queries across the application.   PagingParameters is placed
    /// in the Application layer so it becomes a cross-layer contract (usable by controllers, 
    /// services and repositories).
    /// 
    /// Reason: paging parameters are a DTO/contract (not infrastructure-specific). The Application 
    /// project already holds DTOs and shared contracts per project conventions.
    /// 
    /// PagingParameters is "sealed" to make the paging contract a small, fixed API surface: 
    /// It prevents consumers from inheriting and changing behavior which simplifies versioning, 
    /// validation and reasoning about repository/controller code.
    /// </summary>
    public sealed class PagingParameters
    {
        private const int MaxPageSize = 100;

        /// <summary>
        /// Page number (1-based). Defaults to 1.
        /// </summary>
        [Range(1, int.MaxValue)]
        public int PageNumber { get; set; } = 1;

        private int _pageSize = 20;

        /// <summary>
        /// Page size. Defaults to 20. Capped by <see cref="MaxPageSize"/>.
        /// </summary>
        [Range(1, MaxPageSize)]
        public int PageSize
        {
            get => _pageSize;
            set => _pageSize = value <= 0 ? 20 : Math.Min(value, MaxPageSize);
        }

        /// <summary>
        /// Optional search/filter text (controller/service may interpret).
        /// </summary>
        public string? Search { get; set; }

        /// <summary>
        /// Optional order by clause (e.g. "createdAt desc"). Repository interprets safely.
        /// </summary>
        public string? OrderBy { get; set; }
    }
}
