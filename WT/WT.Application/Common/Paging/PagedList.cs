#nullable enable
using Microsoft.EntityFrameworkCore;

namespace WT.Application.Common.Paging
{
    /// <summary>
    /// Simple paged list container with metadata.
    /// </summary>
    public class PagedList<T> : List<T>
    {
        public int CurrentPage { get; private init; }
        public int PageSize { get; private init; }
        public int TotalCount { get; private init; }
        public int TotalPages { get; private init; }

        public bool HasPrevious => CurrentPage > 1;
        public bool HasNext => CurrentPage < TotalPages;

        private PagedList(IEnumerable<T> items, int count, int pageNumber, int pageSize)
        {
            AddRange(items);
            TotalCount = count;
            PageSize = pageSize;
            CurrentPage = pageNumber;
            TotalPages = (int)Math.Ceiling(count / (double)pageSize);
        }

        /// <summary>
        /// Synchronous creation from an IQueryable source.
        /// Useful when repository method is synchronous.
        /// </summary>
        public static PagedList<T> Create(IQueryable<T> source, int pageNumber, int pageSize)
        {
            var count = source.Count();
            var items = source.Skip((pageNumber - 1) * pageSize).Take(pageSize).ToList();
            return new PagedList<T>(items, count, pageNumber, pageSize);
        }

        /// <summary>
        /// Async creation from an IQueryable source (EF Core).
        /// </summary>
        public static async Task<PagedList<T>> CreateAsync(IQueryable<T> source, int pageNumber, int pageSize, CancellationToken cancellationToken = default)
        {
            var count = await source.CountAsync(cancellationToken).ConfigureAwait(false);
            var items = await source.Skip((pageNumber - 1) * pageSize).Take(pageSize).ToListAsync(cancellationToken).ConfigureAwait(false);
            return new PagedList<T>(items, count, pageNumber, pageSize);
        }
    }
}
