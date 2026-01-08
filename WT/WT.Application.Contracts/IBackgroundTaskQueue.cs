using System;
using System.Threading;
using System.Threading.Tasks;

namespace WT.Application.Contracts
{
    /// <summary>
    /// Lightweight background task queue contract for enqueuing fire-and-forget work items.
    /// Work items are executed by a hosted BackgroundService.
    /// </summary>
    public interface IBackgroundTaskQueue
    {
        /// <summary>
        /// Enqueue a work item represented by a function that accepts a CancellationToken.
        /// </summary>
        /// <param name="workItem">The work item to execute.</param>
        void QueueBackgroundWorkItem(Func<CancellationToken, Task> workItem);

        /// <summary>
        /// Dequeue the next work item. Implementations should block until an item is available.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token used to abort waiting.</param>
        /// <returns>The work item.</returns>
        Task<Func<CancellationToken, Task>> DequeueAsync(CancellationToken cancellationToken);
    }
}
