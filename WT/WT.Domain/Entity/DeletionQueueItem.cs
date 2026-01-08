using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace WT.Domain.Entity
{
    /// <summary>
    /// Persistent queue item representing a file to delete from remote storage (e.g., Firebase).
    /// Worker will process items in Pending state and perform retries with backoff.
    /// </summary>
    public class DeletionQueueItem
    {
        [Key]
        public Guid Id { get; set; } = Guid.NewGuid();

        /// <summary>
        /// Public URL of the file to delete (as stored in WTTrailPhoto.PhotoUrl or ApplicationUser.ProfilePicture)
        /// </summary>
        [Required]
        [MaxLength(1024)]
        public string FileUrl { get; set; } = string.Empty;

        /// <summary>
        /// Optional ID of the user related to this deletion (helps audits / tracing)
        /// </summary>
        public Guid? RelatedUserId { get; set; }

        /// <summary>
        /// Number of attempts already made to delete the file.
        /// </summary>
        public int AttemptCount { get; set; } = 0;

        /// <summary>
        /// Time after which the item should be retried. Used for exponential backoff.
        /// </summary>
        public DateTime NextAttemptAt { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Status of the queue item.
        /// </summary>
        public DeletionQueueStatus Status { get; set; } = DeletionQueueStatus.Pending;

        /// <summary>
        /// Last error message recorded from a failed attempt (if any).
        /// </summary>
        [MaxLength(2000)]
        public string? LastError { get; set; }

        /// <summary>
        /// When the queue item was created.
        /// </summary>
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// When the queue item was last updated.
        /// </summary>
        public DateTime? UpdatedAt { get; set; }
    }

    public enum DeletionQueueStatus
    {
        Pending = 0,
        InProgress = 1,
        Succeeded = 2,
        Failed = 3
    }
}
