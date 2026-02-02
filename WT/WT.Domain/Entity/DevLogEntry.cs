using System.ComponentModel.DataAnnotations;

namespace WT.Domain.Entity
{
    public class DevLogEntry
    {
        [Key]
        public int Id { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        [MaxLength(5000)]
        public string Message { get; set; } = string.Empty;       
    }
}


