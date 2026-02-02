
using System.ComponentModel.DataAnnotations;

namespace WT.Application.DTO.Request.Dev
{
    public class DevLogEntryDTO
    {
        [Required]
        [MaxLength(4000)]
        public string Message { get; set; } = string.Empty;
    }
}
