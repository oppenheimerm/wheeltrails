
using Microsoft.AspNetCore.Http;

namespace WT.Application.DTO.Request.Account
{
    public class UpdateProfilePhotoDTO
    {
        public IFormFile? ProfilePhoto { get; set; }
        public string? ContentType { get; set; }
    }
}
