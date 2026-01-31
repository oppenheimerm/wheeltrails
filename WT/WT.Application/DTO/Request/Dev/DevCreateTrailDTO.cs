
using WT.Application.DTO.Request.Trail;

namespace WT.Application.DTO.Request.Dev
{
    public class DevCreateTrailDTO : CreateTrailDTO
    {
        public string? ErrorMessage { get; set; }
    }
}
