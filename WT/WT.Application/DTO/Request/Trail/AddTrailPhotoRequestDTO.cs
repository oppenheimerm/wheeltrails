
using Microsoft.AspNetCore.Http;
using System.ComponentModel.DataAnnotations;

namespace WT.Application.DTO.Request.Trail
{
    public class AddTrailPhotoRequestDTO
    {
        [Required]
        public Guid TrailId { get; set; }
        // UserId will be set from the authenticated user context in the controller/service
        //public Guid? UserId { get; set; }
        [Required]
        public IFormFile? TrailPhoto { get; set; }
        [Required]
        public string? ContentType { get; set; }

        /// <summary>
        /// Optional description or caption for the photo.
        /// </summary>
        [MaxLength(500, ErrorMessage = "Description has a maximum length of 500 characters.")]
        public string? Description { get; set; }
    }
}
