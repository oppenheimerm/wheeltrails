
using Microsoft.AspNetCore.Components.Forms;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Internal;

namespace WT.Application.Extensions
{

    public static class FileHelpers
    {

        /// <summary>
        /// Converts an IBrowserFile to IFormFile. This is useful when you need to handle file uploads 
        /// in a Blazor application.
        /// </summary>
        /// <param name="browserFile"></param>
        /// <returns></returns>
        public static async Task<IFormFile> ConvertToIFormFileAsync(IBrowserFile browserFile, long maxFileSize)
        {
            //  - Read the IBrowserFile stream using OpenReadStream().
            var stream = browserFile.OpenReadStream(maxFileSize);
            //  - Copy the stream into a MemoryStream.
            var memoryStream = new MemoryStream();
            //  - Create a new FormFile using the copied data.
            await stream.CopyToAsync(memoryStream);
            memoryStream.Position = 0;

            return new FormFile(memoryStream, 0, memoryStream.Length, browserFile.Name, browserFile.Name);
        }
    }
}
