using System.IO;
using WT.Application.Extensions;
using Xunit;

namespace WT.Application.Tests.ImageUtilsTests
{
    public class ImageUtilsTests
    {
        [Fact]
        public void IsValidImageStream_ReturnsTrue_For_JpegHeader()
        {
            // Arrange: JPEG header FF D8 FF
            var data = new byte[] { 0xFF, 0xD8, 0xFF, 0x00, 0x00 };
            using var ms = new MemoryStream(data);

            // Act
            var resultNoContentType = ImageUtils.IsValidImageStream(ms, null);

            // Assert
            Assert.True(resultNoContentType);

            // With matching content type
            ms.Seek(0, SeekOrigin.Begin);
            var resultWithContentType = ImageUtils.IsValidImageStream(ms, "image/jpeg");
            Assert.True(resultWithContentType);

            // With non-matching content type
            ms.Seek(0, SeekOrigin.Begin);
            var resultMismatched = ImageUtils.IsValidImageStream(ms, "image/png");
            Assert.False(resultMismatched);
        }

        [Fact]
        public void IsValidImageStream_ReturnsTrue_For_PngHeader()
        {
            // PNG signature:89504E470D0A1A0A
            var data = new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00 };
            using var ms = new MemoryStream(data);

            var resultNoContentType = ImageUtils.IsValidImageStream(ms, null);
            Assert.True(resultNoContentType);

            ms.Seek(0, SeekOrigin.Begin);
            var resultWithContentType = ImageUtils.IsValidImageStream(ms, "image/png");
            Assert.True(resultWithContentType);
        }

        [Fact]
        public void IsValidImageStream_ReturnsTrue_For_WebpHeader()
        {
            // WEBP header: 'RIFF' (52494646) +4 bytes + 'WEBP' (57454250)
            var data = new byte[] { (byte)'R', (byte)'I', (byte)'F', (byte)'F', 0x00, 0x00, 0x00, 0x00, (byte)'W', (byte)'E', (byte)'B', (byte)'P' };
            using var ms = new MemoryStream(data);

            var resultNoContentType = ImageUtils.IsValidImageStream(ms, null);
            Assert.True(resultNoContentType);

            ms.Seek(0, SeekOrigin.Begin);
            var resultWithContentType = ImageUtils.IsValidImageStream(ms, "image/webp");
            Assert.True(resultWithContentType);
        }

        [Fact]
        public void IsValidImageStream_ReturnsTrue_For_GifHeader()
        {
            // GIF header: 'GIF8' ->47494638
            var data = new byte[] { 0x47, 0x49, 0x46, 0x38, 0x00 };
            using var ms = new MemoryStream(data);

            var resultNoContentType = ImageUtils.IsValidImageStream(ms, null);
            Assert.True(resultNoContentType);

            ms.Seek(0, SeekOrigin.Begin);
            var resultWithContentType = ImageUtils.IsValidImageStream(ms, "image/gif");
            Assert.True(resultWithContentType);
        }

        [Fact]
        public void IsValidImageStream_ReturnsFalse_For_InvalidData()
        {
            var data = System.Text.Encoding.UTF8.GetBytes("this is not an image");
            using var ms = new MemoryStream(data);

            var result = ImageUtils.IsValidImageStream(ms, null);
            Assert.False(result);

            ms.Seek(0, SeekOrigin.Begin);
            // Even if content type claims image/png, magic bytes don't match
            var resultMismatched = ImageUtils.IsValidImageStream(ms, "image/png");
            Assert.False(resultMismatched);
        }
    }
}
