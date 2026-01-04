namespace WT.Application.Extensions
{
    /// <summary>
    /// Utility helpers for lightweight image validation.
    /// </summary>
    /// <remarks>
    /// This class contains fast, non-exhaustive checks based on file "magic bytes" (file signatures)
    /// to validate that a provided <see cref="System.IO.Stream"/> likely contains an image.
    /// It is intended as a quick guard against spoofed MIME types before more expensive
    /// processing (e.g. ImageSharp decoding) is performed by downstream code.
    /// </remarks>
    public static class ImageUtils
    {
        /// <summary>
        /// Performs a lightweight validation of an image stream by inspecting the first
        /// bytes (magic bytes / file signature) and optionally comparing with the provided
        /// MIME <paramref name="contentType"/>.
        /// </summary>
        /// <param name="stream">Readable stream containing the file data. The method will try to seek to the start.</param>
        /// <param name="contentType">Optional MIME content type (for example "image/png"). When provided the method will
        /// prefer signatures that match the content type but will still accept a matching signature even when contentType is null.</param>
        /// <returns>
        /// <c>true</c> if the initial bytes match one of the supported image signatures (JPEG, PNG, WEBP, GIF);
        /// otherwise <c>false</c>.
        /// </returns>
        /// <remarks>
        /// - The method will not dispose the provided <paramref name="stream"/>.
        /// - If the stream supports seeking the method will attempt to seek to position0 and will
        /// leave the stream positioned at the end of the bytes it read. Callers should rewind the
        /// stream as needed before further processing.
        /// - This check is intentionally lightweight and prevents most basic spoofing attempts, but it
        /// is not a replacement for decoding the image (e.g., with ImageSharp) when strict validation
        /// is required.
        /// - Supported formats: JPEG, PNG, WEBP, GIF (based on common signatures).
        /// </remarks>
        public static bool IsValidImageStream(System.IO.Stream stream, string? contentType)
        {
            if (stream == null || !stream.CanRead) return false;
            // Read up to12 bytes
            Span<byte> header = stackalloc byte[12];
            int read = 0;
            try
            {
                stream.Seek(0, System.IO.SeekOrigin.Begin);
            }
            catch { }

            read = stream.Read(header);

            if (read >= 3)
            {
                // JPEG: FF D8 FF
                if (header[0] == 0xFF && header[1] == 0xD8 && header[2] == 0xFF)
                {
                    if (string.IsNullOrEmpty(contentType) || contentType.Contains("jpeg") || contentType.Contains("jpg"))
                        return true;
                }
            }

            if (read >= 8)
            {
                // PNG:89504E470D0A1A0A
                if (header[0] == 0x89 && header[1] == 0x50 && header[2] == 0x4E && header[3] == 0x47 && header[4] == 0x0D && header[5] == 0x0A && header[6] == 0x1A && header[7] == 0x0A)
                {
                    if (string.IsNullOrEmpty(contentType) || contentType.Contains("png"))
                        return true;
                }
            }

            if (read >= 12)
            {
                // WEBP: RIFF....WEBP (52494646 xxxx xxxx57454250)
                if (header[0] == (byte)'R' && header[1] == (byte)'I' && header[2] == (byte)'F' && header[3] == (byte)'F' && header[8] == (byte)'W' && header[9] == (byte)'E' && header[10] == (byte)'B' && header[11] == (byte)'P')
                {
                    if (string.IsNullOrEmpty(contentType) || contentType.Contains("webp"))
                        return true;
                }
            }

            if (read >= 4)
            {
                // GIF:47494638 (GIF8)
                if (header[0] == 0x47 && header[1] == 0x49 && header[2] == 0x46 && header[3] == 0x38)
                {
                    if (string.IsNullOrEmpty(contentType) || contentType.Contains("gif"))
                        return true;
                }
            }

            return false;
        }
    }
}
