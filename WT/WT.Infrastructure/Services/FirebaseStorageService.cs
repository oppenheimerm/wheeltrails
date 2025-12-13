using FirebaseAdmin;
using Google.Apis.Auth.OAuth2;
using Google.Cloud.Storage.V1;
using Microsoft.Extensions.Configuration;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.Processing;
using SixLabors.ImageSharp.Formats.Jpeg;
using WT.Application.APIServiceLogs;
using WT.Application.Contracts;

namespace WT.Infrastructure.Services
{
    /// <summary>
    /// Firebase Storage implementation using Firebase Admin SDK.
    /// Authenticates via Service Account JSON file.
    /// FREE TIER: 5GB storage, 1GB/day bandwidth, 20k downloads/day, 20k uploads/day
    /// </summary>
    public class FirebaseStorageService : IFileStorageService
    {
        private readonly StorageClient _storageClient;
        private readonly string _bucketName;
        private static bool _firebaseInitialized = false;
        private static readonly object _lock = new object();

        public FirebaseStorageService(IConfiguration configuration)
        {
            var serviceAccountPath = configuration["Firebase:ServiceAccountKeyPath"];
            _bucketName = configuration["Firebase:StorageBucket"]!;

            if (string.IsNullOrEmpty(serviceAccountPath))
            {
                throw new InvalidOperationException(
                    "Firebase:ServiceAccountKeyPath is not configured in User Secrets. " +
                    "Please set it using: dotnet user-secrets set \"Firebase:ServiceAccountKeyPath\" \"path/to/firebase-adminsdk.json\"");
            }

            if (!File.Exists(serviceAccountPath))
            {
                throw new FileNotFoundException(
                    $"Firebase service account key file not found at: {serviceAccountPath}. " +
                    $"Please download the JSON file from Firebase Console and update the path in User Secrets.");
            }

            // Initialize Firebase Admin SDK (singleton pattern)
            lock (_lock)
            {
                if (!_firebaseInitialized)
                {
                    try
                    {
                        FirebaseApp.Create(new AppOptions
                        {
                            Credential = GoogleCredential.FromFile(serviceAccountPath)
                        });
                        _firebaseInitialized = true;
                        LogException.LogToFile($"Firebase Admin SDK initialized successfully at {DateTime.UtcNow}");
                    }
                    catch (Exception ex)
                    {
                        LogException.LogExceptions(ex);
                        throw new InvalidOperationException($"Failed to initialize Firebase Admin SDK: {ex.Message}", ex);
                    }
                }
            }

            // Initialize Storage Client
            var credential = GoogleCredential.FromFile(serviceAccountPath);
            _storageClient = StorageClient.Create(credential);
        }

        /// <summary>
        /// Uploads profile picture: max 400x400px, 80% JPEG quality.
        /// Path: profile-pictures/{userId}/{uniqueFileName}
        /// </summary>
        public async Task<string> UploadProfilePictureAsync(Stream stream, string fileName, Guid userId)
        {
            try
            {
                // Optimize image for profile picture (smaller size, lower quality)
                using var optimizedStream = await OptimizeImageAsync(stream, maxWidth: 400, maxHeight: 400, quality: 80);

                // ✅ CORRECT: Guaranteed unique filenames
                var uniqueFileName = $"{Guid.NewGuid()}_{SanitizeFileName(fileName)}";
                var objectName = $"profile-pictures/{userId}/{uniqueFileName}";

                var downloadUrl = await UploadToFirebaseAsync(optimizedStream, objectName, "image/jpeg");

                LogException.LogToFile($"✅ Profile picture uploaded: {objectName} (User: {userId}) at {DateTime.UtcNow}");
                return downloadUrl;
            }
            catch (Exception ex)
            {
                LogException.LogExceptions(ex);
                throw new Exception($"Failed to upload profile picture: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Uploads trail photo: max 1200x1200px, 85% JPEG quality.
        /// Path: trail-photos/{trailId}/{uniqueFileName}
        /// </summary>
        public async Task<string> UploadTrailPhotoAsync(Stream stream, string fileName, Guid trailId)
        {
            try
            {
                // Optimize image for trail photo (larger size, higher quality)
                using var optimizedStream = await OptimizeImageAsync(stream, maxWidth: 1200, maxHeight: 1200, quality: 85);

                // ✅ CORRECT: Guaranteed unique filenames
                var uniqueFileName = $"{Guid.NewGuid()}_{SanitizeFileName(fileName)}";
                var objectName = $"trail-photos/{trailId}/{uniqueFileName}";

                var downloadUrl = await UploadToFirebaseAsync(optimizedStream, objectName, "image/jpeg");

                LogException.LogToFile($"✅ Trail photo uploaded: {objectName} (Trail: {trailId}) at {DateTime.UtcNow}");
                return downloadUrl;
            }
            catch (Exception ex)
            {
                LogException.LogExceptions(ex);
                throw new Exception($"Failed to upload trail photo: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Deletes a file from Firebase Storage.
        /// Extracts object name from public URL.
        /// </summary>
        public async Task<bool> DeleteFileAsync(string fileUrl)
        {
            try
            {
                // Extract object name from public URL
                // Format: https://storage.googleapis.com/{bucket}/{objectName}
                var uri = new Uri(fileUrl);
                var pathSegments = uri.AbsolutePath.TrimStart('/').Split('/');

                // Remove bucket name from path (first segment)
                var objectName = string.Join("/", pathSegments.Skip(1));

                await _storageClient.DeleteObjectAsync(_bucketName, objectName);

                LogException.LogToFile($"✅ File deleted from Firebase: {objectName} at {DateTime.UtcNow}");
                return true;
            }
            catch (Exception ex)
            {
                LogException.LogExceptions(ex);
                LogException.LogToFile($"❌ Failed to delete file from Firebase: {fileUrl}. Error: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Gets download URL for an existing Firebase Storage object.
        /// </summary>
        public async Task<string> GetDownloadUrlAsync(string objectName)
        {
            try
            {
                // For publicly readable objects, construct the URL directly
                var publicUrl = $"https://storage.googleapis.com/{_bucketName}/{objectName}";
                
                // Verify object exists
                await _storageClient.GetObjectAsync(_bucketName, objectName);

                return publicUrl;
            }
            catch (Exception ex)
            {
                LogException.LogExceptions(ex);
                throw new Exception($"Failed to get download URL for {objectName}: {ex.Message}", ex);
            }
        }

        #region Private Helpers

        /// <summary>
        /// Core Firebase upload using Google Cloud Storage Client.
        /// Makes objects publicly readable via PredefinedAcl.
        /// </summary>
        private async Task<string> UploadToFirebaseAsync(Stream stream, string objectName, string contentType)
        {
            try
            {
                // Upload to Firebase Storage (which uses Google Cloud Storage)
                var storageObject = await _storageClient.UploadObjectAsync(
                    bucket: _bucketName,
                    objectName: objectName,
                    contentType: contentType,
                    source: stream,
                    options: new UploadObjectOptions
                    {
                        PredefinedAcl = PredefinedObjectAcl.PublicRead // Make publicly accessible
                    }
                );

                // Return public URL
                var publicUrl = $"https://storage.googleapis.com/{_bucketName}/{objectName}";
                return publicUrl;
            }
            catch (Exception ex)
            {
                LogException.LogExceptions(ex);
                throw new Exception($"Firebase upload failed for {objectName}: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Optimizes image using SixLabors.ImageSharp.
        /// Resizes maintaining aspect ratio and compresses with JPEG encoding.
        /// </summary>
        private async Task<MemoryStream> OptimizeImageAsync(Stream inputStream, int maxWidth, int maxHeight, int quality)
        {
            using var image = await Image.LoadAsync(inputStream);

            // ✅ Calculate aspect ratio to avoid distortion
            var ratioX = (double)maxWidth / image.Width;
            var ratioY = (double)maxHeight / image.Height;
            var ratio = Math.Min(ratioX, ratioY);

            // ✅ Only resize if image is larger than max dimensions
            if (ratio < 1.0)
            {
                var newWidth = (int)(image.Width * ratio);
                var newHeight = (int)(image.Height * ratio);
                image.Mutate(x => x.Resize(newWidth, newHeight));
            }

            // ✅ Compress with JPEG
            var outputStream = new MemoryStream();
            var encoder = new JpegEncoder { Quality = quality };
            await image.SaveAsync(outputStream, encoder);

            outputStream.Position = 0;
            return outputStream;
        }

        /// <summary>
        /// Sanitizes file name to prevent path traversal attacks and invalid characters.
        /// </summary>
        private string SanitizeFileName(string fileName)
        {
            // Get only the file name (removes any path components)
            var sanitized = Path.GetFileName(fileName);

            // Replace invalid file name characters with underscore
            var invalidChars = Path.GetInvalidFileNameChars();
            foreach (var c in invalidChars)
            {
                sanitized = sanitized.Replace(c, '_');
            }

            return sanitized;
        }

        #endregion
    }
}