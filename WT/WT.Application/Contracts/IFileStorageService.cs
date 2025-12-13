namespace WT.Application.Contracts
{
    /// <summary>
    /// File storage service for uploading and managing profile pictures and trail photos.
    /// Uses Firebase Storage with automatic image optimization via SixLabors.ImageSharp.
    /// </summary>
    public interface IFileStorageService
    {
        /// <summary>
        /// Uploads a profile picture with automatic optimization.
        /// Resizes to max 400x400px, 80% JPEG quality.
        /// </summary>
        /// <param name="stream">Image file stream</param>
        /// <param name="fileName">Original file name</param>
        /// <param name="userId">User ID for folder organization</param>
        /// <returns>Public URL of uploaded profile picture</returns>
        Task<string> UploadProfilePictureAsync(Stream stream, string fileName, Guid userId);

        /// <summary>
        /// Uploads a trail photo with automatic optimization.
        /// Resizes to max 1200x1200px, 85% JPEG quality.
        /// </summary>
        /// <param name="stream">Image file stream</param>
        /// <param name="fileName">Original file name</param>
        /// <param name="trailId">Trail ID for folder organization</param>
        /// <returns>Public URL of uploaded trail photo</returns>
        Task<string> UploadTrailPhotoAsync(Stream stream, string fileName, Guid trailId);

        /// <summary>
        /// Deletes a file from Firebase Storage.
        /// </summary>
        /// <param name="fileUrl">Full Firebase Storage public URL</param>
        /// <returns>True if deleted successfully, false otherwise</returns>
        Task<bool> DeleteFileAsync(string fileUrl);

        /// <summary>
        /// Gets download URL for an existing file.
        /// </summary>
        /// <param name="objectName">Firebase Storage object path (e.g., "profile-pictures/userId/file.jpg")</param>
        /// <returns>Public download URL</returns>
        Task<string> GetDownloadUrlAsync(string objectName);
    }
}