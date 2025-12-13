using WT.Application.DTO.Request.Trail;
using WT.Application.DTO.Response;

namespace WT.Application.Services
{
    /// <summary>
    /// Repository interface for managing trail-related operations including creation, likes, and photo management.
    /// Defines contracts for trail data access and persistence operations.
    /// </summary>
    public interface IWTTrailRepository
    {
        /// <summary>
        /// Creates a new trail in the database with the provided details.
        /// </summary>
        /// <param name="model">DTO containing trail creation data including title, description, location, difficulty, and surface types</param>
        /// <param name="userId">GUID of the authenticated user creating the trail (derived from JWT token)</param>
        /// <returns>
        /// An <see cref="APIResponseCreateTrail"/> containing:
        /// - Success: true if trail created successfully, false otherwise
        /// - Message: Descriptive message about the operation result
        /// - TrailId: GUID of the newly created trail (if successful)
        /// - TrailTitle: Title of the newly created trail (if successful)
        /// </returns>
        /// <remarks>
        /// This method validates the user ID from the authentication context and logs trail creation events.
        /// All exceptions are caught, logged using <see cref="LogException"/>, and returned as error responses.
        /// </remarks>
        Task<APIResponseCreateTrail> CreateTrailAsync(CreateTrailDTO model, Guid userId);

        /// <summary>
        /// Adds a user's "like" to a trail with an optional rating.
        /// Ensures the trail exists and prevents duplicate likes from the same user.
        /// </summary>
        /// <param name="model">DTO containing the trail ID and optional rating (1-5 stars)</param>
        /// <param name="userId">GUID of the authenticated user liking the trail (derived from JWT token, NOT from model)</param>
        /// <returns>
        /// A <see cref="BaseAPIResponseDTO"/> containing:
        /// - Success: true if like added successfully, false if trail not found or already liked
        /// - Message: Descriptive message about the operation result
        /// </returns>
        /// <remarks>
        /// This method performs the following validations:
        /// 1. Verifies the trail exists in the database
        /// 2. Checks if the user has already liked this trail (prevents duplicates)
        /// 3. Sets LikedAt timestamp to current UTC time
        /// All operations are logged using <see cref="LogException.LogToFile"/>.
        /// The userId MUST come from the authenticated context for data integrity, never from the DTO.
        /// </remarks>
        Task<BaseAPIResponseDTO> AddTrailLikeAsync(AddTrailLikeDTO model, Guid userId);

        /// <summary>
        /// Removes a user's "like" from a trail by deleting the corresponding <see cref="TrailLike"/> entity.
        /// </summary>
        /// <param name="trailId">GUID of the trail to unlike</param>
        /// <param name="userId">GUID of the authenticated user removing their like (derived from JWT token)</param>
        /// <returns>
        /// A <see cref="BaseAPIResponseDTO"/> containing:
        /// - Success: true if like removed successfully, false if like not found
        /// - Message: Descriptive message including trail ID and user ID (if successful) or error details
        /// </returns>
        /// <remarks>
        /// This method verifies that a like exists for the specified trail and user before attempting removal.
        /// If no like is found, returns an error response without modifying the database.
        /// All operations are logged using <see cref="LogException.LogToFile"/>.
        /// Exceptions are caught and logged without exposing internal details to the client.
        /// </remarks>
        Task<BaseAPIResponseDTO> UnlikeTraiAsync(Guid trailId, Guid userId);

        /// <summary>
        /// Adds a trail photo entity to the database after the photo has been uploaded to Firebase Storage.
        /// This method ONLY handles database persistence; file upload must be completed beforehand.
        /// </summary>
        /// <param name="model">DTO containing Firebase Storage URL (PhotoName) and metadata (TrailId, Description)</param>
        /// <returns>
        /// A <see cref="BaseAPIResponseDTO"/> containing:
        /// - Success: true if photo metadata saved successfully, false if trail not found or database error
        /// - Message: Descriptive message about the operation result
        /// </returns>
        /// <remarks>
        /// <para>
        /// <strong>Important:</strong> This method assumes the photo file has already been uploaded to Firebase Storage.
        /// The PhotoName property should contain the complete Firebase Storage URL.
        /// </para>
        /// <para>
        /// The method performs the following operations:
        /// 1. Validates that the trail exists using <see cref="AppDbContext.Trails"/>
        /// 2. Creates a new <see cref="WTTrailPhoto"/> entity with server-generated ID and timestamp
        /// 3. Persists the entity to the database
        /// </para>
        /// <para>
        /// All exceptions are logged using <see cref="LogException.LogExceptions"/> without exposing internal details.
        /// </para>
        /// </remarks>
        Task<BaseAPIResponseDTO> AddTrailPhotoAsync(AddTrailPhotoDbEntityDTO model);
    }
}
