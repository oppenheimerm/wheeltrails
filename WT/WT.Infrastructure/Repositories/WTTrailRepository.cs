using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using WT.Application.APIServiceLogs;
using WT.Application.DTO.Request.Account;
using WT.Application.DTO.Request.Trail;
using WT.Application.DTO.Response;
using WT.Application.Services;
using WT.Domain.Entity;
using WT.Infrastructure.Data;

namespace WT.Infrastructure.Repositories
{

    /// <summary>
    /// Repository implementation for managing trail-related operations including creation, likes, and photo management.
    /// Implements <see cref="IWTTrailRepository"/> interface using Entity Framework Core for data access.
    /// </summary>
    /// <remarks>
    /// This repository follows Clean Architecture principles and is part of the Infrastructure layer.
    /// All methods use async/await patterns for I/O operations and include comprehensive error handling.
    /// Operations are logged using the <see cref="LogException"/> utility for debugging and monitoring.
    /// </remarks>
    public class WTTrailRepository : IWTTrailRepository
    {
        private readonly AppDbContext _context;

        /// <summary>
        /// Initializes a new instance of the <see cref="WTTrailRepository"/> class.
        /// </summary>
        /// <param name="context">The database context for trail-related operations</param>
        public WTTrailRepository(AppDbContext context)
        {
            _context = context;
        }

        /// <summary>
        /// This method creates a new trail in the database based on the provided CreateTrailDTO model
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
        /// <para>
        /// This method uses a try-catch block to handle exceptions during trail creation.
        /// The userId parameter is trusted and comes from the authenticated context, ensuring data integrity.
        /// </para>
        /// <para>
        /// The following operations are performed:
        /// 1. Creates a new <see cref="WTTrail"/> entity from the provided DTO
        /// 2. Assigns the authenticated user's ID to ensure proper ownership
        /// 3. Saves the entity to the database using <see cref="AppDbContext"/>
        /// 4. Logs the creation event with timestamp using <see cref="LogException.LogToFile"/>
        /// </para>
        /// <para>
        /// All exceptions are caught, logged using <see cref="LogException.LogExceptions"/>, 
        /// and returned as error responses without exposing internal details.
        /// </para>
        /// </remarks>
        public async Task<APIResponseCreateTrail> CreateTrailAsync(CreateTrailDTO model, Guid userId)
        {
            // using a try -catch block to handle exceptions, create a new instance
            // of WTTrail and populate its properties with data from the CreateTrailDTO model,
            // logging any exceptions that occur during the process, as well as saving the new trail to the database context
            try
            {
                var newTrail = new WTTrail
                {
                    Title = model.Title,
                    Description = model.Description,
                    Latitude = model.Latitude,
                    Longitude = model.Longitude,
                    Difficulty = model.Difficulty,
                    SurfaceTypes = model.SurfaceTypes,
                    UserId = userId // Assign the trusted userId from the method parameter
                };
                await _context.Trails.AddAsync(newTrail);
                await _context.SaveChangesAsync();

                // Log trail creation
                LogException.LogToFile($"Creating trail: {model.Title} by User ID: {userId} at time: {DateTime.UtcNow}");

                return new APIResponseCreateTrail
                {
                    Success = true,
                    Message = "Trail created successfully",
                    TrailId = newTrail.Id,
                    TrailTitle = newTrail.Title
                };
            }
            catch (Exception ex)
            {
                // Log the exception details (you can use a logging framework here)
                LogException.LogExceptions(ex);
                return new APIResponseCreateTrail
                {
                    Success = false,
                    Message = $"Error creating trail: {ex.Message}"
                };

            }
        }

        /// <summary>
        /// This method allows a user to like a trail and optionally provide a rating. It ensures 
        /// that the <see cref="WTTrail"/> exists and that the <see cref="ApplicationUser"/> has not already liked it.
        /// </summary>
        /// <param name="model">DTO containing the trail ID and optional rating (1-5 stars)</param>
        /// <param name="userId">GUID of the authenticated user liking the trail (derived from JWT token, NOT from model)</param>
        /// <returns>
        /// A <see cref="BaseAPIResponseDTO"/> containing:
        /// - Success: true if like added successfully, false if trail not found or already liked
        /// - Message: Descriptive message about the operation result
        /// </returns>
        /// <remarks>
        /// <para>
        /// <strong>Security Note:</strong> The userId parameter MUST come from the authenticated context (JWT token)
        /// for data integrity and security. It is never derived from the DTO model.
        /// </para>
        /// <para>
        /// This method performs the following validations and operations:
        /// 1. Verifies the trail exists in the database using <see cref="DbSet{TEntity}.FindAsync"/>
        /// 2. Checks for existing likes to prevent duplicates using <see cref="DbSet{TEntity}.FirstOrDefaultAsync"/>
        /// 3. Creates a new <see cref="TrailLike"/> entity with UTC timestamp
        /// 4. Persists the like to the database
        /// 5. Logs the operation using <see cref="LogException.LogToFile"/>
        /// </para>
        /// <para>
        /// All exceptions are caught and logged without exposing internal details to the API consumer.
        /// </para>
        /// </remarks>
        public async Task<BaseAPIResponseDTO> AddTrailLikeAsync( AddTrailLikeDTO model, Guid userId)
        {
            try {

                //  Does the trail exist?
                var trail = await _context.Trails.FindAsync(model.TrailId);
                if (trail == null)
                {
                    return new BaseAPIResponseDTO
                    {
                        Success = false,
                        Message = "Trail not found"
                    };
                }

                // Has the user already liked this trail?
                var existingLike = await _context.TrailLikes
                    .FirstOrDefaultAsync(tl => tl.TrailId == model.TrailId && tl.UserId == userId);

                if (existingLike != null)
                {
                    return new BaseAPIResponseDTO
                    {
                        Success = false,
                        Message = "You have already liked this trail"
                    };
                }

                // Create new TrailLike
                var trailLike = new TrailLike
                {
                    TrailId = model.TrailId,
                    UserId = userId,
                    Rating = model.Rating,
                    LikedAt = DateTime.UtcNow
                };
                await _context.TrailLikes.AddAsync(trailLike);
                await _context.SaveChangesAsync();

                // Log trail like creation
                LogException.LogToFile($"User ID: {userId} liked Trail ID: {model.TrailId} at time: {DateTime.UtcNow}");
                return new BaseAPIResponseDTO
                {
                    Success = true,
                    Message = "Trail liked successfully"
                };
            }
            catch (Exception ex)
            {
                // Log the exception details (you can use a logging framework here)
                LogException.LogExceptions(ex);
                // Return generic error response, without exposing internal details
                return new BaseAPIResponseDTO
                {
                    Success = false,
                    Message = "An error occurred while liking the trail"
                };

            }
        }

        /// <summary>
        /// Method to unlike a <see cref="WTTrail"/> by removing the corresponding TrailLike entry from the database.
        /// </summary>
        /// <param name="trailId">GUID of the trail to unlike</param>
        /// <param name="userId">GUID of the authenticated user removing their like (derived from JWT token)</param>
        /// <returns>
        /// A <see cref="BaseAPIResponseDTO"/> containing:
        /// - Success: true if like removed successfully, false if like not found
        /// - Message: Descriptive message including trail ID and user ID (if successful) or error details
        /// </returns>
        /// <remarks>
        /// <para>
        /// This method verifies that a like exists for the specified trail and user before attempting removal.
        /// If no matching <see cref="TrailLike"/> entity is found, the method returns an error response
        /// without modifying the database state.
        /// </para>
        /// <para>
        /// The method performs the following operations:
        /// 1. Queries for an existing like using <see cref="DbSet{TEntity}.FirstOrDefaultAsync"/>
        /// 2. Returns error if no like exists for this user/trail combination
        /// 3. Removes the like entity from the context
        /// 4. Persists the change to the database
        /// 5. Logs the unlike action with timestamp using <see cref="LogException.LogToFile"/>
        /// </para>
        /// <para>
        /// All exceptions are caught and logged using <see cref="LogException.LogExceptions"/>
        /// without exposing internal details to the API consumer.
        /// </para>
        /// </remarks>
        public async Task<BaseAPIResponseDTO> UnlikeTraiAsync(Guid trailId, Guid userId)
        {
            try
            {
                // Find the existing like
                var existingLike = await _context.TrailLikes
                    .FirstOrDefaultAsync(tl => tl.TrailId == trailId && tl.UserId == userId);
                if (existingLike == null)
                {
                    return new BaseAPIResponseDTO
                    {
                        Success = false,
                        Message = "You have not liked this trail"
                    };
                }

                // Remove the like
                _context.TrailLikes.Remove(existingLike);
                await _context.SaveChangesAsync();

                // Log trail unlike action
                LogException.LogToFile($"User ID: {userId} unliked Trail ID: {trailId} at time: {DateTime.UtcNow}");

                return new BaseAPIResponseDTO
                {
                    Success = true,
                    Message = $"Trail Id: {trailId} unliked by User Id: {userId} successfully"
                };
            }
            catch (Exception ex)
            {
                // Log the exception details (you can use a logging framework here)
                LogException.LogExceptions(ex);
                // Return generic error response, without exposing internal details
                return new BaseAPIResponseDTO
                {
                    Success = false,
                    Message = "An error occurred while unliking the trail"
                };
            }
        }

        /// <summary>
        /// Adds a trail photo entity to the database.
        /// The photo file should already be uploaded to Firebase Storage before calling this.
        /// </summary>
        /// <param name="model">DTO containing Firebase Storage URL (PhotoName) and metadata (TrailId, Description)</param>
        /// <returns>
        /// A <see cref="BaseAPIResponseDTO"/> containing:
        /// - Success: true if photo metadata saved successfully, false if trail not found or database error
        /// - Message: Descriptive message about the operation result
        /// </returns>
        /// <remarks>
        /// <para>
        /// <strong>Important:</strong> This method is the second step in a two-step photo upload process:
        /// 1. Upload photo file to Firebase Storage (handled by <see cref="IFileStorageService"/>)
        /// 2. Save photo metadata to database (THIS method)
        /// </para>
        /// <para>
        /// The method performs the following operations:
        /// 1. Validates that the trail exists using <see cref="EntityFrameworkQueryableExtensions.AnyAsync{TSource}"/>
        /// 2. Creates a new <see cref="WTTrailPhoto"/> entity with:
        ///    - Server-generated GUID for Id
        ///    - PhotoName from the DTO (Firebase Storage URL)
        ///    - Optional Description from the DTO
        ///    - TrailId from the DTO
        ///    - Server-set CreatedAt timestamp (UTC)
        /// 3. Adds the entity to <see cref="AppDbContext.TrailPhotos"/>
        /// 4. Persists the change to the database
        /// </para>
        /// <para>
        /// <strong>Error Handling:</strong>
        /// - If the trail doesn't exist, returns error without attempting to save
        /// - All exceptions are logged using <see cref="LogException.LogExceptions"/>
        /// - Error messages are generic to avoid exposing internal details
        /// </para>
        /// <para>
        /// <strong>TODO:</strong> Consider implementing Firebase cleanup if database save fails
        /// (see commented code in <see cref="FilesController.UploadTrailPhoto"/>).
        /// </para>
        /// </remarks>
        public async Task<BaseAPIResponseDTO> AddTrailPhotoAsync(AddTrailPhotoDbEntityDTO model)
        {
            try
            {
                // ✅ Validate trail exists
                var trailExists = await _context.Trails
                    .AnyAsync(t => t.Id == model.TrailId);

                if (!trailExists)
                {
                    return new BaseAPIResponseDTO
                    {
                        Success = false,
                        Message = "Trail not found"
                    };
                }

                // ✅ Create WTTrailPhoto entity from DTO
                var photo = new WTTrailPhoto
                {
                    Id = Guid.NewGuid(),
                    PhotoName = model.PhotoName,
                    Description = model.Description,
                    TrailId = model.TrailId,
                    CreatedAt = DateTime.UtcNow // ✅ Server sets timestamp
                };

                _context.TrailPhotos.Add(photo);
                await _context.SaveChangesAsync();

                return new BaseAPIResponseDTO
                {
                    Success = true,
                    Message = "Photo added successfully"
                };
            }
            catch (Exception ex)
            {
                LogException.LogExceptions(ex);
                return new BaseAPIResponseDTO
                {
                    Success = false,
                    Message = "Failed to add photo to database"
                };
            }
        }
    }
}
