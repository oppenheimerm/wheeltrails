// We need a method to get user by profile username (public), that is lightweight and returns DTO
// return profile metadata + counts(trails, comments, likes). This must take a cancellation token
// to handle OperationCanceledException(499) from client disconnects.
public async Task<APIResponsePublicViewProfile?> GetUserProfileByUsernameAsync(string profileUsername, CancellationToken cancellationToken)
{
 try
 {
 if (string.IsNullOrWhiteSpace(profileUsername))
 {
 return new APIResponsePublicViewProfile(false, "Profile username is required", null, null);
 }

 var normalized = profileUsername.ToLower().Trim();

 // Read-only query for user
 var user = await dbContext.Users
 .AsNoTracking()
 .FirstOrDefaultAsync(u => u.ProfileUsername == normalized, cancellationToken);

 if (user == null || user.IsDeleted)
 {
 return new APIResponsePublicViewProfile(false, "User not found", null, null);
 }

 // Start count tasks in parallel - pass cancellationToken so client disconnects are honored
 var trailsCountTask = dbContext.Trails
 .AsNoTracking()
 .CountAsync(t => t.UserId == user.Id, cancellationToken);

 var commentsCountTask = dbContext.Comments
 .AsNoTracking()
 .CountAsync(c => c.UserId == user.Id, cancellationToken);

 var likesCountTask = dbContext.TrailLikes
 .AsNoTracking()
 .CountAsync(l => l.UserId == user.Id, cancellationToken);

 await Task.WhenAll(trailsCountTask, commentsCountTask, likesCountTask);

 var publicProfileDto = new PublicViewProfileDTO
 {
 ProfileUsername = user.ProfileUsername,
 FirstName = user.FirstName,
 ProfilePicture = user.ProfilePicture,
 Bio = user.Bio,
 CountryCode = user.CountryCode,
 MemberSince = user.ProfileUsernameCreatedAt,
 TrailsCount = trailsCountTask.Result,
 CommentsCount = commentsCountTask.Result,
 LikesCount = likesCountTask.Result
 };

 var response = new APIResponsePublicViewProfile(true, string.Empty, publicProfileDto, null);
 return response;
 }
 catch (OperationCanceledException)
 {
 // Client disconnected or request was cancelled
 return new APIResponsePublicViewProfile(false, "Request canceled", null,499);
 }
 catch (Exception ex)
 {
 LogException.LogExceptions(ex);
 return new APIResponsePublicViewProfile(false, "Unable to retrieve profile", null,500);
 }
}
