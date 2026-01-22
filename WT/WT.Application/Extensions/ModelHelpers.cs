
using WT.Application.DTO.Request.Account;
using WT.Application.DTO.Response;
using WT.Application.DTO.Response.Account;
using WT.Domain.Entity;

namespace WT.Application.Extensions
{
    public static class ModelHelpers
    {
        public static ApplicationUserDTO ToDto(this ApplicationUser entity)
        {
            if (entity == null) throw new ArgumentNullException(nameof(entity));

            var _user = new ApplicationUserDTO
            {
                Id = entity.Id,
                FirstName = entity.FirstName,
                Email = entity.Email,
                ProfilePicture = entity.ProfilePicture,
                ProfileUsername = entity.ProfileUsername,
                Bio = entity.Bio,
                CountryCode = entity.CountryCode,
                RegistrationDate = entity.ProfileUsernameCreatedAt,
            };

            List<RoleDTO>? _userRoles;

            if (entity.Roles is not null)
            {
                if (entity.Roles.Count >= 1)
                {
                    _userRoles = entity.Roles!.Select(_ => new RoleDTO()
                    {
                        RoleName = _.Name
                    }).ToList();
                    _user.Roles = _userRoles;
                }
            }

            return _user;
        }


        public static NavBarSettingsDTO ToDto(this APIResponseUserSettingsDTO entity)
        {
            if (entity == null) throw new ArgumentNullException(nameof(entity));

            var _navBarSettings = new NavBarSettingsDTO()
            {
                RegistrationDate = entity.MemberSince,
                FirstName = entity.FirstName,
                ProfileUsername = entity.ProfileUsername!,
                Bio = entity.Bio,
                UserPhoto = entity.ProfilePicture
            };

            return _navBarSettings;
        }

        /// <summary>
        /// Helpers to convert WTTrail entity to TrailDTO.
        /// </summary>
        /// <param name="entity"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static TrailDTO ToDto(this WTTrail entity)
        {
            if (entity == null) throw new ArgumentNullException(nameof(entity));
            var _trail = new TrailDTO
            {
                Id = entity.Id,
                Title = entity.Title,
                Description = entity.Description,
                User = entity.User!.ToDto(),
                Start = entity.Start,
                End = entity.End,
                Waypoints = entity.Waypoints,
                LengthMeters = entity.LengthMeters,
                ElevationProfile = entity.ElevationProfile,
                PointsOfInterest = entity.PointsOfInterest,
                Difficulty = entity.Difficulty,
                SurfaceTypes = entity.SurfaceTypes,
                CreatedAt = entity.CreatedAt,
                UpdatedAt = entity.UpdatedAt,
                LikeCount = entity.LikeCount,
                AverageRating = entity.AverageRating,
                RatingCount = entity.RatingCount,
                CommentCount = entity.CommentCount,
                PhotoCount = entity.PhotoCount,
                TrailLocked = entity.TrailLocked
                //  Navigaiton properties properties are loaded as a separate call
            };
            return _trail;
        }
    }
}
