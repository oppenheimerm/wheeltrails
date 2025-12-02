
using WT.Application.DTO.Request.Account;
using WT.Application.DTO.Response;
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
                Bio = entity.Bio,
                CountryCode = entity.CountryCode,
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
    }
}
