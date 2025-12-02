using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using WT.Application.APIServiceLogs;
using WT.Application.Contracts;
using WT.Application.DTO.Request.Account;
using WT.Application.DTO.Response;
using WT.Application.Extensions;
using WT.Domain.Entity;
using WT.Infrastructure.Data;
using static WT.Application.Extensions.Constants;

namespace WT.Infrastructure.Repositories
{
    public class WTAccount(RoleManager<IdentityRole<Guid>> roleManager,
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signinManager,
        AppDbContext dbContext,
        IConfiguration config) : IWTAccount
    {

        /// <summary>
        /// Adds a <see cref="ApplicationUser"/> to a role
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="model"></param>
        /// <returns></returns>
        public async Task<BaseAPIResponseDTO> AddUserToRoleAsync(Guid userId, CreateRoleDTO model)
        {
            var user = await FindUserByIdAsync(userId);
            if (user == null)
            {
                return new BaseAPIResponseDTO
                {
                    Success = false,
                    Message = "User not found."
                };
            }
             
            return await AddUserToRoleAsync(user, model.RoleName!);
        }

        public async Task CreateAdmin()
        {
            try {
                if ((await FindRoleByNameAsync(Constants.Role.ADMIN_DEVELOPER)) != null) return;
                var admin = new RegisterDTO()
                { 
                    FirstName = config["AdminUser:FirstName"]!,
                    LasttName = config["AdminUser:LastName"]!,
                    Email = config["AdminUser:Email"]!,
                    Password = config["AdminUser:Password"]!,
                    AcceptTerms = true,
                    Bio = "Administrator Account"
                };

                var adminRole = new List<RoleDTO>
                {
                    new RoleDTO { RoleName = Constants.Role.ADMIN_DEVELOPER },
                    new RoleDTO { RoleName = Constants.Role.ADMIN_EDITOR }
                };

                admin.Roles = adminRole;

                var status = await RegisterAsync(admin);
                if (status.Success)
                {
                    var user = await FindUserByEmailAsync(admin.Email!);
                    if (user != null)
                    {
                        foreach (var role in admin.Roles!)
                        {
                            await AddUserToRoleAsync(user, role.RoleName!);
                        }
                    }

                    LogException.LogToFile($"Admin user created: {admin.Email} at {DateTime.UtcNow}");
                }
                else
                {
                    LogException.LogToConsole($"Failed to create admin user: {admin.Email} at {DateTime.UtcNow}. Reason: {status.Message}");
                }
            }
            catch(Exception err)
            {
                LogException.LogExceptions(err);
            }
        }

        public Task<BaseAPIResponseDTO> CreateRoleASync(CreateRoleDTO model)
        {
            throw new NotImplementedException();
        }

        public Task<IEnumerable<RoleDTO>> GetRolesAsync()
        {
            throw new NotImplementedException();
        }

        public async Task<APIResponseAuthentication> LoginAsync(LoginDTO model, string ipAddress)
        {
            try {
                var user = userManager.FindByEmailAsync(model.Email!).Result;
                if (user == null)
                {
                    return new APIResponseAuthentication
                    {
                        Success = false,
                        Message = "Invalid email or password."
                    };
                }

                if (!user.IsVerified)
                    return new APIResponseAuthentication(false, "Please verify your account");

                /*
                if (account.AccountLockedOut == true)
                    return new APIResponseAuthentication(false, "Your account is locked.  Please contact our help desk for assistance.");
                 */

                SignInResult result;
                result = await signinManager.CheckPasswordSignInAsync(user, model.Password!, false);
                if (result.Succeeded)
                {
                    //  Get user roles
                    user.Roles = await GetRolesForUserAsync(user.Id);

                    // Generate JWT token
                    var jwtToken = await GenerateToken(user);
                    // Generate refresh token
                    var refreshToken = await GenerateRefreshToken(ipAddress, user.Id);

                    if (user.RefreshTokens is not null  && refreshToken is not null)
                    {
                        user.RefreshTokens.Add(refreshToken);
                    }

                    // remove old refresh tokens from user instance
                    RemoveOldRefreshTokens(user);

                    // save changes to database
                    // FYI UserManager.UpdateAsync(),Automatically calls SaveChangesAsync on the underlying DbContext
                    //  and returns an IdentityResult, indicating whether the operation was successful or not.
                    //  In the case where we call the dbContext.Update(user) above, we would need to call
                    //  dbContext.SaveChangesAsync() ourselves.
                    var userUpdate = await userManager.UpdateAsync(user);

                    if (userUpdate.Succeeded) {
                        LogException.LogToFile($"User logged in: {user.Email} at {DateTime.UtcNow}");
                        return new APIResponseAuthentication
                        {
                            Success = true,
                            Message = "Login successful.",
                            User = user.ToDto(),
                            JwtToken = jwtToken,
                            RefreshToken = refreshToken!.Token
                        };
                    }
                    else { 
                        LogException.LogToConsole($"Login failed for {user.Email} at {DateTime.UtcNow}. Unable to update user with refresh token.");
                        return new APIResponseAuthentication
                        {
                            Success = false,
                            Message = "Login failed. Unable to update user with refresh token."
                        };
                    }

                }
                else
                {
                    LogException.LogToFile($"Login failed for {model.Email} at {DateTime.UtcNow}. Invalid credentials.");
                    return new APIResponseAuthentication
                    {
                        Success = false,
                        Message = "Invalid email or password."
                    };
                }
            }
            catch (Exception Err)
            {
                // Login failed due to exception, log exception
                LogException.LogExceptions(Err);
                return new APIResponseAuthentication
                {
                    Success = false,
                    Message = "An error occurred during login. Please try again later."
                };
            }
        }

        /// <summary>
        /// Method to register a new <see cref="ApplicationUser"/> 
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        public async Task<BaseAPIResponseDTO> RegisterAsync(RegisterDTO model)
        {
            try {

                if(await FindUserByEmailAsync(model.Email) != null)
                {
                    return new BaseAPIResponseDTO
                    {
                        Success = false,
                        Message = "User with this email already exists."
                    };
                }

                if (string.IsNullOrWhiteSpace(model.Password))
                {
                    return new BaseAPIResponseDTO
                    {
                        Success = false,
                        Message = "Password is required."
                    };
                }

                if (string.IsNullOrWhiteSpace(model.FirstName))
                {
                    return new BaseAPIResponseDTO
                    {
                        Success = false,
                        Message = "First name is required."
                    };
                }

                // User must accept terms and conditions
                if (!model.AcceptTerms)
                {
                    return new BaseAPIResponseDTO
                    {
                        Success = false,
                        Message = "You must accept the terms and conditions to register."
                    };
                }

                var user = new ApplicationUser
                {
                    UserName = model.Email,
                    Email = model.Email,
                    FirstName = model.FirstName,
                    Bio = model.Bio,
                    VerificationToken = GenerateVerificationToken(),
                    AcceptTerms = model.AcceptTerms,
                    CountryCode = model.CountryCode,
                    PasswordHash = model.Password!
                };
                var result = await userManager.CreateAsync(user, model.Password);

                // Handle the IDentityResult from above
                if (result.Succeeded)
                {

                    //  Add user to user role
                    var roleStatus = await userManager.AddToRoleAsync(user, Constants.Role.USER);
                    if (!roleStatus.Succeeded)
                    {
                        var roleErrors = string.Join("; ", roleStatus.Errors.Select(e => e.Description));
                        return new BaseAPIResponseDTO
                        {
                            Success = false,
                            Message = $"Failed to add user to role: {roleErrors}"
                        };
                    }

                    // Registration successful, log information
                    LogException.LogToFile($"New user registered: {user.Email} at {DateTime.UtcNow}");

                    // Return success response with message containing verification token.
                    return new BaseAPIResponseDTO
                    {
                        Success = true,
                        Message = user.VerificationToken
                    };
                }
                else
                {
                    var errors = string.Join("; ", result.Errors.Select(e => e.Description));

                    // Registration failed, log errors
                    LogException.LogToFile($"User registration failed for {model.Email} at {DateTime.UtcNow}. Errors: {errors}");

                    return new BaseAPIResponseDTO
                    {
                        Success = false,
                        Message = $"User registration failed: {errors}"
                    };
                }
            }
            catch (Exception Err)
            {
                // Registration failed due to exception, log exception
                LogException.LogExceptions(Err);

                return new BaseAPIResponseDTO
                {
                    Success = false,
                    Message = "An error occurred during registration. Please try again later."
                };
            }
        }


        #region Helpers

        /// <summary>
        /// A method to get roles for a user, given the userId.
        /// </summary>
        /// <param name="userId"></param>
        /// <returns></returns>
        private async Task<List<IdentityRole<Guid>>?> GetRolesForUserAsync(Guid userId)
        {
            var user = await FindUserByIdAsync(userId);
            if (user == null)
            {
                return null;
            }

            var roleNames = await userManager.GetRolesAsync(user);
            var roles = new List<IdentityRole<Guid>>();

            foreach (var roleName in roleNames)
            {
                var role = await FindRoleByNameAsync(roleName);
                if (role != null)
                {
                    roles.Add(role);
                }
            }

            return roles;
        }

        /// <summary>
        /// Adds an instance of a <see cref="ApplicationUser"/> to a role
        /// </summary>
        /// <param name="user"></param>
        /// <param name="roleName"></param>
        /// <returns></returns>
        private async Task<BaseAPIResponseDTO> AddUserToRoleAsync(ApplicationUser user, string roleName)
        {

            // null checks
            if (user == null || string.IsNullOrEmpty((roleName)))
            {
                return new BaseAPIResponseDTO
                {
                    Success = false,
                    Message = "Uaser and role name are required!"
                };
            }
            var role = await FindRoleByNameAsync(roleName);
            if (role == null)
            {
                return new BaseAPIResponseDTO
                {
                    Success = false,
                    Message = "Role does not exist."
                };
            }
            var result = await userManager.AddToRoleAsync(user, role.Name!);
            if (result.Succeeded)
            {
                return new BaseAPIResponseDTO
                {
                    Success = true,
                    Message = "User added to role successfully."
                };
            }
            else
            {
                return new BaseAPIResponseDTO
                {
                    Success = false,
                    Message = "Failed to add user to role."
                };
            }
        }

        /// <summary>
        /// Remover and instance of a <see cref="ApplicationUser"/> from a role"/>
        /// </summary>
        /// <param name="user"></param>
        /// <param name="roleName"></param>
        /// <returns></returns>
        private async Task<BaseAPIResponseDTO> RemoveUserFromRoleAsync(ApplicationUser user, string roleName)
        {
            // null checks
            if (user == null || string.IsNullOrEmpty((roleName)))
            {
                return new BaseAPIResponseDTO
                {
                    Success = false,
                    Message = "User and role name are required!"
                };
            }
            var role = await FindRoleByNameAsync(roleName);
            if (role == null)
            {
                return new BaseAPIResponseDTO
                {
                    Success = false,
                    Message = "Role does not exist."
                };
            }
            var result = await userManager.RemoveFromRoleAsync(user, role.Name!);
            if (result.Succeeded)
            {
                return new BaseAPIResponseDTO
                {
                    Success = true,
                    Message = "User removed from role successfully."
                };
            }
            else
            {
                return new BaseAPIResponseDTO
                {
                    Success = false,
                    Message = "Failed to remove user from role."
                };
            }
        }

        public async Task<string?> GenerateToken(ApplicationUser user)
        {
            // Implementation for generating JWT token
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["JwtSettings:Secret"]!));
            // Use HmacSha256 instead of deprecated HmacSha256Signature
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var userClaims = new List<Claim> {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.FirstName!),
                new Claim(ClaimTypes.Email, user.Email!),
            };

            // Get user roles as a List<IdentityRole>
            user.Roles = await GetRolesForUserAsync(user.Id);


            if (user.Roles is not null && user.Roles.Any())
            {
                foreach (var role in user.Roles)
                {
                    userClaims.Add(
                        new Claim(ClaimTypes.Role, role.Name!));
                }
            }

            var token = new JwtSecurityToken(
                issuer: config["JwtSettings:Issuer"],
                audience: config["JwtSettings:Audience"],
                claims: userClaims,
                expires: DateTime.UtcNow.AddMinutes(30),
                signingCredentials: credentials
            );
            
            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private async Task<RefreshToken?> GenerateRefreshToken(string ipAddress, Guid userId)
        {
            // User exist?
            var user = await FindUserByIdAsync(userId);
            if (user == null)
            {
                return null;
            }

            var refreshToken = new RefreshToken
            {
                // Token is a cryptographically strong random sequence of values
                Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
                // Valid for 7 days
                Expires = DateTime.UtcNow.AddDays(7),
                Created = DateTime.UtcNow,
                CreatedByIp = ipAddress,
                AccountId = userId
            };

            // ensure token is unique by checking against db
            var tokenIsUnique = !userManager.Users.Any(x => x.RefreshTokens!.Any(t => t.Token == refreshToken.Token));

            // If not unique, recursively generate a new token
            if (!tokenIsUnique)
                return await GenerateRefreshToken(ipAddress, userId);

            try
            {
                // Save refresh token to database
                await dbContext.RefreshTokens.AddAsync(refreshToken);
                await dbContext.SaveChangesAsync();
                LogException.LogToFile($"Generated new refresh token for user {user.Email} at {DateTime.UtcNow}");
                return refreshToken;
            }
            catch (Exception ex)
            {
                // Log exception
                LogException.LogExceptions(ex);
                return null;
            }
        }

        private async Task<ApplicationUser?> FindUserByEmailAsync(string email)
        {
            var user = await userManager.FindByEmailAsync(email);
            return user;
        }

        private async Task<ApplicationUser?> FindUserByIdAsync(Guid id)
        {
            var user = await userManager.FindByIdAsync(id.ToString());
            return user;
        }

        private async Task<IdentityRole<Guid>?> FindRoleByNameAsync(string roleName)
        {
            var role = await roleManager.FindByNameAsync(roleName);
            return role;
        }

        /// <summary>
        /// Generates a unique verification token for <see cref="ApplicationUser"/>
        /// </summary>
        /// <returns></returns>
        private string GenerateVerificationToken()
        {
            // token is a cryptographically strong random sequence of values
            var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(64));

            // ensure token is unique by checking against db
            var tokenIsUnique = !userManager.Users.Any(x => x.VerificationToken == token);
            if (!tokenIsUnique)
                return GenerateVerificationToken();

            return token;
        }

        /// <summary>
        /// Helpers method to remove old <see cref="RefreshToken"/>(s) from <see cref="ApplicationUser"/> instance
        /// </summary>
        /// <param name="user"></param>
        private void RemoveOldRefreshTokens(ApplicationUser user)
        {
            if (user.RefreshTokens is not null)
            {
                if (user.RefreshTokens.Count >= 1)
                {
                    // remove old inactive refresh tokens from user based on TTL in app settings
                    user.RefreshTokens.RemoveAll(x =>
                        !x.IsActive && x.Created!.Value.AddDays(int.Parse(config["ApplicationSettings:RefreshTokenTTL"]!)) <= DateTime.UtcNow);
                }
            }
        }

        #endregion
    }
}
