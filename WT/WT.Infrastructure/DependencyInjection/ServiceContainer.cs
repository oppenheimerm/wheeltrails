using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using WT.Application.Contracts;
using WT.Domain.Entity;
using WT.Infrastructure.Data;
using WT.Infrastructure.Repositories;

namespace WT.Infrastructure.DependencyInjection
{
    /// <summary>
    /// Provides methods to register services into the dependency injection container. It muset
    /// be public static class, so it can be accessed from the composition root.
    /// </summary>
    public static class ServiceContainer
    {
        //  Our class to return a IserviceCollection for Dependency Injection
        public static IServiceCollection AddInfrastructureServices(this IServiceCollection services, IConfiguration config)
        {
            // Here we can register infrastructure services, e.g., database context, repositories, etc.

            //  Add our default connection string from secrets
            services.AddDbContext<AppDbContext>(o => o.UseSqlServer(config.GetConnectionString("WTConnectionString")));
            
            //  Register signin manager / Identity manager with custom WTRole
            services.AddIdentityCore<ApplicationUser>()
                .AddRoles<IdentityRole<Guid>>()
                .AddEntityFrameworkStores<AppDbContext>()
                .AddSignInManager()
                .AddDefaultTokenProviders();
            
            //  Since we're using JWT, we need to register authentication
            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            }).AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateIssuerSigningKey = true,
                    ValidateLifetime = true,
                    ValidIssuer = config["JwtSettings:Issuer"],
                    ValidAudience = config["JwtSettings:Audience"],
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["JWT:Key"]!))
                };
            });
            
            //  Add authentication and authorization
            services.AddAuthentication();
            services.AddAuthorization();
            
            // add CORS
            services.AddCors(options =>
            {
                options.AddPolicy("WebClient",
                    builder => builder
                    .WithOrigins("")
                    .AllowAnyMethod()
                    .AllowAnyHeader()
                    .AllowCredentials());
            });
            services.AddScoped<IWTAccount, WTAccount>();
            return services;
        }
    }
}
