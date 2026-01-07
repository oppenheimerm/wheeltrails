using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using WT.Application.Contracts;
using WT.Application.Services;
using WT.Domain.Entity;
using WT.Infrastructure.Data;
using WT.Infrastructure.Repositories;
using WT.Infrastructure.Services;


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

            //You should register your custom ILookupNormalizer before or alongside your AddIdentity call.
            services.AddSingleton<ILookupNormalizer, UnicodeLookupNormalizer>();

            //  Register signin manager / Identity manager with custom WTRole
            services.AddIdentityCore<ApplicationUser>(options => {
                // By default, Identity restricts usernames to ASCII. You can override this behavior by setting
                // AllowedUserNameCharacters to null or to a custom string of allowed characters.
                options.User.AllowedUserNameCharacters = string.Empty;
                // Lockout settings
                //  How long the user stays locked out
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
                //  Maximum failed access attempts before lockout
                options.Lockout.MaxFailedAccessAttempts = 5;
                //  Whether new users are subject to lockout
                options.Lockout.AllowedForNewUsers = true;

            }).AddRoles<IdentityRole<Guid>>()
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
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["JwtSettings:Secret"]!))
                };
            });
            
            //  Add authentication and authorization
            services.AddAuthentication();
            services.AddAuthorization();

            // ✅ Server-side only - used by API controllers
            services.AddScoped<IAccountRepository, WTAccount>();
            
            // ❌ REMOVE THIS LINE (client-side service, doesn't belong here):
            // services.AddScoped<IAccountService, WTAccount>();
            
            // Replace generic EmailService with SendGrid implementation for production readiness.
            services.AddScoped<IEmailService, SendGridEmailService>();
            services.AddScoped<IFileStorageService, FirebaseStorageService>();
            services.AddSingleton<IUsernameValidator, UsernameValidator>();
            services.AddScoped<IWTTrailRepository, WTTrailRepository>();

            // In-memory cache for per-user navbar data and other short-lived caching
            services.AddMemoryCache();

            var allowedOrigins = new[] { "https://www.wheelytrails.com" }; // add others as needed
            services.AddCors(options =>
            {
                options.AddPolicy("DefaultCorsPolicy", policy =>
                {
                    policy.WithOrigins(allowedOrigins)
                          .AllowAnyHeader()
                          .AllowAnyMethod()
                          .AllowCredentials(); // only if you need cookies
                });
            });

            return services;
        }
    }
}
