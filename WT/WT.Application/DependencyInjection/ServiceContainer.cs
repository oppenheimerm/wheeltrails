using Blazored.LocalStorage;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.DependencyInjection;

namespace WT.Application.DependencyInjection
{
    /// <summary>
    /// Provides extension methods for registering application-level services in the dependency injection container.
    /// </summary>
    public static class ServiceContainer
    {
        /// <summary>
        /// Registers application services including authentication, authorization, and local storage.
        /// </summary>
        /// <param name="services">The service collection to add services to.</param>
        /// <returns>The service collection for method chaining.</returns>
        /// <remarks>
        /// <para>
        /// This method registers:
        /// <list type="bullet">
        /// <item><description>Account service for authentication operations</description></item>
        /// <item><description>Authorization core services</description></item>
        /// <item><description>Blazored LocalStorage for browser storage access</description></item>
        /// <item><description>Custom authentication state provider for JWT-based auth</description></item>
        /// <item><description>Cascading authentication state for Blazor components</description></item>
        /// </list>
        /// </para>
        /// <para>
        /// <strong>Note:</strong> HttpClient must be registered separately in each consuming project
        /// with project-specific BaseAddress configuration.
        /// </para>
        /// </remarks>
        public static IServiceCollection AddApplicationServices(this IServiceCollection services)
        {
            // Application Services
            services.AddScoped<Services.IAccountService, Services.AccountService>();
            
            // Authorization
            services.AddAuthorizationCore();
            
            // Local Storage
            services.AddBlazoredLocalStorage();
            
            // Authentication
            services.AddScoped<AuthenticationStateProvider, Extensions.CustomAuthenticationStateProvider>();
            services.AddCascadingAuthenticationState();

            return services;
        }
    }
}
