# GitHub Copilot Instructions for Wheel Trails Project

## Project Overview
**Wheel Trails** is a .NET 9 web application built using Clean Architecture principles. The solution consists of multiple projects organized into distinct layers for separation of concerns.

## Technology Stack
- **.NET Version:** .NET 9
- **C# Version:** 13.0
- **Architecture:** Clean Architecture / Onion Architecture
- **Database:** SQL Server (LocalDB for development)
- **ORM:** Entity Framework Core 9.0.11
- **Authentication:** JWT Bearer Tokens with ASP.NET Core Identity
- **API Documentation:** Scalar API Reference (OpenAPI)
- **Frontend:** Blazor Server (Admin Panel) & Blazor WebAssembly (Client)

## Solution Structure

### Projects and Their Responsibilities

#### 1. **WT.Domain** (Core Layer)
- **Purpose:** Contains enterprise business rules and domain entities
- **Dependencies:** None (should remain dependency-free)
- **Contains:**
  - Domain entities (e.g., `ApplicationUser`, `RefreshToken`)
  - Value objects
  - Domain events
  - Domain exceptions

**Guidelines:**
- Keep domain entities pure with minimal framework dependencies
- Use `IdentityUser<Guid>` as base for user entities
- Avoid data annotations for validation; use domain validation instead
- Use `Guid` for all entity IDs

#### 2. **WT.Application** (Application Layer)
- **Purpose:** Application business rules and use cases
- **Dependencies:** WT.Domain only
- **Contains:**
  - DTOs (Request/Response models)
  - Interfaces/Contracts (e.g., `IWTAccount`)
  - Application services
  - Extensions and helpers
  - Constants

**Guidelines:**
- All DTOs should be in `WT.Application.DTO` namespace
- Use data annotations for API model validation
- Implement request/response DTOs separately
- Keep interfaces in `WT.Application.Contracts`
- Use constants for role names: `Constants.Role.ADMIN_DEVELOPER`, `Constants.Role.ADMIN_EDITOR`, `Constants.Role.USER`, `Constants.Role.USER_EDITOR`

#### 3. **WT.Infrastructure** (Infrastructure Layer)
- **Purpose:** External concerns implementation
- **Dependencies:** WT.Application, WT.Domain
- **Contains:**
  - Data access (`AppDbContext`)
  - Repository implementations
  - External service integrations
  - Dependency injection configuration (`ServiceContainer`)

**Guidelines:**
- All database context code goes here
- Use `IdentityDbContext<ApplicationUser, IdentityRole<Guid>, Guid>` as base
- Configure services via extension methods (e.g., `AddInfrastructureServices`)
- Store secrets in User Secrets, never in code
- Use Mapster for object mapping where needed

#### 4. **API** (Presentation Layer - API)
- **Purpose:** RESTful Web API endpoints
- **Dependencies:** WT.Infrastructure
- **Contains:**
  - Controllers
  - API-specific middleware
  - Program.cs configuration

**Guidelines:**
- Controllers should be thin; delegate to services
- Use attribute routing: `[Route("api/[controller]")]`
- Return appropriate HTTP status codes
- Use `[ApiController]` attribute for automatic model validation
- Implement proper error handling middleware

#### 5. **WT.Admin** (Presentation Layer - Admin Panel)
- **Purpose:** Blazor Server admin interface
- **Dependencies:** WT.Application (via HTTP calls to API)
- **URL:** `https://localhost:7127` (HTTPS) or `http://localhost:5041` (HTTP)

#### 6. **WT.Client** (Presentation Layer - Client App)
- **Purpose:** Blazor WebAssembly client application
- **Dependencies:** WT.Application (via HTTP calls to API)

## Authentication & Authorization

### JWT Configuration
```json
{
  "JwtSettings": {
    "Issuer": "https://localhost:5001",
    "Audience": "https://localhost:5001",
    "Secret": "Your-secret-key-at-least-32-characters-long"
  }
}
```

**Guidelines:**
- Always use User Secrets for development
- JWT tokens expire after 30 minutes
- Refresh tokens valid for 7 days
- Use role-based authorization with predefined roles
- All JWT configuration keys must use `JwtSettings:` prefix

### Security Best Practices
- Never log sensitive data (passwords, tokens)
- Use `LogException.LogToFile()` for production logging
- Use `LogException.LogToConsole()` for debugging
- Always hash passwords using Identity's password hasher
- Implement refresh token rotation
- Revoke compromised refresh tokens and their descendants

## Database & Entity Framework

### Configuration
```json
{
  "ConnectionStrings": {
    "WTConnectionString": "Server=(localdb)\\mssqllocaldb;Database=WTAPIDB;Trusted_Connection=True;MultipleActiveResultSets=true;TrustServerCertificate=true;"
  }
}
```

**Guidelines:**
- Use async methods for all database operations
- Implement `Include()` for eager loading related entities
- Use `AsNoTracking()` for read-only queries
- Create indexes for frequently queried fields
- Use migrations for schema changes: `Add-Migration`, `Update-Database`
- Seed initial roles in `CreateAdminRoles()` method

### Entity Conventions
- Primary keys: Use `Guid` for user-related entities, `int` for system entities
- Foreign keys: Use nullable `Guid?` with `[Required]` and `[ForeignKey]` attributes
- Navigation properties: Make nullable with `?`
- Use `[MaxLength]` for string properties
- DateTime properties: Use `DateTime?` and store in UTC

## API Response Patterns

### Standard Response DTOs
- `BaseAPIResponseDTO`: Basic success/message response
- `APIResponseAuthentication`: Authentication responses with tokens
- `ApplicationUserDTO`: User data transfer object

**Guidelines:**
- Always return consistent response structures
- Include success flag and descriptive messages
- Return proper HTTP status codes (200, 400, 401, 404, 500)
- Log all errors before returning error responses

## Code Style & Conventions

### General
- Use nullable reference types (`#nullable enable`)
- Use implicit usings
- Use primary constructors for dependency injection (C# 12+)
- Use file-scoped namespaces
- Use expression-bodied members where appropriate

### Naming Conventions
- Interfaces: Prefix with `I` (e.g., `IWTAccount`)
- Private fields: Use camelCase (e.g., `roleManager`)
- Constants: Use UPPER_SNAKE_CASE (e.g., `ADMIN_DEVELOPER`)
- Methods: Use PascalCase with `Async` suffix for async methods
- DTOs: Suffix with `DTO` (e.g., `LoginDTO`, `RegisterDTO`)

### Comments & Documentation
- Use XML documentation comments (`///`) for public APIs
- Include `<summary>`, `<param>`, and `<returns>` tags
- Document complex business logic
- Keep comments up-to-date with code changes

## Error Handling & Logging

### Logging Utility
Use `LogException` class from `WT.Application.APIServiceLogs`:
```csharp
// For file logging (production)
LogException.LogToFile($"User logged in: {user.Email} at {DateTime.UtcNow}");

// For console logging (debugging)
LogException.LogToConsole($"Failed to create admin user at {DateTime.UtcNow}");

// For exception logging
LogException.LogExceptions(exception);
```

**Guidelines:**
- Wrap external calls in try-catch blocks
- Log exceptions before returning error responses
- Include timestamps in all log messages
- Don't expose internal errors to API consumers
- Use structured logging with Serilog where available

## Dependency Injection

### Registration Pattern
All service registrations happen in `ServiceContainer.AddInfrastructureServices()`:
```csharp
// DbContext
services.AddDbContext<AppDbContext>(o => o.UseSqlServer(connectionString));

// Identity
services.AddIdentityCore<ApplicationUser>()
    .AddRoles<IdentityRole<Guid>>()
.AddEntityFrameworkStores<AppDbContext>()
    .AddSignInManager()
    .AddDefaultTokenProviders();

// Authentication
services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options => { /* JWT config */ });

// Custom services
services.AddScoped<IWTAccount, WTAccount>();
```

**Guidelines:**
- Use appropriate lifetimes: `AddScoped` for per-request, `AddSingleton` for app lifetime
- Register interfaces, not concrete types
- Use primary constructors for DI in classes
- Validate required configuration on startup

## Testing Considerations

### Unit Testing
- Mock dependencies using interfaces
- Test business logic in isolation
- Use `InMemoryDatabase` for repository tests
- Mock `IConfiguration` for testing configuration-dependent code

### Integration Testing
- Test full request/response cycles
- Use `WebApplicationFactory` for API tests
- Test authentication and authorization flows
- Verify database state changes

## Application Configuration

### Required Configuration Sections
```json
{
  "ConnectionStrings": {
    "WTConnectionString": "..."
  },
  "JwtSettings": {
    "Issuer": "...",
    "Audience": "...",
    "Secret": "..."
  },
  "AdminUser": {
    "FirstName": "...",
    "Email": "...",
    "Password": "..."
  },
  "ApplicationSettings": {
    "RefreshTokenTTL": "90"
  }
}
```

### User Secrets
- Use User Secrets for local development (both API and Infrastructure projects have UserSecretsId)
- Store: connection strings, JWT secrets, admin credentials
- Never commit secrets to source control

## Common Patterns & Practices

### Async/Await
- Always use `async`/`await` for I/O operations
- Don't block on async code with `.Result` or `.Wait()`
- Use `ConfigureAwait(false)` in library code

### Validation
- Use Data Annotations in DTOs for API validation
- Implement domain validation in entities
- Return validation errors in response DTOs
- Use `[Required]`, `[EmailAddress]`, `[StringLength]`, etc.

### Token Management
- Generate cryptographically secure tokens using `RandomNumberGenerator`
- Ensure token uniqueness before saving
- Implement token rotation for refresh tokens
- Clean up expired tokens based on TTL

### User Management
- Verify email before allowing login
- Store names in Title Case
- Use claims for user identity and roles
- Include user roles in JWT claims

## API Endpoints Pattern

### Controller Structure
```csharp
[ApiController]
[Route("api/[controller]")]
public class AccountController : ControllerBase
{
    private readonly IWTAccount _accountService;
 
    public AccountController(IWTAccount accountService)
    {
      _accountService = accountService;
    }
    
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterDTO model)
    {
  var result = await _accountService.RegisterAsync(model);
        return result.Success ? Ok(result) : BadRequest(result);
    }
}
```

### Best Practices
- Use `[FromBody]` for complex types
- Use `[FromRoute]` for route parameters
- Use `[FromQuery]` for query parameters
- Return `IActionResult` or `ActionResult<T>`
- Use async actions with proper cancellation tokens

## Middleware Pipeline Order

Correct order in `Program.cs`:
```csharp
app.UseHttpsRedirection();// 1. HTTPS redirection
app.UseAuthentication();        // 2. Authentication
app.UseAuthorization();         // 3. Authorization
app.MapControllers();      // 4. Routing
```

## Common Pitfalls to Avoid

1. **Don't** use `.Result` or `.Wait()` on async methods
2. **Don't** expose stack traces to API consumers
3. **Don't** use magic strings; use constants
4. **Don't** access configuration directly in domain/application layers
5. **Don't** forget to validate null parameters
6. **Don't** catch exceptions without logging
7. **Don't** use `AddAuthentication()` twice (it's called in JWT setup)
8. **Don't** return sensitive information in error messages
9. **Don't** forget to include `app.UseAuthentication()` in middleware pipeline
10. **Don't** mix up JWT configuration key names (use consistent `JwtSettings:` prefix)

## Performance Considerations

- Use `AsNoTracking()` for read-only queries
- Implement pagination for large result sets
- Use projection (Select) to return only needed data
- Cache frequently accessed data
- Use compiled queries for hot paths
- Implement proper indexes on database tables

## Startup & Development URLs

| Project | HTTPS URL | HTTP URL |
|---------|-----------|----------|
| API | https://localhost:5001 | http://localhost:5000 |
| WT.Admin | https://localhost:7127 | http://localhost:5041 |

**Default API Documentation:** `https://localhost:5001/scalar/v1`

## Git & Version Control

- Current branch: `webapi-controllers`
- Repository: `https://github.com/oppenheimerm/wheeltrails`
- Don't commit: `secrets.json`, `appsettings.Development.json` with secrets

---

## Quick Reference Commands

### Entity Framework Migrations
```bash
# Add migration
Add-Migration MigrationName

# Update database
Update-Database

# Remove last migration
Remove-Migration
```

### User Secrets
```bash
# Set secret
dotnet user-secrets set "JwtSettings:Secret" "your-secret"

# List secrets
dotnet user-secrets list

# Clear all secrets
dotnet user-secrets clear
```

### Run Projects
```bash
# Run API
dotnet run --project API

# Run multiple projects
# Set in Visual Studio: Solution Properties > Multiple Startup Projects
```

---

**Last Updated:** 2024
**Project Phase:** Web API Development (Controllers)
