![WheelyTrails Logo](../logo.png)
# WheelyTrails.Com 🦽🌲

[![.NET Version](https://img.shields.io/badge/.NET-9.0-512BD4?logo=dotnet)](https://dotnet.microsoft.com/)
[![Blazor](https://img.shields.io/badge/Blazor-WebAssembly-512BD4?logo=blazor)](https://blazor.net/)
[![PWA](https://img.shields.io/badge/PWA-Enabled-5A0FC8?logo=pwa)](https://web.dev/explore/progressive-web-apps)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

> Empowering wheelchair users to explore the world, one accessible trail at a time.

## 📖 About

**WheelyTrails** is a community-driven Progressive Web Application (PWA) built with ASP.NET Core Blazor WebAssembly and ASP.NET Core Web API. The platform enables users to discover, share, and rate wheelchair-accessible trails worldwide, fostering an inclusive outdoor experience for everyone.

This MVP/proof-of-concept demonstrates modern web technologies and Clean Architecture principles to create an accessible, offline-capable, and mobile-friendly application that serves the mobility-impaired community.

## ✨ Key Features

### 🗺️ Trail Database
- Comprehensive database of wheelchair-accessible trails worldwide
- Detailed trail information including:
  - 📍 Location with GPS coordinates
  - 🎯 Difficulty level (Easy, Moderate, Challenging)
  - 📏 Trail length and estimated duration
  - 🛤️ Surface type (paved, gravel, boardwalk, etc.)
  - ♿ Accessibility features (grade, width, rest areas)
  - 🚻 Nearby amenities (parking, restrooms, facilities)

### ⭐ User Reviews and Ratings
- Community-driven reviews and ratings system
- Share personal experiences and accessibility insights
- Help others make informed trail decisions
- Rate trails based on accessibility, scenery, and overall experience

### 🔍 Search and Filter
- Advanced search functionality with multiple criteria
- Filter by:
  - Geographic location and distance
  - Difficulty level and trail length
  - Surface type and accessibility features
  - Amenities and facilities
- Save favorite searches for quick access

### 🗺️ Trail Maps and Directions
- Interactive maps powered by mapping APIs
- Turn-by-turn directions to trailheads
- Visual trail route overlays
- Parking location markers

### 📸 Photo Upload
- Community photo sharing for visual trail previews
- Upload and view trail photos
- Help others visualize accessibility features
- Gallery view of community contributions

### 🔐 Authentication & Security
- JWT Bearer token authentication with ASP.NET Core Identity
- Role-based authorization (Admin Developer, Admin Editor, User Editor, User)
- Secure user registration and login
- Refresh token rotation for enhanced security (7-day expiry)
- Custom authentication state provider for Blazor applications
- Local storage integration for client-side token management

## 🏗️ Architecture

WheelyTrails follows **Clean Architecture** (Onion Architecture) principles, ensuring maintainability, testability, and separation of concerns.

### Solution Structure

```
WT/
├── WT.Domain/           # Core domain entities and business rules
│   ├── Entity/             # Domain entities (ApplicationUser, RefreshToken)
│   └── [No external dependencies]
│
├── WT.Application/       # Application business logic
│   ├── Contracts/          # Service interfaces (IWTAccount)
│   ├── DTO/              # Data Transfer Objects
│   ├── Extensions/    # Helper classes and constants
│   └── APIServiceLogs/     # Logging utilities
│
├── WT.Infrastructure/      # External concerns implementation
│   ├── Data/# DbContext and migrations
│   ├── Repositories/  # Repository implementations (WTAccount)
│   └── DependencyInjection/ # Service registration
│
├── API/   # Web API presentation layer
│ ├── Controllers/        # API endpoints
│ └── Program.cs          # Application entry point
│
├── WT.Admin/  # Blazor Server admin panel
│   └── Components/         # Admin UI components
│
└── WT.Client/    # Blazor WebAssembly client (PWA)
    └── Pages/     # Client pages and components
```

### Dependency Flow
```
WT.Client/WT.Admin → API → WT.Infrastructure → WT.Application → WT.Domain
```

## 🛠️ Technology Stack

### Backend
- **Framework**: [ASP.NET Core Web API (.NET 9)](https://dotnet.microsoft.com/en-us/apps/aspnet/apis)
- **Database**: SQL Server with Entity Framework Core 9.0.11
- **Authentication**: JWT Bearer Tokens with ASP.NET Core Identity
- **Object Mapping**: [Mapster](https://github.com/MapsterMapper/Mapster)
- **Logging**: [Serilog](https://serilog.net/)
- **API Documentation**: [Scalar](https://guides.scalar.com/scalar/scalar-api-references/integrations/net-aspnet-core/integration)

### Frontend
- **Client App**: [Blazor WebAssembly (.NET 9)](https://dotnet.microsoft.com/en-us/apps/aspnet/web-apps/blazor)
- **Admin Panel**: [Blazor Server (.NET 9)](https://dotnet.microsoft.com/en-us/apps/aspnet/web-apps/blazor)
- **UI Framework**: [Tailwind CSS](https://tailwindcss.com/)
- **Architecture**: [Progressive Web Application (PWA)](https://web.dev/explore/progressive-web-apps)
- **LocalStorage**: For client-side storage [Blazored LocalStorage](https://github.com/Blazored/LocalStorage)

### Development Tools
- **IDE**: Visual Studio 2022 / Visual Studio Code
- **Version Control**: Git
- **Package Manager**: NuGet

## 🚀 Getting Started

### Prerequisites

- [.NET 9 SDK](https://dotnet.microsoft.com/download/dotnet/9.0)
- [Visual Studio 2022](https://visualstudio.microsoft.com/) (17.8 or later) or [Visual Studio Code](https://code.visualstudio.com/)
- [SQL Server LocalDB](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/sql-server-express-localdb) (included with Visual Studio)
- Modern web browser (Chrome, Edge, Firefox, Safari)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/oppenheimerm/wheeltrails.git
   cd wheeltrails/src/WT
   ```

2. **Configure User Secrets** (for API project)
   ```bash
   cd API
   dotnet user-secrets set "ConnectionStrings:WTConnectionString" "Server=(localdb)\\mssqllocaldb;Database=WTAPIDB;Trusted_Connection=True;MultipleActiveResultSets=true;TrustServerCertificate=true;"
   dotnet user-secrets set "JwtSettings:Issuer" "https://localhost:5001"
   dotnet user-secrets set "JwtSettings:Audience" "https://localhost:5001"
   dotnet user-secrets set "JwtSettings:Secret" "YourSuperSecretKeyThatIsAtLeast32CharactersLongForHS256Algorithm!"
   dotnet user-secrets set "AdminUser:FirstName" "Admin"
   dotnet user-secrets set "AdminUser:Email" "admin@wheeltrails.com"
   dotnet user-secrets set "AdminUser:Password" "Admin@123456"
dotnet user-secrets set "ApplicationSettings:RefreshTokenTTL" "90"
   ```

3. **Apply Database Migrations**
   ```bash
   # From the API project directory
   dotnet ef database update
   
   # Or using Package Manager Console in Visual Studio
   Update-Database
   ```

4. **Run the Application**
   
   **Option A: Run API only**
   ```bash
   cd API
   dotnet run
   ```
   Access API documentation at: `https://localhost:5001/scalar/v1`

   **Option B: Run multiple projects** (in Visual Studio)
   - Right-click on the Solution → Properties
   - Select "Multiple startup projects"
   - Set `API`, `WT.Admin`, and `WT.Client` to "Start"
   - Press F5

### Development URLs

| Project | Purpose | HTTPS URL | HTTP URL |
|---------|---------|-----------|----------|
| API | Web API Backend | https://localhost:5001 | http://localhost:5000 |
| WT.Admin | Admin Panel | https://localhost:7127 | http://localhost:5041 |
| WT.Client | Client PWA | *To be configured* | *To be configured* |

## 📚 API Documentation

The Web API uses Scalar for interactive API documentation. Once the API is running, visit:

**https://localhost:5001/scalar/v1**

This provides:
- Interactive API testing
- Request/response examples
- Authentication testing
- Endpoint documentation

## 🔒 Security & Configuration

### User Secrets
The project uses .NET User Secrets for sensitive configuration during development. **Never commit secrets to source control.**

Required secrets for API and Infrastructure projects:
- `JwtSettings:Issuer`, `JwtSettings:Audience`, `JwtSettings:Secret`
- `AdminUser:FirstName`, `AdminUser:Email`, `AdminUser:Password`
- `ConnectionStrings:WTConnectionString`
- `ApplicationSettings:RefreshTokenTTL`

### Authentication Flow
1. User registers/logs in via API endpoints
2. API returns JWT token (30-minute expiry) and refresh token (7-day expiry)
3. Client includes JWT in `Authorization: Bearer <token>` header
4. Refresh token can be used to obtain new JWT without re-authentication
5. Tokens are rotated on each refresh for security

### User Roles
- `ADMIN_DEVELOPER`: Full system access
- `ADMIN_EDITOR`: Content management
- `USER_EDITOR`: Trail editing capabilities
- `USER`: Basic authenticated user

## 🗄️ Database

### Entity Framework Core
The project uses EF Core 9 with SQL Server:
- **DbContext**: `AppDbContext` in `WT.Infrastructure`
- **Identity**: ASP.NET Core Identity with `Guid` primary keys
- **Migrations**: Code-first migrations for schema management

### Key Entities
- `ApplicationUser`: Extends `IdentityUser<Guid>` with custom properties
- `RefreshToken`: Manages JWT refresh tokens
- *Additional entities to be added for trails, reviews, etc.*

### Common Commands
```bash
# Add new migration
Add-Migration MigrationName

# Apply migrations to database
Update-Database

# Remove last migration (if not applied)
Remove-Migration

# Generate SQL script for migration
Script-Migration
```

## 🧪 Testing

*Testing infrastructure to be implemented*

Planned testing strategy:
- **Unit Tests**: Business logic in Application layer
- **Integration Tests**: API endpoints and database operations
- **E2E Tests**: Complete user workflows

## 📁 Project Documentation

For detailed development guidelines and best practices, see:
- [GitHub Copilot Instructions](.github/copilot-instructions.md) - Comprehensive development guidelines

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

Please ensure your code follows the project's architecture patterns and conventions outlined in the Copilot Instructions.

## 📝 Development Status

**Current Phase**: Web API Development (Controllers)

**Branch**: `webapi-controllers`

### Completed
- ✅ Clean Architecture foundation
- ✅ ASP.NET Core Identity integration
- ✅ JWT authentication with refresh tokens
- ✅ User registration and login endpoints
- ✅ Database schema and migrations
- ✅ API documentation with Scalar

### In Progress
- 🔨 Account management controllers
- 🔨 Trail CRUD endpoints
- 🔨 Review and rating system

### Planned
- 📋 Admin panel functionality
- 📋 Blazor WebAssembly client
- 📋 PWA features (offline support, installability)
- 📋 Search and filtering
- 📋 Photo upload and management
- 📋 Map integration
- 📋 Testing suite
- 📋 Azure deployment

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👥 Authors

- **oppenheimerm** - *Initial work* - [GitHub](https://github.com/oppenheimerm)

## 🙏 Acknowledgments

- Microsoft for .NET and Blazor
- The accessibility community for inspiration and feedback
- Open source contributors

## 📞 Support

For questions or support, please:
- Open an issue on [GitHub](https://github.com/oppenheimerm/wheeltrails/issues)
- Contact the maintainer via GitHub

---

**Built with ❤️ for the wheely community**
