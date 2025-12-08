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
- Email verification for new accounts
- Refresh token rotation for enhanced security (7-day expiry)
- Custom authentication state provider for Blazor applications
- Local storage integration for client-side token management

### 📧 Email Notifications
- Automated email verification for new user registrations
- Password reset functionality with secure email tokens
- HTML email templates with responsive design
- Support for multiple SMTP providers (Gmail, SendGrid, Outlook, Mailtrap, etc.)
- Configurable email settings via User Secrets

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
- **Email Service**: SMTP-based email delivery (supports Gmail, SendGrid, Outlook, Mailtrap, AWS SES)
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
- SMTP email service account (recommended: [Mailtrap](https://mailtrap.io) for development/testing)

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

3. **Configure Email Service**

Choose one of the following email service providers based on your needs:

**Option A: Mailtrap (⭐ Recommended for Development/Testing)**

[Mailtrap](https://mailtrap.io) is a safe email testing service that captures emails without sending them to real recipients. Perfect for development!

**Benefits of Mailtrap:**
- ✅ **Free tier**: 500 emails/month, 5 inboxes
- ✅ **Safe testing**: Emails never reach real inboxes
- ✅ **Email preview**: View how emails look in different clients (Gmail, Outlook, etc.)
- ✅ **Spam testing**: Check if your emails might be flagged as spam
- ✅ **HTML validation**: Verify your email templates render correctly
- ✅ **Team collaboration**: Share inboxes with team members
- ✅ **API access**: Automate email testing

After configuration, access your captured emails at: [https://mailtrap.io/inboxes](https://mailtrap.io/inboxes)

   **Option B: Gmail (Development/Testing)**

   **Option C: Outlook (Development/Testing)**

4. **Apply Database Migrations**

````````
cd WT.Infrastructure
dotnet ef database update
```
> **Note**: Ensure SQL Server LocalDB is running. Use `SqlLocalDB start` command if needed.

5. **Run the Application**
   
   **Option A: Run API only**
````````
cd API
dotnet run
````````

Visit `https://localhost:5001` to access the API.

**Option B: Run multiple projects** (in Visual Studio)
- Right-click on the Solution → Properties
- Select "Multiple startup projects"
- Set `API`, `WT.Admin`, and `WT.Client` to "Start"
- Press F5

6. **Test Email Functionality**

After starting the application:
1. Navigate to the registration page
2. Register a new user account
3. Check your email service:
   - **Mailtrap**: Go to [https://mailtrap.io/inboxes](https://mailtrap.io/inboxes) and view the captured email
   - **Gmail**: Check your Gmail inbox
   - **Papercut**: View the email in the Papercut UI window
4. Click the verification link to verify your account

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

### Configuration Strategy by Project Type

#### Server-Side Projects (API, WT.Infrastructure)
✅ **Use User Secrets** for sensitive configuration:
- Database connection strings
- JWT signing secrets
- SMTP credentials and passwords
- API keys and credentials
- Admin user passwords
- Any sensitive data

#### Blazor WebAssembly (WT.Client)
⚠️ **Use appsettings.json in wwwroot** (public configuration only):
- ✅ API base URLs
- ✅ Local storage keys
- ✅ Feature flags
- ❌ **NEVER** database credentials
- ❌ **NEVER** JWT secrets
- ❌ **NEVER** SMTP credentials
- ❌ **NEVER** API keys or passwords

> **Why?** Blazor WASM runs entirely in the browser. All files in `wwwroot` are downloaded to the client and can be inspected using browser DevTools. User Secrets only work for server-side .NET projects.

### User Secrets
The project uses .NET User Secrets for sensitive configuration during development. **Never commit secrets to source control.**

Required secretsfor API and Infrastructure projects:
- `JwtSettings:Issuer`, `JwtSettings:Audience`, `JwtSettings:Secret`
- `AdminUser:FirstName`, `AdminUser:Email`, `AdminUser:Password`
- `ConnectionStrings:WTConnectionString`
- `ApplicationSettings:RefreshTokenTTL`
- `EmailSettings:SmtpHost`, `EmailSettings:SmtpPort`, `EmailSettings:SmtpUser`, `EmailSettings:SmtpPassword`
- `EmailSettings:EnableSsl`, `EmailSettings:FromEmail`, `EmailSettings:FromName`, `EmailSettings:ClientUrl`

### Authentication Flow
1. User registers via API endpoint
2. System generates a cryptographically secure 128-character verification token
3. Verification email is sent to user's email address with verification link
4. User clicks verification link to verify account
5. User logs in via API endpoint
6. API returns JWT token (30-minute expiry) and refresh token (7-day expiry)
7. Client stores tokens in browser local storage using configured `LocalStorageKey`
8. Client includes JWT in `Authorization: Bearer <token>` header for authenticated requests
9. Refresh token can be used to obtain new JWT without re-authentication
10. Tokens are rotated on each refresh for security
11. Custom `AuthenticationStateProvider` manages authentication state in Blazor components

### Email Verification Flow
1. User registers or requests email verification
2. System generates a verification token and sends email via SMTP
3. User receives email with verification link
4. User clicks verification link
5. Web API verifies token and activates user account
6. User can now log in

#### Navigation Patterns After Authentication

The application uses specific navigation patterns to ensure proper authentication state management:

**Login Flow** (Use `forceLoad: false` ✅)

After a successful login, the client app should:
- Store `token` and `refreshToken` in local storage
- Navigate to the requested page or home page
- Use `Authorization: Bearer <token>` for API requests

**Why `forceLoad: false` for login?**
- ⚡ Preserves authentication state just set in memory
- ✨ Instant UI updates - `<AuthorizeView>` components respond immediately
- 🎯 Smooth SPA-like navigation experience
- 💪 No unnecessary page reload or flash of content

**Logout Flow** (Use `forceLoad: true` ✅)

After logout, the client app should:
- Clear `token` and `refreshToken` from local storage
- Navigate to the login page or home page
- Revalidate authentication state on the server

**Why `forceLoad: true` for logout?**
- 🔄 Forces a full page reload to clear application state
- 🚫 Prevents access to authenticated routes until re-logged in
- ✅ Ensures proper cleanup of resources and state

### User Roles
- `ADMIN_DEVELOPER`: Full system access
- `ADMIN_EDITOR`: Content management
- `USER_EDITOR`: Trail editing capabilities
- `USER`: Basic authenticated user

## 📧 Email Service

### Architecture
The email service follows Clean Architecture principles:
- **Interface**: `IEmailService` in `WT.Application.Contracts`
- **Implementation**: `EmailService` in `WT.Infrastructure.Services`
- **Registration**: Configured in `ServiceContainer.AddInfrastructureServices()`

### Features
- ✅ HTML email templates with responsive design
- ✅ Account verification emails
- ✅ Password reset emails (planned)
- ✅ Configurable SMTP settings via User Secrets
- ✅ Support for multiple SMTP providers
- ✅ Comprehensive error logging
- ✅ Email sending success/failure tracking

### Email Templates

**Verification Email**
- Branded header with WheelyTrails logo theme
- Personalized greeting with user's first name
- Prominent "Verify Email Address" call-to-action button
- Plain text verification link as fallback
- 48-hour expiration notice
- Professional footer

**Password Reset Email** (planned)
- Security-focused design
- Clear reset password instructions
- 24-hour expiration notice
- Safety information if request was not made by user

### SMTP Provider Support

| Provider | SMTP Host | Port | SSL | Notes | Best For |
|----------|-----------|------|-----|-------|----------|
| **[Mailtrap](https://mailtrap.io)** ⭐ | sandbox.smtp.mailtrap.io | 2525 | Yes | Safe email testing, free tier available | Development & Testing |
| **Gmail** | smtp.gmail.com | 587 | Yes | Requires App Password with 2FA | Development |
| **SendGrid** | smtp.sendgrid.net | 587 | Yes | Reliable, scalable | Production |
| **Outlook** | smtp.office365.com | 587 | Yes | Works with Outlook/Hotmail | Development/Production |
| **AWS SES** | email-smtp.{region}.amazonaws.com | 587 | Yes | Configure SMTP credentials in AWS | Production |
| **Mailgun** | smtp.mailgun.org | 587 | Yes | Use SMTP relay credentials | Production |
| **Papercut** | localhost | 25 | No | No internet required, local only | Local Testing |

### Testing Email Locally

#### Option 1: Mailtrap (⭐ Recommended)

[Mailtrap](https://mailtrap.io) provides a safe email testing environment that captures emails without sending them to real recipients.

**Setup Steps:**
1. Sign up for a free account at [https://mailtrap.io](https://mailtrap.io)
2. Create an inbox (or use the default "My Inbox")
3. Go to **SMTP Settings** tab
4. Copy your credentials and configure User Secrets (see Installation step 3)
5. Start your application and register a new user
6. View the captured email at [https://mailtrap.io/inboxes](https://mailtrap.io/inboxes)

**Mailtrap Features:**
- 📧 Email inbox viewer with multiple client previews
- 🐛 HTML and CSS validation
- 📊 Spam score analysis
- 📱 Mobile and desktop email previews
- 🔗 API access for automated testing
- 👥 Team collaboration with shared inboxes

**Free Tier Limits:**
- 500 emails per month
- 5 inboxes
- Email history retention
- Unlimited team members

#### Option 2: Papercut SMTP

For completely local testing without internet connection:

- Install and run [Papercut SMTP](https://github.com/ChangemakerStudios/Papercut-SMTP)
- Configure User Secrets with `SmtpHost=localhost`, `SmtpPort=25`, leave user/password blank
- Register a new user in the application
- View the email in the Papercut desktop application

Papercut will capture all emails in a local desktop application without actually sending them.

### Switching Between Development and Production

**Development Environment:**
- API URL: `https://localhost:5001`
- Admin URL: `https://localhost:7127`
- Client URL: (To be configured)
- Email: Mailtrap (Local SMTP for development)

**Production Environment:**
- API URL: `https://api.wheeltrails.com`
- Admin URL: `https://admin.wheeltrails.com`
- Client URL: `https://wheeltrails.com`
- Email: Configured SMTP provider (SendGrid, Gmail, etc.)

Use environment-specific configuration files or Azure App Configuration for seamless switching between environments.

## 🗄️ Database

### Entity Framework Core
The project uses EF Core 9 with SQL Server:
- **DbContext**: `AppDbContext` in `WT.Infrastructure`
- **Identity**: ASP.NET Core Identity with `Guid` primary keys
- **Migrations**: Code-first migrations for schema management

### Key Entities
- `ApplicationUser`: Extends `IdentityUser<Guid>` with custom properties including email verification
- `RefreshToken`: Manages JWT refresh tokens with rotation support
- *Additional entities to be added for trails, reviews, etc.*

### Common Commands

````````

## 🧪 Testing

*Testing infrastructure to be implemented*

Planned testing strategy:
- **Unit Tests**: Business logic in Application layer
- **Integration Tests**: API endpoints and database operations
- **E2E Tests**: Complete user workflows
- **Email Testing**: Mock email service for unit tests, Mailtrap/Papercut for integration tests

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

**Branch**: `WTClient-AuthPage`

### Completed
- ✅ Clean Architecture foundation
- ✅ ASP.NET Core Identity integration
- ✅ JWT authentication with refresh tokens
- ✅ User registration and login endpoints
- ✅ Email verification system with SMTP support
- ✅ Multiple email provider support (Mailtrap, Gmail, SendGrid, etc.)
- ✅ Database schema and migrations
- ✅ API documentation with Scalar

### In Progress
- 🔨 Account management controllers
- 🔨 Blazor WebAssembly client authentication
- 🔨 Trail CRUD endpoints
- 🔨 Review and rating system

### Planned
- 📋 Password reset functionality with email
- 📋 Admin panel functionality
- 📋 Complete Blazor WebAssembly client
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
- [Mailtrap](https://mailtrap.io) for excellent email testing infrastructure
- The accessibility community for inspiration and feedback
- Open source contributors

## 📞 Support

For questions or support, please:
- Open an issue on [GitHub](https://github.com/oppenheimerm/wheeltrails/issues)
- Contact the maintainer via GitHub

---

**Built with ❤️ for the wheely community**
