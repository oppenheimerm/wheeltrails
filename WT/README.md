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
- Secure user registration and login with comprehensive validation
- **Email verification system with automated email sending** ✨
- **Password reset functionality with secure token-based flow** ✨
- Refresh token rotation for enhanced security (7-day expiry)
- Custom authentication state provider for Blazor applications
- Local storage integration for client-side token management
- Automatic revocation of all sessions on password change
- IP address tracking for security monitoring

### 👤 User Interface & Navigation ✨ NEW
- **User Menu Dropdown** with profile avatar
  - Displays user profile picture or Material Symbol icon fallback
  - Personalized greeting with user's first name
  - Quick access to Profile, Settings, and Logout
  - Smooth transitions and hover effects
  - Mobile-responsive design
  - Automatic close on navigation
- **Enhanced Navigation Bar**
  - Active link highlighting
  - Dark mode support
  - Mobile hamburger menu
  - Tailwind CSS styling

### 📝 User Registration Features
- **Multi-step registration form** with comprehensive validation
  - First name (3-30 characters, required)
  - Email address with format validation and uniqueness check
  - Password with confirmation (minimum 7 characters)
  - Optional bio field (max 500 characters)
  - Country code selection from predefined list
- **Terms and Conditions Modal**
  - Interactive modal dialog for terms acceptance
  - JavaScript Interop for smooth modal interactions
  - Accept/Decline functionality with navigation
  - Backdrop click to close
- **Registration Success Page** (`/account/identity/registration-success`)
  - Dedicated success page with personalized email confirmation
  - Email address displayed for user verification
  - Step-by-step verification instructions
  - Resend verification email functionality (planned)
  - Quick navigation to login or home page
  - Beautiful, responsive UI with step-by-step instructions
- **Email Verification Page** (`/account/identity/verify-email`) ✨
  - Automatic email verification with token from URL query parameter
  - Four distinct UI states: Loading, Success, Error, and Missing Token
  - User-friendly error messages with troubleshooting tips
  - Auto-redirect to login page after successful verification (3 seconds)
  - Manual navigation options to login, register, or home
  - Token validation via ASP.NET Identity
  - Comprehensive logging for debugging
- **Enhanced User Experience**
  - Real-time form validation with visual feedback
  - Loading states during submission
  - Error message display
  - Success message handling
  - Query parameter support for email tracking
  - Responsive design for all devices

### 🔑 Password Reset Features ✨
- **Forgot Password Page** (`/account/identity/forgot-password`)
  - Clean, user-friendly password reset request form
  - Email address validation
  - Generic success messages to prevent user enumeration attacks
  - Loading states and error handling
  - Navigation to login and home pages
- **Reset Password Page** (`/account/identity/reset-password`)
  - Secure password reset form with token validation
  - Token extracted from URL query parameter
  - Password strength validation with confirmation
  - Real-time form validation feedback
  - Four distinct UI states: Loading, Form, Success, and Error
  - Auto-redirect to login page after successful reset (3 seconds)
  - User-friendly error messages and troubleshooting tips
- **Forgot Password Flow**
  - Secure password reset request via email
  - Token generation via ASP.NET Identity's `GeneratePasswordResetTokenAsync()`
  - Generic responses to prevent user enumeration attacks
  - Email confirmation required before reset allowed
  - 24-hour token expiration (configurable via `DataProtectionTokenProviderOptions`)
  - SMTP-based email delivery with branded templates
- **Reset Password Process**
  - Token validation via ASP.NET Identity's `ResetPasswordAsync()`
  - Password strength validation
  - Single-use tokens (automatically invalidated after use)
  - All refresh tokens revoked on successful password reset for security
  - Comprehensive logging for security monitoring
- **Security Features**
  - Tokens sent via email only (never exposed in API responses)
  - Failed attempts logged for security monitoring with timestamps
  - IP address tracking for reset operations
  - Prevention of user enumeration attacks
  - Session invalidation on password change
  - Cryptographically secure token generation

### 📧 Email Notifications
- Automated email verification for new user registrations
- **Password reset emails with secure tokens** ✨
- HTML email templates with responsive design
- Personalized emails with user's first name
- Branded templates with WheelyTrails theme (🦽🌲)
- Support for multiple SMTP providers (Gmail, SendGrid, Outlook, Mailtrap, AWS SES, Mailgun)
- Configurable email settings via User Secrets
- 48-hour verification link expiration
- 24-hour password reset link expiration
- Email service abstraction via `IEmailService` interface

### 🛠️ Developer Tools
- **Authentication Diagnostic Page** (`/auth-diagnostic`) 🔍
  - Real-time authentication state inspection
  - Local storage data viewer with JSON formatting
  - Claims viewer with all user claims
  - Configuration checker (API URL, LocalStorage key)
  - Full diagnostic report with error handling
  - Helps troubleshoot authentication issues during development

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
- **Password Reset**: ASP.NET Identity Token Providers (configurable 24-hour expiry)
- **Email Service**: SMTP-based email delivery (supports Gmail, SendGrid, Outlook, Mailtrap, AWS SES)
- **Object Mapping**: [Mapster](https://github.com/MapsterMapper/Mapster)
- **Logging**: [Serilog](https://serilog.net/)
- **API Documentation**: [Scalar](https://guides.scalar.com/scalar/scalar-api-references/integrations/net-aspnet-core/integration)

### Frontend
- **Client App**: [Blazor WebAssembly (.NET 9)](https://dotnet.microsoft.com/en-us/apps/aspnet/web-apps/blazor)
- **Admin Panel**: [Blazor Server (.NET 9)](https://dotnet.microsoft.com/en-us/apps/aspnet/web-apps/blazor)
- **UI Framework**: [Tailwind CSS](https://tailwindcss.com/)
- **JavaScript Interop**: Custom modal helpers for enhanced UX
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

**OptionA: Run API only**
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

6. **Test Registration Flow**

After starting the application:
1. Navigate to the registration page (`/account/identity/register`)
2. Fill out the registration form:
- First name (required, 3-30 characters)
- Email address (required, valid format)
- Bio (optional, max 500 characters)
- Password (required, min 7 characters)
- Confirm password (must match)
- Country code (select from dropdown)
- Accept Terms and Conditions (click link to view modal)
3. Click "Create Account"
4. You'll be redirected to the success page showing your email
5. Check your email service:
- **Mailtrap**: Go to [https://mailtrap.io/inboxes](https://mailtrap.io/inboxes) and view the captured email
- **Gmail**: Check your Gmail inbox
6. Click the verification link in the email to verify your account
7. Return to login page and sign in

8. **Test Password Reset Flow** ✨ NEW

After registration:
1. Navigate to the login page
2. Click "Forgot Password?" link (when implemented)
3. Enter your registered email address
4. Check your email for password reset link
5. Click the reset link and enter new password
6. All existing sessions will be logged out
7. Log in with your new password

### Development URLs

| Project | Purpose | HTTPS URL | HTTP URL |
|---------|---------|-----------|----------|
| API | Web API Backend | https://localhost:5001 | http://localhost:5000 |
| WT.Admin | Admin Panel | https://localhost:7127 | http://localhost:5041 |
| WT.Client | Client PWA | https://localhost:7000 | http://localhost:7001 |

### Registration Flow Diagram

````````

## 📚 API Documentation

The Web API uses Scalar for interactive API documentation. Once the API is running, visit:

**https://localhost:5001/scalar/v1**

This provides:
- Interactive API testing
- Request/response examples
- Authentication testing
- Endpoint documentation

### Key API Endpoints

#### Registration Endpoint

**POST** `/api/account/identity/create`

**Request Body:**
```json
{
  "firstName": "string (required, 3-30 characters)",
  "email": "user@example.com (required, valid format)",
  "bio": "string (optional, max 500 characters)",
  "password": "string (required, min 7 characters)",
  "confirmPassword": "string (must match password)",
  "countryCode": "string (select from dropdown)",
  "termsAccepted": true
}
```

**Success Response (200 OK):**
```json
{
  "succeeded": true,
  "message": "Registration successful. Check your email for verification link.",
  "errors": null
}
```


# Response
```json
{
  "succeeded": true,
  "token": "jwt_token",
  "refreshToken": "refresh_token",
  "user": {
    "id": "user_id",
    "email": "user@example.com",
    "firstName": "User",
    "role": "USER"
  }
}
```

## Trail Management

### Create Trail

**POST** `/api/trails`

**Request Body:**
```json
{
  "location": {
    "latitude": 12.345678,
    "longitude": 87.654321
  },
  "difficulty": "Easy",
  "length": 5.2,
  "surface": "Paved",
  "accessibilityFeatures": ["Wheelchair\nRamp"],
  "amenities": ["Restroom", "Parking"],
  "description": "A beautiful and accessible trail."
}
```

# Response
```json
{
  "succeeded": true,
  "trailId": "new_trail_id",
  "message": "Trail created successfully."
}
```

### Get Trail by ID

**GET** `/api/trails/{id}`

# Response
```json
{
  "id": "trail_id",
  "location": {
    "latitude": 12.345678,
    "longitude": 87.654321
  },
  "difficulty": "Easy",
  "length": 5.2,
  "surface": "Paved",
  "accessibilityFeatures": ["Wheelchair\nRamp"],
  "amenities": ["Restroom", "Parking"],
  "description": "A beautiful and accessible trail.",
  "reviews": [
    {
      "userId": "user_id",
      "rating": 5,
      "comment": "Very accessible and well-maintained."
    }
  ]
}
```

### Update Trail

**PUT** `/api/trails/{id}`

**Request Body:**
```json
{
  "difficulty": "Moderate",
  "length": 6.0,
  "surface": "Gravel",
  "accessibilityFeatures": ["Wheelchair\nRamp", "Wide\nPath"],
  "amenities": ["Restroom", "Parking", "Picnic\nTable"],
  "description": "Updated trail description."
}
```

# Response
```json
{
  "succeeded": true,
  "message": "Trail updated successfully."
}
```

### Delete Trail

**DELETE** `/api/trails/{id}`

# Response
```json
{
  "succeeded": true,
  "message": "Trail deleted successfully."
}
```

### Search Trails

**GET** `/api/trails/search`

**Query Parameters:**
- `location`: `longitude,latitude`
- `distance`: `number_in_miles`
- `difficulty`: `Easy|Moderate|Challenging`
- `surface`: `paved|gravel|boardwalk|...`
- `amenities`: `parking,restrooms,...` (comma-separated)

# Response
```json
{
  "trails": [
    {
      "id": "trail_id",
      "location": {
        "latitude": 12.345678,
        "longitude": 87.654321
      },
      "difficulty": "Easy",
      "length": 5.2,
      "surface": "Paved",
      "accessibilityFeatures": ["Wheelchair\nRamp"],
      "amenities": ["Restroom", "Parking"],
      "description": "A beautiful and accessible trail."
    }
  ]
}
```

### Add Review

**POST** `/api/trails/{trailId}/reviews`

**Request Body:**
```json
{
  "rating": 5,
  "comment": "This trail is amazing!"
}
```

# Response
```json
{
  "succeeded": true,
  "message": "Review added successfully."
}
```

### Get Reviews for Trail

**GET** `/api/trails/{trailId}/reviews`

# Response
```json
{
  "reviews": [
    {
      "userId": "user_id",
      "rating": 5,
      "comment": "This trail is amazing!"
    }
  ]
}
```

### Analytics Data

**GET** `/api/admin/analytics`

# Response
```json
{
  "totalUsers": 150,
  "totalTrails": 75,
  "totalReviews": 200,
  "userGrowthRate": 5.2,
  "trailCompletionRate": 80.5
}
```

### Error Response Format
```json
{
  "succeeded": false,
  "message": "Error message describing the issue.",
  "errors": {
    "fieldName": "Validation error message",
    "anotherField": "Another error message"
  }
}
```

### HTTP Status Codes
- `200 OK`: Successful request
- `201 Created`: Resource created successfully
- `204 No Content`: Successful request with no content
- `400 Bad Request`: Client-side input validation failed
- `401 Unauthorized`: Authentication failed or not provided
- `403 Forbidden`: Insufficient permissions for the requested operation
- `404 Not Found`: Requested resource not found
- `500 Internal Server Error`: Server-side error, unexpected condition

Ensure the client application handles these status codes appropriately for a seamless user experience.

For detailed API documentation, visit **[Scalar API Docs](https://localhost:5001/scalar/v1)** after running the application.

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

Required secrets for API and Infrastructure projects:
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
4. User is redirected to success page with email confirmation
5. User clicks verification link in email to verify account
6. User logs in via API endpoint
7. API returns JWT token (30-minute expiry) and refresh token (7-day expiry)
8. Client stores tokens in browser local storage using configured `LocalStorageKey`
9. Client includes JWT in `Authorization: Bearer <token>` header for authenticated requests
10. Refresh token can be used to obtain new JWT without re-authentication
11. Tokens are rotated on each refresh for security
12. Custom `AuthenticationStateProvider` manages authentication state in Blazor components

### Registration Security Features
- ✅ **Terms acceptance bypass in development**: `AcceptTerms` validation skipped in Development environment
- ✅ **Email verification required**: Users must verify email before login (can be disabled for testing)
- ✅ **Password hashing**: All passwords hashed using ASP.NET Identity's secure hashing
- ✅ **Role-based access**: Default USER role assigned to all new registrations
- ✅ **Data validation**: Server-side and client-side validation
- ✅ **CSRF protection**: Built-in ASP.NET Core anti-forgery tokens
- ✅ **Rate limiting**: (Planned) Prevent registration abuse

### Password Reset Security Features ✨ NEW
- ✅ **Token expiration**: 24-hour token validity (configurable)
- ✅ **Single-use tokens**: Automatically invalidated after use
- ✅ **Email confirmation required**: Only verified emails can reset passwords
- ✅ **Session invalidation**: All refresh tokens revoked on password change
- ✅ **User enumeration prevention**: Generic responses regardless of email existence
- ✅ **IP address tracking**: All password reset attempts logged with IP
- ✅ **Comprehensive logging**: Security monitoring for failed attempts

### Navigation Patterns After Registration

**Registration Flow** (Use `forceLoad: false` ✅)

After successful registration:
- User data validated server-side
- Verification email sent via SMTP
- User redirected to success page: `/account/identity/registration-success?email={encodedEmail}`
- Email address displayed in success page for confirmation
- User can navigate to login page or home page

**Why pass email as query parameter?**
- ✅ Personalized success message
- ✅ User knows which email to check
- ✅ Enables resend verification functionality
- ✅ Better user experience

**Terms and Conditions Modal Flow**

User interactions:
- Click "Terms and Conditions" link → Modal opens (JavaScript Interop)
- Click "I Accept" → Checkbox checked, modal closes, user can submit form
- Click "Decline" → User redirected to homepage
- Click "X" or outside modal → Modal closes
- Press ESC key → Modal closes (optional enhancement)

**Password Reset Flow** (Use `forceLoad: false` ✅) ✨ NEW

After successful password reset:
- Password validated and updated
- All refresh tokens revoked
- User redirected to login page
- Success message displayed
- User can log in with new password

### User Roles
- `ADMIN_DEVELOPER`: Full system access
- `ADMIN_EDITOR`: Content management
- `USER_EDITOR`: Trail editing capabilities
- `USER`: Basic authenticated user (default for new registrations)

## 📧 Email Service

### Architecture
The email service follows Clean Architecture principles:
- **Interface**: `IEmailService` in `WT.Application.Contracts`
- **Implementation**: `EmailService` in `WT.Infrastructure.Services`
- **Registration**: Configured in `ServiceContainer.AddInfrastructureServices()'

### Features
- ✅ HTML email templates with responsive design
- ✅ Account verification emails with personalized greeting
- ✅ **Password reset emails with secure tokens** ✨ NEW
- ✅ Branded templates with WheelyTrails theme
- ✅ Verification link with 48-hour expiration
- ✅ **Password reset link with 24-hour expiration** ✨ NEW
- ✅ Configurable SMTP settings via User Secrets
- ✅ Support for multiple SMTP providers
- ✅ Comprehensive error logging
- ✅ Email sending success/failure tracking

### Email Templates

**Verification Email**
- Branded header with WheelyTrails logo theme (🦽🌲)
- Personalized greeting with user's first name
- Prominent "Verify Email Address" call-to-action button
- Plain text verification link as fallback
- 48-hour expiration notice
- Professional footer with copyright information
- Mobile-responsive design

**Password Reset Email** ✨ NEW
- Security-focused design
- Personalized greeting with user's first name
- Clear "Reset Password" call-to-action button
- Plain text reset link as fallback
- 24-hour expiration notice
- Safety information if request was not made by user
- Contact support information
- Professional footer
- Mobile-responsive design

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
4. Copy your credentials and configure User Secrets (see Installation step 2)
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

## 🗄️ Database

### Entity Framework Core
The project uses EF Core 9 with SQL Server:
- **DbContext**: `AppDbContext` in `WT.Infrastructure`
- **Identity**: ASP.NET Core Identity with `Guid` primary keys
- **Migrations**: Code-first migrations for schema management

### Key Entities
- `ApplicationUser`: Extends `IdentityUser<Guid>` with custom properties including:
  - `FirstName` (string, required)
  - `Bio` (string?, optional, max 500 characters)
  - `CountryCode` (string?, optional, 2 characters)
  - `VerificationToken` (string?, 128-character hex)
  - `Verified` (DateTime?, timestamp of verification)
  - `AcceptTerms` (bool, required)
  - `ProfilePicture` (string?, URL to profile image)
  - `Roles` (List<IdentityRole<Guid>>?, navigation property)
  - `RefreshTokens` (List<RefreshToken>?, navigation property)
- `RefreshToken`: Manages JWT refresh tokens with rotation support
  - `Token` (string, 64-byte base64, unique)
  - `Expires` (DateTime, 7-day expiry)
  - `Created` (DateTime?, creation timestamp)
  - `CreatedByIp` (string?, client IP address)
  - `Revoked` (DateTime?, revocation timestamp)
  - `RevokedByIp` (string?, revocation IP)
  - `ReplacedByToken` (string?, token chain tracking)
  - `ReasonRevoked` (string?, audit reason - e.g., "Password reset")
  - `AccountId` (Guid, foreign key to ApplicationUser)
- *Additional entities to be added for trails, reviews, etc.*

### Common Commands

````````

## 🧪 Testing

*Testing infrastructure to be implemented*

Planned testing strategy:
- **Unit Tests**: Business logic in Application layer
  - RegisterDTO validation
  - ForgotPasswordDTO validation ✨ NEW
  - ResetPasswordDTO validation ✨ NEW
  - StringHelpers country code utilities
  - Email service mocking
- **Integration Tests**: API endpoints and database operations
  - Registration endpoint with valid/invalid data
  - Email verification workflow
  - **Password reset workflow** ✨ NEW
  - Database state after registration
  - **Refresh token revocation on password change** ✨ NEW
- **E2E Tests**: Complete user workflows
  - Full registration flow
  - Email verification click-through
  - Terms and conditions modal interaction
  - **Complete password reset flow** ✨ NEW
- **Email Testing**: Mock email service for unit tests, Mailtrap/Papercut for integration tests
- **UI Tests**: Blazor component testing
  - Form validation
  - Modal behavior
  - Navigation flow
  - **Password reset form validation** ✨ NEW

## 📁 Project Documentation

For detailed development guidelines and best practices, see:
- [GitHub Copilot Instructions](.github/copilot-instructions.md) - Comprehensive development guidelines
- [Architecture Documentation](docs/architecture.md) - Clean Architecture details (planned)
- [API Documentation](https://localhost:5001/scalar/v1) - Interactive API reference

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

Please ensure your code follows the project's architecture patterns and conventions outlined in the Copilot Instructions.

### Contribution Guidelines
- Follow Clean Architecture principles
- Write unit tests for new features
- Update documentation for significant changes
- Follow C# 13 and .NET 9 conventions
- Use Tailwind CSS for styling
- Implement responsive design
- Add XML documentation comments
- Log important operations

## 📝 Development Status

**Current Phase**: Blazor WebAssembly Client Development

**Branch**: `api-register`

### Completed
- ✅ Clean Architecture foundation
- ✅ ASP.NET Core Identity integration
- ✅ JWT authentication with refresh tokens
- ✅ User registration endpoint with validation
- ✅ User login endpoint
- ✅ Email verification system with SMTP support
- ✅ **Password reset functionality** ✨ NEW
  - ✅ Forgot password endpoint
  - ✅ Reset password endpoint
  - ✅ Password reset email templates
  - ✅ Token generation and validation
  - ✅ Session invalidation on password change
- ✅ Multiple email provider support (Mailtrap, Gmail, SendGrid, etc.)
- ✅ Database schema and migrations
- ✅ API documentation with Scalar
- ✅ Registration form with comprehensive validation
- ✅ Terms and Conditions modal with JavaScript Interop
- ✅ Registration success page with email confirmation
- ✅ Country code selection dropdown
- ✅ Form validation with visual feedback
- ✅ Error and success message handling
- ✅ Responsive design for mobile/tablet/desktop

### In Progress
- 🔨 **Forgot Password UI (Blazor client)** ✨ NEW
- 🔨 **Reset Password UI (Blazor client)** ✨ NEW
- 🔨 Email resend functionality
- 🔨 User profile management
- 🔨 Trail CRUD endpoints
- 🔨 Review and rating system

### Planned
- 📋 User profile page with edit capabilities
- 📋 Change password functionality (authenticated users)
- 📋 Admin panel functionality
- 📋 Complete Blazor WebAssembly client features
- 📋 PWA features (offline support, installability)
- 📋 Advanced search and filtering
- 📋 Photo upload and management
- 📋 Map integration with interactive markers
- 📋 Social login (Google, Facebook, Apple)
- 📋 Two-factor authentication (2FA)
- 📋 Testing suite (unit, integration, E2E)
- 📋 Azure deployment
- 📋 CI/CD pipeline

## 📊 Project Statistics

- **Total Projects**: 6 (Domain, Application, Infrastructure, API, Admin, Client)
- **Lines of Code**: ~18,000+ (and growing) ⬆️
- **Languages**: C# 13, Razor, HTML, CSS (Tailwind), JavaScript
- **Target Framework**: .NET 9
- **Database**: SQL Server with EF Core 9
- **Frontend**: Blazor WebAssembly + Blazor Server
- **Architecture Pattern**: Clean Architecture (Onion)

## 🔗 Useful Links

- [ASP.NET Core Documentation](https://docs.microsoft.com/en-us/aspnet/core/)
- [ASP.NET Core Identity](https://docs.microsoft.com/en-us/aspnet/core/security/authentication/identity)
- [Blazor Documentation](https://docs.microsoft.com/en-us/aspnet/core/blazor/)
- [Entity Framework Core](https://docs.microsoft.com/en-us/ef/core/)
- [Tailwind CSS](https://tailwindcss.com/docs)
- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)
- [Clean Architecture Principles](https://blog.cleancoder.com/uncle-bob/2012/08/13/the-clean-architecture.html)
- [OWASP Password Reset Guide](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Contact

- GitHub: [@oppenheimerm](https://github.com/oppenheimerm)
- Issues: [GitHub Issues](https://github.com/oppenheimerm/wheeltrails/issues)
- Project Repository: [https://github.com/oppenheimerm/wheeltrails](https://github.com/oppenheimerm/wheeltrails)

## 🙏 Acknowledgments

- ASP.NET Core team for excellent framework and documentation
- Blazor community for inspiration and best practices
- Tailwind CSS for utility-first CSS framework
- Mailtrap for excellent email testing service
- All contributors and supporters of accessible outdoor recreation

---

📖 **For detailed technical documentation, see [src/WT/README.md](src/WT/README.md)**

🦽🌲 **Making outdoor adventures accessible to everyone, one trail at a time.**
