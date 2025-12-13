![WheelyTrails Logo](../logo.png)
# WheelyTrails.Com 🦽🌲

[![.NET Version](https://img.shields.io/badge/.NET-9.0-512BD4?logo=dotnet)](https://dotnet.microsoft.com/)
[![Blazor](https://img.shields.io/badge/Blazor-WebAssembly-512BD4?logo=blazor)](https://blazor.net/)
[![PWA](https://img.shields.io/badge/PWA-Enabled-5A0FC8?logo=pwa)](https://web.dev/explore/progressive-web-apps)
[![Firebase](https://img.shields.io/badge/Firebase-Storage-FFCA28?logo=firebase)](https://firebase.google.com/)
[![Application Insights](https://img.shields.io/badge/Azure-Application%20Insights-0078D4?logo=microsoft-azure)](https://azure.microsoft.com/en-us/services/monitor/)
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

### ⭐ User Reviews and Comments
- Community-driven comments and feedback system
- Share personal experiences and accessibility insights
- Help others make informed trail decisions
- Comment on trails with 300-character limit
- View comments with user attribution
- Delete comments when trails are deleted

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

### 📸 Photo Upload & Storage ✨
- **Firebase Cloud Storage Integration**
  - Secure, scalable cloud storage for images
  - FREE tier: 5GB storage, 1GB/day bandwidth
  - Global CDN for fast photo delivery
  - Automatic public URL generation
- **Profile Picture Upload**
  - User profile photos with automatic optimization
  - Resized to 400×400px, 80% JPEG quality
  - ~50-100KB per image (10-50x smaller than originals)
  - Stored in user-specific folders: `profile-pictures/{userId}/`
- **Trail Photo Upload**
  - Community trail photos with visual previews
  - Multiple file upload support (up to 5 photos)
  - Resized to 1200×1200px, 85% JPEG quality
  - ~200-400KB per image
  - Organized by trail: `trail-photos/{trailId}/`
- **Image Optimization**
  - Server-side processing with SixLabors.ImageSharp
  - Automatic resizing while maintaining aspect ratio
  - JPEG compression for reduced file sizes
  - Significant bandwidth and storage savings
- **Security Features**
  - Server-side upload validation (file size, type)
  - Firebase Security Rules for access control
  - Authenticated uploads only
  - User identity verification
  - Path traversal protection via filename sanitization
- **User Experience**
  - Drag-and-drop upload interface
  - Real-time upload progress indicators
  - Image preview before upload
  - Error handling with user-friendly messages
  - Mobile-responsive design

### 🔐 Authentication & Security
- JWT Bearer token authentication with ASP.NET Core Identity
- Role-based authorization (Admin Developer, Admin Editor, User Editor, User)
- Secure user registration and login with comprehensive validation
- **Email verification system with automated email sending**
- **Password reset functionality with secure token-based flow**
- Refresh token rotation for enhanced security (7-day expiry)
- Custom authentication state provider for Blazor applications
- Local storage integration for client-side token management
- Automatic revocation of all sessions on password change
- IP address tracking for security monitoring

### 👤 User Management ✨ NEW

#### **Unique Username System**
- **Display Username** (different from email)
  - 3-20 characters (letters, numbers, `_`, `-`, `.`)
  - Must be unique across all users
  - Can be changed once every 90 days
  - Cannot contain offensive or profanity words
  - Validated against LDNOOBW (List of Dirty, Naughty, Obscene, and Otherwise Bad Words)
- **Username Validation**
  - Real-time availability checking
  - Server-side profanity filter
  - Client-side format validation
  - Automatic uniqueness enforcement via database index

#### **Soft Delete System** ✨ NEW
- **Account Deactivation** (instead of hard delete)
  - Users marked as `IsDeleted` rather than removed from database
  - Trails and content preserved when user account is deactivated
  - User data anonymized for privacy compliance (GDPR-friendly)
  - Audit trail maintained with deletion timestamp and reason
- **Data Preservation**
  - All user-created trails remain accessible
  - Comments remain visible with `[Deleted User]` attribution
  - Trail photos remain available
  - Community contributions preserved
- **Account Recovery**
  - Soft-deleted accounts can be restored if needed
  - Full audit history maintained
  - Rollback capability for accidental deletions

### 👍 Trail Likes Feature ✨ NEW
- **Like/Unlike Trails**
  - Users can like trails to show appreciation and bookmark favorites
  - One like per user per trail (enforced by database constraint)
  - Real-time like count updates
  - Visual feedback on like status
- **Database Implementation**
  - Composite unique index on `(UserId, TrailId)` prevents duplicate likes
  - Performance indexes on `TrailId`, `UserId`, and `LikedAt`
  - Cascade deletion when user or trail is deleted
  - Timestamp tracking for analytics
- **API Endpoints**
  - `POST /api/trails/{trailId}/like` - Like a trail
  - `DELETE /api/trails/{trailId}/unlike` - Unlike a trail
  - `GET /api/trails/{trailId}/likes` - Get like count
  - `GET /api/trails/{trailId}/user-like-status` - Check if current user liked the trail

### 👤 User Interface & Navigation
- **User Menu Dropdown** with profile avatar
  - Displays user profile picture or Material Symbol icon fallback
  - Personalized greeting with user's first name or username
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
- **Email Verification Page** (`/account/identity/verify-email`)
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

### 🔑 Password Reset Features
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
- **Password reset emails with secure tokens**
- HTML email templates with responsive design
- Personalized emails with user's first name
- Branded templates with WheelyTrails theme (🦽🌲)
- Support for multiple SMTP providers (Gmail, SendGrid, Outlook, Mailtrap, AWS SES, Mailgun)
- Configurable email settings via User Secrets
- 48-hour verification link expiration
- 24-hour password reset link expiration
- Email service abstraction via `IEmailService` interface

### 📊 Monitoring & Observability ✨ NEW

#### **Azure Application Insights Integration**
- **Production Monitoring**
  - Real-time performance metrics
  - Request and response tracking
  - Exception logging and alerting
  - Dependency call monitoring (SQL, HTTP, etc.)
  - Custom telemetry and events
- **Configuration**
  - Connection string configured via User Secrets or Azure Key Vault
  - Automatic instrumentation for ASP.NET Core
  - Configurable sampling for high-traffic scenarios
- **Usage**
  - Monitor application availability and responsiveness
  - Track user interactions and feature usage
  - Analyze performance bottlenecks and failures
  - Monitor external dependency calls (e.g., SQL, API)
  - Custom alerts for critical failures or performance issues

#### **Health Checks** ✨ NEW
- **API Health Monitoring**
- Database connectivity check
- API status check
- Readiness and liveness probes for Kubernetes/Azure
- **Endpoints**
- `/health` - General health check
- `/health/ready` - Readiness probe (tagged checks)
- **Configuration**

#### **Rate Limiting** ✨ NEW
- **DDoS Protection**
- Global rate limit: 100 requests/minute per IP
- Auth endpoints limit: 10 requests/minute per IP
- Queue management for burst traffic
- Custom rejection responses
- **Policies**
- `AuthPolicy`: Strict limits for sensitive authenticationendpoints
- Global limiter: Default protection for all endpoints
- **Configuration**

## 🛠️ Developer Tools
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
- **File Storage**: Firebase Cloud Storage for images
- **Monitoring**: Azure Application Insights for telemetry ✨ NEW
- **Health Checks**: ASP.NET Core Health Checks with EF Core integration ✨ NEW
- **Rate Limiting**: ASP.NET Core Rate Limiting middleware ✨ NEW
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

### Cloud Services
- **Firebase**: Cloud storage for user-uploaded images
- **Azure Application Insights**: Performance monitoring and diagnostics ✨ NEW

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
- **Firebase Project** with Cloud Storage enabled (see Firebase setup below) ✨ NEW

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

3. **Configure Firebase Storage** ✨ NEW

**Step 1: Create a Firebase Project**
1. Go to [Firebase Console](https://console.firebase.google.com/)
2. Click "Add project" and follow the wizard
3. Enable Google Analytics (optional)

**Step 2: Enable Cloud Storage**
1. In the Firebase console, navigate to **Build** → **Storage**
2. Click "Get Started"
3. Choose production mode and select a storage location
4. Copy your storage bucket URL (format: `your-project.appspot.com`)

**Step 3: Generate Service Account Key**
1. Go to **Project Settings** (gear icon) → **Service Accounts**
2. Click "Generate New Private Key"
3. Save the JSON file securely (NEVER commit to source control!)
4. Copy the entire JSON content

**Step 4: Configure User Secrets**
   ```bash
   cd API
   dotnet user-secrets set "Firebase:Bucket" "your-project.appspot.com"
   dotnet user-secrets set "Firebase:DatabaseUrl" "https://your-project.firebaseio.com"
   dotnet user-secrets set "Firebase:ServiceAccount" "your-service-account-json"
   ```

4. **Configure Email Service**

Choose one of the following email service providers based on your needs:

**Option A: Mailtrap (⭐ Recommended for Development/Testing)**

[Mailtrap](https://mailtrap.io) is a safe email testing service that captures emails without sending them to real recipients. Perfect for development!

**Benefits ofMailtrap:**
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

5. **Install Required NuGet Packages** ✨ NEW

6. **Run the application**
   ```bash
   cd ../..
   dotnet run --project API
   ```
   - The API will be available at `https://localhost:5001`
   - The Client app will be available at `https://localhost:5001` (same as API, configured as a PWA)

7. **Access the application**
   - Open a web browser and navigate to `https://localhost:5001`
   - Register a new user account
   - Verify your email address using the link sent to your inbox
   - Sign in with your new account
   - Explore the admin panel at `https://localhost:5001/admin` (admin credentials: `admin@wheeltrails.com` / `Admin@123456`)

8. **Test Registration Flow**

After starting the application:
1. Navigate to the registration page (`/account/identity/register`)
2. Fill out the registration form:
   - First name (required, 3-30 characters)
   - Email address (required, valid format)
   - Bio (optional, max500 characters)
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

9. **Test Password Reset Flow** ✨ NEW

After registration:
1. Navigate to the login page
2. Click "Forgot Password?" link (when implemented)
3. Enter your registered email address
4. Check your email for password reset link
5. Click the reset link and enter new password
6. All existing sessions will be logged out
7. Log in with your new password

10. **Test Health Checks** ✨ NEW
 ```bash
 # Check API health
 curl https://localhost:5001/health
 
 # Check readiness (forKubernetes/Azure)
 curl https://localhost:5001/health/ready
 ```

### Development URLs

| Project | Purpose | HTTPS URL | HTTP URL |
|---------|---------|-----------|----------|
| API | Web API Backend | https://localhost:5001 | http://localhost:5000 |
| WT.Admin | Admin Panel | https://localhost:7127 | http://localhost:5041 |
| WT.Client | Client PWA | https://localhost:7000 | http://localhost:7001 |

### Health Check Endpoints ✨ NEW

**GET** `/health`

**Description:** General health status check

**Response:**

```json
{
  "status": "healthy",
  "timestamp": "2023-10-10T12:00:00Z"
}
```

---

**GET** `/health/ready`

**Description:** Readiness probe for deployment verification

**Response:**
```json
{
  "status": "ready",
  "timestamp": "2023-10-10T12:00:00Z"
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
- `429 Too Many Requests`: Rate limit exceeded ✨ NEW
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
- **Firebase service account JSON** ✨ NEW
- **Application Insights connection string** ✨ NEW
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
- ❌ **NEVER** Firebase service account credentials

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
- `Firebase:ServiceAccountJson` ✨ NEW
- `ApplicationInsights:ConnectionString` ✨ NEW (optional)

### Rate Limiting Configuration ✨ NEW

**Global Rate Limit:**
- 100 requests per minute per IP address
- Sliding window with queue support
- Custom rejection messages

**Auth Endpoint Rate Limit:**
- 10 requests per minute per IP address
- Applied to sensitive authentication endpoints
- Prevents brute force attacks

**Override Rate Limits:**
