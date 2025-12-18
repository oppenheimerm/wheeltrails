![WheelyTrails Logo](../logo.png)
# WheelyTrails.Com 🦽🌲

[![.NET Version](https://img.shields.io/badge/.NET-9.0-512BD4?logo=dotnet)](https://dotnet.microsoft.com/)
[![Blazor](https://img.shields.io/badge/Blazor-WebAssembly-512BD4?logo=blazor)](https://blazor.net/)
[![PWA](https://img.shields.io/badge/PWA-Enabled-5A0FC8?logo=pwa)](https://web.dev/explore/progressive-web-apps)
[![Material Design 3](https://img.shields.io/badge/Material-Design%203-757575?logo=material-design)](https://m3.material.io/)
[![Firebase](https://img.shields.io/badge/Firebase-Storage-FFCA28?logo=firebase)](https://firebase.google.com/)
[![Application Insights](https://img.shields.io/badge/Azure-Application%20Insights-0078D4?logo=microsoft-azure)](https://azure.microsoft.com/en-us/services/monitor/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

> Empowering wheelchair users to explore the world, one accessible trail at a time.

## 📖 About

**WheelyTrails** is a community-driven Progressive Web Application (PWA) built with ASP.NET Core Blazor WebAssembly and ASP.NET Core Web API. The platform enables users to discover, share, and rate wheelchair-accessible trails worldwide, fostering an inclusive outdoor experience for everyone.

This MVP/proof-of-concept demonstrates modern web technologies and Clean Architecture principles to create an accessible, offline-capable, and mobile-friendly application that serves the mobility-impaired community.

## 🔄 Latest updates (v1.3 — Dec 18, 2025)

- Visual & UX polish for the client app:
  - Top App Bar (NavBar) standardized to Material 3 recommended height: 64px (`min-h-[64px]`).
  - Subtle backdrop blur + translucent surface and increased elevation (`shadow-elevation-3`) for a layered, native-app feel.
  - Mobile drawer now stops above the TabBar (drawer bottom inset = `4rem` / `h-16`) and supports internal scrolling to avoid clipping footer controls (Login/Sign Up, Settings).
  - Bottom TabBar primary Add action converted to a true circular floating action: square container `w-14 h-14` + `rounded-full`, shadow, ring and hover/focus micro-interactions so the Add button appears perfectly round and accessible.
  - Small accessibility improvements: visible focus rings on interactive controls and ensured touch targets meet minimum sizes.
- Navigation consistency:
  - Settings/Profile routes unified in the UI (NavBar & TabBar) — ensure canonical route in codebase (see `NavBar.razor` / `TabBar.razor`).
- Theme and contrast:
  - Dark mode toggle persists via `localStorage`. Contrast selector remains in the UI but is non-destructive until `themeManager.setContrast` + contrast CSS files are implemented.
- Other: Application Insights integration and health check endpoints added for monitoring.

For full component and implementation notes see the design system: `Design-Notes.md` (updated to v1.3).

## 🎨 Design System

WheelyTrails follows **Material Design 3 (Material You)** principles with a comprehensive design system built on **Tailwind CSS 3.4+**.

### 📐 Design Documentation

For detailed design specifications, implementation guidelines, and component libraries, see:

**[📘 Design System Documentation](Design-Notes.md)**

The design documentation includes:
- **Color System** - Material 3 theme with seed color `#7CAC7E` (nature green)
  - Light, dark, and high-contrast modes
  - 30+ color tokens with WCAG AAA compliance
  - Surface elevation system with 5 levels
- **Typography** - Roboto font family with Material 3 type scale
- **Layout & Spacing** - Responsive grid system with iOS safe area support
- **Components** - Reusable Blazor components (NavBar, ThemeToggle, Buttons, Cards)
- **Dark Mode** - JavaScript-based theme manager with localStorage persistence
- **Accessibility** - WCAG 2.1/2.2 compliance, screen reader support, keyboard navigation
- **PWA Features** - Progressive Web App configuration with offline capabilities
- **Implementation Guide** - Step-by-step setup instructions for developers

### Key Design Features

- ✨ **Material Design 3 Integration** - Generated from Material Theme Builder  
- 🌗 **Dark Mode Support** - Automatic system preference detection + manual toggle  
- ♿ **Accessibility First** - WCAG 2.1/2.2 compliance considerations  
- 📱 **Mobile-First Design** - Fixed header/footer, bottom navigation, touch-optimized  
- 🎨 **Tailwind CSS** - Utility-first framework with Material 3 color tokens  
- 🔄 **Theme Persistence** - User preferences saved to localStorage  
- 🎯 **iOS Safe Areas** - Proper padding for notch and home indicator

---

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
  - ~50-100KB per image
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
- **Security Features**
  - Server-side upload validation (file size, type)
  - Firebase Security Rules for access control
  - Authenticated uploads only
  - Path traversal protection via filename sanitization

### 🔐 Authentication & Security ✨ ENHANCED
- **JWT Bearer Token Authentication** with ASP.NET Core Identity
  - 30-minute JWT token expiration
  - 7-day refresh token validity
  - Automatic token refresh on expiration
  - Secure token rotation to prevent reuse
- **Enhanced Token Management**
  - Automatic refresh token handling in `AccountService`
  - Transparent token refresh when JWT expires (401 Unauthorized)
  - Authorization header management with proper cleanup
- **Role-Based Authorization**
  - Admin Developer, Admin Editor, User Editor, User roles
- **User Authentication Features**
  - Secure registration, email verification, password reset
  - Session management with Blazored LocalStorage and custom auth provider

---

## 🛠️ Developer Tools & Getting Started

### Prerequisites
- [.NET 9 SDK](https://dotnet.microsoft.com/download/dotnet/9.0)
- [Visual Studio 2022](https://visualstudio.microsoft.com/) (17.8+) or VS Code
- [Node.js 18+](https://nodejs.org/) (for Tailwind CSS build)
- Modern browser

### Installation & Run
1. Clone and change directory:
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

**Step 2: EnableCloud Storage**
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

5. **Build Tailwind CSS**

````````bash
cd WT.Client
npm install
npm run build
````````

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
6. Click theverification link in the email to verify your account
7. Return to login page and sign in

9. **Test Password Reset Flow**✨ NEW

After registration:
1. Navigate to the login page
2. Click "Forgot Password?" link
3. Enter your registered email address
4. Check your email for password reset link
5. Click the reset link and enter new password
6. All existing sessions will be logged out
7. Log in with your new password

10. **Test Account Settings** ✨ NEW

After logging in:
1. Click on your profile avatar in the top-right corner
2. Select "Settings" from the dropdown menu
3. View your account information:
- Profile picture
- First name and profile username
- Email address (view only)
- Bio
- Member since date
- Country code
4. Make changes and click "Save"
5. If your JWT expires, the page will automatically refresh your token

11. **Test Health Checks** ✨ NEW
 ```bash
 # Check APIhealth
 curl https://localhost:5001/health
 
 # Check readiness (for Kubernetes/Azure)
 curl https://localhost:5001/health/ready
 ```

### Development URLs

| Project | Purpose | HTTPS URL | HTTPURL |
|---------|---------|-----------|----------|
| API | Web API Backend | https://localhost:5001 | http://localhost:5000 |
| WT.Admin | Admin Panel | https://localhost:7127 | http://localhost:5041 |
| WT.Client | Client PWA | https://localhost:7000 | http://localhost:7001 |

### Health Check Endpoints ✨ NEW

**GET** `/health`

**Description:** General health statuscheck

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
- **Application Insights connection string** ✨ NEW (optional)

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

### Privacy Protection ✨ NEW

⚠️ **CRITICAL: Never Expose User Email Addresses Publicly**

**Security Rule:** The `ApplicationUser.Email` property should **NEVER** be exposed in public API responses or displayed in user-facing interfaces.

**Why?**
- **Privacy:** Email addresses are personal identifiable information (PII)
- **Security:** Exposing emails enables targeted phishing attacks
- **Spam:** Email harvesting bots can scrape public email addresses
- **GDPR Compliance:** Email addresses are protected under privacy regulations
- **Professional Standards:** User emails should only be visible to the user themselves and administrators

**What to Use Instead:**
- ✅ **ProfileUsername** (`@john_doe`) - Public display name for profiles, comments, and likes
- ✅ **FirstName** - Safe for public display in user interfaces
- ✅ **UserId (Guid)** - Internal identifier, safe to expose in API responses

**When Email CAN Be Used:**
- ✅ Authentication (login process)
- ✅ Password reset emails
- ✅ Admin user management interfaces
- ✅ User's own profile settings page (viewing their own email)
- ✅ Internal logging and audit trails
- ✅ Email verification workflows

**When Email MUST NOT Be Used:**
- ❌ Public profile pages (`/user/{profileUsername}`)
- ❌ Trail likes/comments display
- ❌ Search results
- ❌ API responses for trail creators
- ❌ Social features (followers, likes, ratings)
- ❌ Any public-facing UI component
- ❌ Trail owner display (`Created by: {email}`)
- ❌ Community leaderboards or user listings

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

## 🧪 Testing

### Manual Testing Checklist

#### Registration Flow ✨ ENHANCED
- [ ] Navigate to `/account/identity/register`
- [ ] Fill out form with valid data
- [ ] Test ProfileUsername validation:
  - [ ] Enter existing username → See "already taken" error
  - [ ] Enter username with profanity → See "inappropriate content" error
  - [ ] Enter valid unique username → See green "available!" checkmark
- [ ] Submit form
- [ ] Verify email received with verification link
- [ ] Click verification link
- [ ] Confirm successful email verification

#### Login Flow
- [ ] Navigate to `/account/identity/login`
- [ ] Enter registered email and password
- [ ] Verify successful login with JWT token
- [ ] Check LocalStorage for authentication data
- [ ] Verify user menu displays ProfileUsername
- [ ] Test logout functionality

#### Password Reset Flow
- [ ] Click "Forgot Password?" link
- [ ] Enter registered email
- [ ] Verify reset email received
- [ ] Click reset link
- [ ] Enter new password
- [ ] Confirm password reset successful
- [ ] Verify all sessions logged out
- [ ] Login with new password

#### Account Settings ✨ NEW
- [ ] Navigate to `/account/identity/settings` while logged in
- [ ] Verify account information displays correctly:
  - [ ] Profile picture (or fallback icon)
  - [ ] First name and profile username
  - [ ] Email address (display only)
  - [ ] Bio content
  - [ ] Member since date
  - [ ] Country code
- [ ] Test JWT expiration handling:
  - [ ] Wait 30+ minutes (or manually invalidate JWT)
  - [ ] Reload settings page
  - [ ] Verify automatic token refresh occurs
  - [ ] Confirm data loads successfully after refresh
- [ ] Test error handling:
  - [ ] Logout and try to access `/account/identity/settings`
  - [ ] Verify redirect to login page
  - [ ] Manually delete local storage data
  - [ ] Verify "not authenticated" error message

#### Trail Likes ✨ NEW
- [ ] Navigate to a trail detail page
- [ ] Click "Like" button
- [ ] Verify like count increments
- [ ] Verify visual feedback (heart icon filled)
- [ ] Click "Unlike" button
- [ ] Verify like count decrements
- [ ] Attempt to like the same trail twice (should fail with error)

#### Health Checks ✨ NEW
- [ ] Visit `/health` endpoint
- [ ] Verify "Healthy" status returned
- [ ] Visit `/health/ready` endpoint
- [ ] Verify readiness probe responds

## 🐛 Known Issues

### Current Limitations
- ProfileUsername is permanent (cannot be changed after registration)
- Rate limiting is IP-based (may affect users behind shared IPs)
- Email verification required before login (no skip option)

## 🗺️ Roadmap

### Planned Features
- [ ] ProfileUsername change requests (admin approval required)
- [ ] User-to-user messaging system
- [ ] Trail difficulty voting/consensus
- [ ] Offline mode for trail discovery
- [ ] Mobile app (React Native or .NET MAUI)
- [ ] Advanced search with natural language processing
- [ ] Trail recommendations based on user preferences
- [ ] Social features (followers, activity feed)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Material Design 3** - Google's design system for modern UIs
- **LDNOOBW** - List of Dirty, Naughty, Obscene, and Otherwise Bad Words (profanity filter)
- **Firebase** - Cloud storage for images
- **Azure** - Application Insights for monitoring
- **Tailwind CSS** - Utility-first CSS framework
- **Blazor Community** - Blazor WebAssembly and Server components

## 📞 Contact

- **Project Repository**: [https://github.com/oppenheimerm/wheeltrails](https://github.com/oppenheimerm/wheeltrails)
- **Issues**: [https://github.com/oppenheimerm/wheeltrails/issues](https://github.com/oppenheimerm/wheeltrails/issues)

---

**Built with ❤️ for the wheelchair community by the WheelyTrails team**