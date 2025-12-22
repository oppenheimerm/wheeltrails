![WheelyTrails Logo](../logo.png)
# WheelyTrails.Com 🦽🌲

[![.NET Version](https://img.shields.io/badge/.NET-9.0-512BD4?logo=dotnet)](https://dotnet.microsoft.com/)
[![Blazor](https://img.shields.io/badge/Blazor-WebAssembly-512BD4?logo=blazor)](https://blazor.net/)
[![PWA](https://img.shields.io/badge/PWA-Enabled-5A0FC8?logo=pwa)](https://web.dev/explore/progressive-web-apps)
[![Material Design3](https://img.shields.io/badge/Material-Design%203-757575?logo=material-design)](https://m3.material.io/)
[![Firebase](https://img.shields.io/badge/Firebase-Storage-FFCA28?logo=firebase)](https://firebase.google.com/)
[![Application Insights](https://img.shields.io/badge/Azure-Application%20Insights-0078D4?logo=microsoft-azure)](https://azure.microsoft.com/en-us/services/monitor/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

> Empowering wheelchair users to explore the world, one accessible trail at a time.

## 📖 About

**WheelyTrails** is a community-driven Progressive Web Application (PWA) built with ASP.NET Core Blazor WebAssembly and ASP.NET Core Web API. The platform enables users to discover, share, and rate wheelchair-accessible trails worldwide, fostering an inclusive outdoor experience for everyone.

This MVP/proof-of-concept demonstrates modern web technologies and Clean Architecture principles to create an accessible, offline-capable, and mobile-friendly application that serves the mobility-impaired community.

## 🔄 Latest updates (v1.3 — Dec18,2025)

- Visual & UX polish for the client app:
 - Top App Bar (NavBar) standardized to Material3 recommended height:64px (`min-h-[64px]`).
 - Subtle backdrop blur + translucent surface and increased elevation (`shadow-elevation-3`) for a layered, native-app feel.
 - Mobile drawer now stops above the TabBar (drawer bottom inset = `4rem` / `h-16`) and supports internal scrolling to avoid clipping footer controls (Login/Sign Up, Settings).
 - Bottom TabBar primary Add action converted to a true circular floating action: square container `w-14 h-14` + `rounded-full`, shadow, ring and hover/focus micro-interactions so the Add button appears perfectly round and accessible.
 - Small accessibility improvements: visible focus rings on interactive controls and ensured touch targets meet minimum sizes.
 - NavBar behavior improvements:
 - Active link detection improved by matching the current absolute path so navigation highlights are consistent across routes.
 - Mobile menu uses an explicit open/close state and a `MobileMenuClass` helper to avoid flicker and ensure the overlay/backdrop behaves correctly.
 - User menu dropdown is keyboard- and focus-friendly and stops event propagation to avoid accidental closes while interacting with menu content.
 - Logout flow now clears client-side authentication data from `localStorage`, updates the custom authentication state provider, closes menus, and uses `Navigation.NavigateTo("/", forceLoad: true)` to ensure a clean client state after sign-out.
 - The NavBar subscribes to `AuthenticationStateProvider.AuthenticationStateChanged` to keep UI in sync with authentication changes and properly unsubscribes on dispose to avoid memory leaks.
- Navigation consistency:
 - Settings/Profile routes unified in the UI (NavBar & TabBar) — ensure canonical route in codebase (see `NavBar.razor` / `TabBar.razor`).
- Theme and contrast:
 - Dark mode toggle persists via `localStorage`. Contrast selector remains in the UI but is non-destructive until `themeManager.setContrast` + contrast CSS files are implemented.
- Other: Application Insights integration and health check endpoints added for monitoring.

For full component and implementation notes see the design system: `Design-Notes.md` (updated to v1.3).

## 🎨 Design System

WheelyTrails follows **Material Design3 (Material You)** principles with a comprehensive design system built on **Tailwind CSS3.4+**.

### 📐 Design Documentation

For detailed design specifications, implementation guidelines, and component libraries, see:

**[📘 Design System Documentation](Design-Notes.md)**

The design documentation includes:
- **Color System** - Material3 theme with seed color `#7CAC7E` (nature green)
 - Light, dark, and high-contrast modes
 -30+ color tokens with WCAG AAA compliance
 - Surface elevation system with5 levels
- **Typography** - Roboto font family with Material3 type scale
- **Layout & Spacing** - Responsive grid system with iOS safe area support
- **Components** - Reusable Blazor components (NavBar, ThemeToggle, Buttons, Cards)
- **Dark Mode** - JavaScript-based theme manager with localStorage persistence
- **Accessibility** - WCAG2.1/2.2 compliance considerations
- **PWA Features** - Progressive Web App configuration with offline capabilities
- **Implementation Guide** - Step-by-step setup instructions for developers

### Key Design Features

- ✨ **Material Design3 Integration** - Generated from Material Theme Builder 
- 🌗 **Dark Mode Support** - Automatic system preference detection + manual toggle 
- ♿ **Accessibility First** - WCAG2.1/2.2 compliance considerations 
- 📱 **Mobile-First Design** - Fixed header/footer, bottom navigation, touch-optimized 
- 🎨 **Tailwind CSS** - Utility-first framework with Material3 color tokens 
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
- Comment on trails with300-character limit
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
 - FREE tier:5GB storage,1GB/day bandwidth
 - Global CDN for fast photo delivery
 - Automatic public URL generation
- **Profile Picture Upload** max size(3 * 1024 * 1024 - 3MB See: WT.Application.Extension.Constants) ✨ NEW
 - User profile photos with automatic optimization
 - Resized to400×400px,80% JPEG quality
 - ~50-100KB per image
 - Stored in user-specific folders: `profile-pictures/{userId}/`
- **Trail Photo Upload**
 - Community trail photos with visual previews
 - Multiple file upload support (up to5 photos)
 - Resized to1200×1200px,85% JPEG quality
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
 -30-minute JWT token expiration
 -7-day refresh token validity
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

### Identity: Unicode username & email normalization (new)
- We now support Unicode in usernames and improved email normalization for lookups.
- What changed in the codebase:
 - `WT.Infrastructure.DependencyInjection.ServiceContainer`:
 - Registers a custom lookup normalizer before Identity is configured:
 - `services.AddSingleton<ILookupNormalizer, UnicodeLookupNormalizer>();`
 - Allows non-ASCII usernames by setting:
 - `options.User.AllowedUserNameCharacters = null;`
 - `WT.Infrastructure.Services.UnicodeLookupNormalizer`:
 - Implements `ILookupNormalizer` with:
 - `NormalizeName(string? name)` — applies Unicode compatibility normalization (FormKC) and invariant upper-casing so usernames with accents or emoji are normalized consistently.
 - `NormalizeEmail(string? email)` — normalizes local-part, converts internationalized domain names to ASCII (punycode via `IdnMapping`) and applies invariant upper-casing for stable email lookups.
- Why this matters:
 - Identity lookup and comparison depend on normalized values (`NormalizedUserName`, `NormalizedEmail`). The custom normalizer ensures usernames and emails containing non-ASCII characters are normalized reliably, preventing unexpected lookup failures for users with accented names or emoji.
- Caveats & recommendations:
 - DataAnnotations `[EmailAddress]` and some third-party validators may still reject Unicode local-parts. For best UX:
 - Convert the domain to punycode (handled by `NormalizeEmail`) before storing/validating where necessary.
 - Consider a custom email validator that accepts Unicode local-parts or pre-processes input for validation.
 - Existing users: run a small migration or admin script to recompute `NormalizedUserName` and `NormalizedEmail` using the new normalizer so previously created accounts continue to match during login/lookups.
 - Some email providers don't accept non-ASCII local parts; consider this when allowing Unicode in the local part.
-`ILookupNormalizer` Dependency Injection Notes
	- Register the `ILookupNormalizer` before Identity so Identity consumes the custom normalizer for `NormalizedUserName`/`NormalizedEmail`.
For development and deployment, see the "Next steps" recommendations in the Technical Notes section below.

<!-- Developer note: UnicodeLookupNormalizer added -->

> Developer note: The project includes a Unicode-aware Identity lookup normalizer implemented in `WT.Infrastructure\Services\UnicodeLookupNormalizer.cs`. This class implements `ILookupNormalizer` and provides `NormalizeName` and `NormalizeEmail` (FormKC normalization + invariant upper-casing, and domain punycode conversion for emails). Register it before Identity is configured via `services.AddSingleton<ILookupNormalizer, UnicodeLookupNormalizer>();` so Identity uses the custom normalizer for `NormalizedUserName`/`NormalizedEmail` values.

--- 

## 🛠️ Developer Tools & Getting Started

### Prerequisites
- [.NET9 SDK](https://dotnet.microsoft.com/download/dotnet/9.0)
- [Visual Studio2022](https://visualstudio.microsoft.com/) (17.8+) or VS Code
- [Node.js18+](https://nodejs.org/) (for Tailwind CSS build)
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

**Step1: Create a Firebase Project**
1. Go to [Firebase Console](https://console.firebase.google.com/)
2. Click "Add project" and follow the wizard
3. Enable Google Analytics (optional)

**Step2: EnableCloud Storage**
1. In the Firebase console, navigate to **Build** → **Storage**
2. Click "Get Started"
3. Choose production mode and select a storage location
4. Copy your storage bucket URL (format: `your-project.appspot.com`)

**Step3: Generate Service Account Key**
1. Go to **Project Settings** (gear icon) → **Service Accounts**
2. Click "Generate New Private Key"
3. Save the JSON file securely (NEVER commit to source control!)
4. Copy the entire JSON content

**Step4: Configure User Secrets**
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
- ✅ **Free tier**:500 emails/month,5 inboxes
- ✅ **Safe testing**: Emails never reach real inboxes
- ✅ **Email preview**: View how emails look in different clients (Gmail, Outlook, etc.)
- ✅ **Spam testing**: Check if your emails might be flagged as spam
- ✅ **HTML validation**: Verify how email templates render
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
- First name (required,3-30 characters)
- Email address (required, valid format)
- Bio (optional, max500 characters)
- Password (required, min7 characters)
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
- `429 Too Many Requests`: Rate limit exceeded ✂️ NEW
- `500 Internal Server Error`: Server-side error, unexpected condition

Ensure the client application handles these status codes appropriately for a seamless user experience.

For detailed API documentation, visit **[Scalar API Docs](https://localhost:5001/scalar/v1)** after running the application.

## 🔒 Security & Configuration

### Configuration Strategy by Project Type

### Server-Side Projects (API, WT.Infrastructure)
✅ **Use User Secrets** for sensitive configuration:
- Database connection strings
- JWT signing secrets
- SMTP credentials and passwords
- API keys and credentials
- Admin user passwords
- **Firebase service account JSON** ✨ NEW
- **Application Insights connection string** ✨ NEW (optional)

### Server-Side - API

### Caching: IMemoryCache strategy for per-user navbar data

The API now uses an in-memory cache for lightweight, per-user navbar data (display name, profile picture URL, profile username, member since). Follow this safe pattern when adding or changing caching behavior:

- What to cache
 - Small, non-sensitive UI data used to render the NavBar (e.g., `DisplayName`, `ProfilePicture`, `ProfileUsername`, `MemberSince`).
 - Do NOT cache emails, tokens, passwords, or any PII that shouldn't be shared.

- Cache key
 - Use a per-user key that includes the user id, for example: `navbarinfo:{userId}`.
 - This avoids cross-user leakage and makes invalidation simple.

- TTL and eviction
 - Use a short TTL (5–15 minutes) to balance freshness vs. performance. The project uses10 minutes by default.
 - Example options: `AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(10)` and `Priority = CacheItemPriority.Normal`.
 - Optionally add `Size` to cache entries and configure `MemoryCacheOptions.SizeLimit` in `Program.cs` for memory pressure control.- What to cache
 - Small, non-sensitive UI data used to render the NavBar (e.g., `DisplayName`, `ProfilePicture`, `ProfileUsername`, `MemberSince`).
 - Do NOT cache emails, tokens, passwords, or any PII that shouldn't be shared.

- Cache key
 - Use a per-user key that includes the user id, for example: `navbarinfo:{userId}`.
 - This avoids cross-user leakage and makes invalidation simple.

- TTL and eviction
 - Use a short TTL (5–15 minutes) to balance freshness vs. performance. The project uses10 minutes by default.
 - Example options: `AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(10)` and `Priority = CacheItemPriority.Normal`.
 - Optionally add `Size` to cache entries and configure `MemoryCacheOptions.SizeLimit` in `Program.cs` for memory pressure control.

- Invalidation
 - Invalidate the cached entry immediately when the user updates profile data (e.g., `UploadProfilePicture()` removes `navbarinfo:{userId}` after a successful DB update).
 - Also invalidate on other profile-changing operations (username set, profile edits, admin updates).

- Where to implement
 - Controller-level cache usage is acceptable for small, authenticated-only data: inject `IMemoryCache` into the controller and use `TryGetValue`/`Set`/`Remove`.
 - For better separation, consider caching in the repository or service layer so controllers remain thin and cache lifecycle is encapsulated.

- Multi-node / production
 - `IMemoryCache` is single-node only. For multi-instance deployments use `IDistributedCache` (Redis) and serialize DTOs.
 - Keep cache keys consistent across instances for distributed caches.

- Registration & configuration
 - Ensure `services.AddMemoryCache()` is called in `Program.cs` for the API project.
 - Configure size limits or eviction policies if needed:
 - `builder.Services.AddMemoryCache(options => { options.SizeLimit =1024 *1024; });`

- Logging and observability
 - Log cache hits, misses, and invalidations at debug/trace level for troubleshooting.
 - Avoid logging entire cached DTOs containing PII.

- Example flow (current implementation)
1. `GET api/account/identity/navbar-info` checks `IMemoryCache` for `navbarinfo:{userId}`.
2. If cache hit → return cached `APIResponseViewAccountSettings`.
3. If cache miss → call repository `GetNavbarUserInfoAsync(userId)`, cache result for10 minutes, return result.
4. When user updates profile picture via `UploadProfilePicture`, controller calls `_cache.Remove($"navbarinfo:{userId}")` after successfully persisting the new URL to ensure the next navbar request is fresh.

This in-memory caching strategy provides a low-risk performance win for frequently-read user UI data while keeping data fresh via explicit invalidation on updates. For multi-instance deployments or higher-scale requirements, replace the in-memory cache with `IDistributedCache` (Redis) and keep the same key and invalidation semantics.

#### Profile Picture Upload Flow ✨ NEW

The API's `AccountController.UploadProfilePicture` implements a robust, production-safe flow for handling profile photo updates. Key behavior and guarantees:

- Validate → Upload → Persist → Cleanup
 - Validate the incoming file using server-side checks (size, MIME, filename) before any storage operation.
 - Stream the file to the storage provider (no full in-memory buffering). The storage service contract expects a `Stream` and should perform image optimization server-side (resize/compress).
 - After a successful upload, update the user's `ProfilePicture` URL in the database. The DB update is the authoritative step that switches the user's profile to the new image.
 - Only after the DB update succeeds, perform a best-effort deletion of the previous profile picture. This avoids data loss if upload fails.
 - If the DB update fails after upload, the controller attempts a compensating delete of the newly-uploaded file to avoid orphaned storage objects.

- Cancellation & resource safety
 - The controller observes `HttpContext.RequestAborted` and returns a `499`-style response when the client disconnects during upload.
 - The upload stream is used inside a `using` scope to ensure disposal and avoid leaked resources.

- Error handling & logging
 - All storage and DB operations are wrapped with try/catch. Failures are logged (via `LogException`) and translated to consistent `APIResponseUploadPhoto` responses.
 - The controller intentionally does not delete the old photo until the new photo's URL is persisted; failures during cleanup are logged but do not block a successful response.

- Recommendations for implementers
 - Ensure `IFileStorageService.UploadProfilePictureAsync(Stream, string, Guid)` streams the data and does not buffer it entirely in memory.
 - Use configuration/constants for max file size and allowed MIME types (see `Constants` and `ApplicationSettings:MaxProfileImageSize`).
 - Consider adding content-signature (magic-bytes) checks to protect against spoofed MIME types.
 - Generate storage object names server-side (e.g., `profile-pictures/{userId}/{guid}.jpg`) to avoid collisions and path-traversal risks.

- Response contract
 - Successful responses return `APIResponseUploadPhoto` with `Success = true` and `PhotoUrl` pointing to the newly-persisted public URL.
 - Validation or persistence failures return `APIResponseUploadPhoto` with `Success = false` and an explanatory message.
 - `499` responses are used to indicate client disconnects or cancellations during the upload.

This flow is implemented in `API.Controllers.AccountController.UploadProfilePicture` and mirrors the best-practices documented in the code comments: validate first, upload (streamed), persist, then clean up old resources in a best-effort way.



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

### Solution Configuration ✨ NEW

For Solution properties that rarely change `Constants.cs`
(**WT.Application.Extensions**) will act as a single source 
of truth and for the following conditions:

- The value is not sensitive
- The value rarely changes
- The value is needed in attributes (which require compile‑time constants)
- You want a single source of truth
- You want to avoid cluttering `Program.cs`


### Rate Limiting Configuration ✨ NEW

**Global Rate Limit:**
-100 requests per minute per IP address
- Sliding window with queue support
- Custom rejection messages

**Auth Endpoint Rate Limit:**
-10 requests per minute per IP address
- Applied to sensitive authentication endpoints
- Prevents brute force attacks

## 🧪 Testing

### Manual Testing Checklist

<!-- Cancellation guidance for profile uploads -->

### Cancellation: Cooperative client + server upload handling

To improve responsiveness and avoid wasted bandwidth and server work, the upload flow implements cooperative cancellation across the Blazor WebAssembly client and the API back end.

Client (Blazor WASM)
- Create a `CancellationTokenSource` when starting an upload and pass `cts.Token` into the client service method that performs the HTTP `POST` of the multipart content.
- Cancel and dispose the `CancellationTokenSource` when the user cancels the operation (Cancel button), when a new upload begins, or when the component is disposed.
- Example pattern (component):
 - Field: `private CancellationTokenSource? _uploadCts;`
 - Before upload: cancel+dispose previous `CTS`, then ` _uploadCts = new CancellationTokenSource();`
 - Call service: `await AccountService.UpdateProfilePictureUrlAsync(dto, _uploadCts.Token);`
 - On user cancel / RemovePhoto / Dispose: `_uploadCts?.Cancel(); _uploadCts?.Dispose(); _uploadCts = null;`
- The client `AccountService.UpdateProfilePictureUrlAsync` accepts an optional `CancellationToken` and forwards it into `HttpClient.PostAsync(..., content, cancellationToken)` so the browser/HttpClient stops sending the request when cancelled.

Server (API)
- Controller actions accept an explicit `CancellationToken` parameter and prefer it when provided. The action also observes `HttpContext.RequestAborted` as a fallback for network disconnects or proxy-level disconnects.
- Example pattern (controller):
 - Action signature: `public async Task<IActionResult> UploadProfilePicture([FromForm] UpdateProfilePhotoDTO? model, CancellationToken cancellationToken)`
 - Choose the token to observe: `var ct = cancellationToken.CanBeCanceled ? cancellationToken : HttpContext.RequestAborted;`
 - Throw/handle `OperationCanceledException` (or check `ct.IsCancellationRequested`) and return a `499`-style response to indicate client cancel.
- For long-running server-side storage operations, consider adding `CancellationToken` parameters to `IFileStorageService` methods so the upload/optimization can be aborted as soon as possible.

Why this matters
- Early client cancellation avoids uploading large files when the user navigates away or explicitly cancels.
- The server's `RequestAborted` helps detect network disconnects, but explicit client tokens make client-initiated cancellation deterministic.
- Proper disposal of `CancellationTokenSource` prevents resource leaks.

Recommendations
- Add a small Cancel button in the upload UI while `isUploading` and call `_uploadCts?.Cancel()` so users can stop upload explicitly.
- Propagate the cancellation token through storage and repository layers (`IFileStorageService.UploadProfilePictureAsync(Stream, string, Guid, CancellationToken)`) for full end-to-end cancellation.
- Continue to log cancellations for telemetry but avoid treating them as errors.

This cooperative cancellation pattern was added to `WT.Application.Services.AccountService.UpdateProfilePictureUrlAsync(...)` (client) and `API.Controllers.AccountController.UploadProfilePicture(...)` (server) to make uploads more resilient and user-friendly.

<!-- End cancellation guidance -->

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
- [ ] Click reset link and enter new password
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
 - [ ] Wait30+ minutes (or manually invalidate JWT)
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

- **Material Design3** - Google's design system for modern UIs
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

