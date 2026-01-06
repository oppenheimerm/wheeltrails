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

## 🔄 Latest updates (v1.5 — Jan01,2026)

Summary of notable changes in this branch:

### File Upload Cancellation Support ✨ NEW
- **CancellationToken Propagation**
 - File storage service (`IFileStorageService`) methods now accept optional `CancellationToken` parameters
 - Controllers propagate `HttpContext.RequestAborted` to all upload operations
 - Enables graceful cancellation of image processing and cloud storage uploads
- **Benefits**
 - Prevents wasted server resources when clients disconnect during uploads
 - Reduces CPU, memory, and bandwidth usage for abandoned requests
 - Proper cleanup of streams and temporary buffers
- **Implementation Details**
 - `UploadProfilePictureAsync` and `UploadTrailPhotoAsync` in `FirebaseStorageService` updated
 - Cancellation tokens propagated to ImageSharp image processing operations
 - Google Cloud Storage upload operations honor cancellation tokens
 - Controllers handle `OperationCanceledException` and return HTTP499 responses
- **Code Documentation**
 - Added JSDoc-style documentation to `uploader.js` (client-side XHR uploader)
 - Documented DotNet interop callbacks and abort semantics
 - Added ARIA attributes to progress bars in upload UI components

### Layout & Navigation
- **New Instagram-Style Sidebar Navigation** (`SideNav.razor`)
 - Replaced top `NavBar` with a fixed left sidebar for desktop/tablet (hidden on mobile)
 - **Responsive widths**:72px (icon-only) at `md`,220px (full labels) at `xl`,244px at `2xl`
 - **Material Design3 tooltips** for icon-only mode using CSS pseudo-elements
 - Tooltips appear on hover/focus when in icon-only mode (below `xl` breakpoint)
 - Uses MD3 inverse surface colors (`--md-sys-color-inverse-surface`, `--md-sys-color-inverse-on-surface`)
 - Smooth fade transitions (150ms)
 - Logo, navigation links, user menu, and theme toggle all support tooltips
- **Mobile Header Simplified**
 - Minimal fixed header with logo and theme toggle only
 - No drawer/hamburger menu (navigation moved to bottom TabBar on mobile)
- **Content Layout Fixed**
 - Main content area now properly accounts for sidebar width at all breakpoints
 - Desktop offline banner correctly positioned to not be clipped by sidebar
 - Tailwind class spacing issues resolved (`xl:left-[220px]2xl:left-[244px]`)

### SVG Logo Support
- Added SVG logo (`img/logo-svg.svg`) for better scaling and performance
- Splash screen updated to use preloaded SVG (`<link rel="preload">`)
- Logo displayed in light/dark variants throughout the app

### Google Maps API Key Management
- Created repeatable PowerShell helper script (`WT.Client/scripts/dev-inject.ps1`)
- Generates `index.html` from `index.html.template` with API key injection
- Simple Windows wrapper (`WT.Client/scripts/inject-key.cmd`) for easy execution
- Both files committed to repo; generated `index.html` is git-ignored

### Bug Fixes
- Fixed Razor parsing errors in FAB inline style attributes
- Corrected z-index and positioning for desktop offline banner
- Resolved sidebar width calculation issues in main content area

### Developer Experience
- Simplified API key injection workflow for local development
- Improved Material Design3 tooltip implementation with proper accessibility
- Better responsive layout consistency across all screen sizes



Summary of notable changes in the previous branch:

- Floating Action Button (FAB)
 - Moved FAB into `MainLayout.razor` so it is global and accessible from any page via `IFabService`.
 - Added keyboard handling (Escape closes FAB via `fabInterop.js`), focus management (focus first action when opened, return focus when closed), ARIA attributes (`aria-haspopup`, `aria-expanded`, `aria-controls`) and rotation animation for the primary icon when expanded.
 - Implemented responsive desktop/mobile variants: desktop FAB is vertically centered at the right edge, mobile FAB is bottom-right above the TabBar to avoid header overlap.
 - Tooltip improvements: `.fab-tooltip` padding increased, tooltip animation preserved.

- Map & Recorder
 - `trailRecorder.js` additions: `getCurrentPosition`, `startWatchPosition`, `stopWatchPosition` for controlled geolocation handling and backwards-compatible `startRecording`/`stopRecording` wrappers.
 - Client (WT.Client/Pages/Trails/TrailCreate.razor): use `getCurrentPosition` on first render to center the map (fallback provided). Recording now uses high-accuracy watch only after user starts recording.
 - Recording supports pause/resume with accumulated elapsed time (`TimeStart`, `TimeEnd`, `TimeAccumulated` + `ElapsedTimeDisplay`). POI markers and polyline updates use `addPoiMarker` / `updateTrailPath` JS interop.

- Accessibility & UX
 - Focus-visible rings and improved keyboard flows for FAB and user menus.
 - ARIA attributes and labels added where appropriate.

- CSS & Styling
 - `WT.Client/wwwroot/css/input.css` updated with responsive FAB positioning, header button hover/focus contrast fixes, `.fab-tooltip` padding, and removal of `display:block` on `#fab-wrapper` so Tailwind responsive utilities work as intended.

- JS Interop
 - `WT.Client/wwwroot/js/fabInterop.js` — Escape key bridge for closing FAB.
 - `WT.Client/wwwroot/js/trailRecorder.js` — documented and extended helpers for map and geolocation.

- Notes / Pending work
 - SendGrid / mail service wiring not yet implemented — will be added under the API project and configured via user secrets / Key Vault before production.
 - Google social login endpoint (server-side token validation and local JWT issuance) suggested next step.
 - Minimal PWA manifest/service-worker baseline recommended to enable phone testing and installable behavior; not yet added in this branch.

Recorder UX & FAB (what to test)
- Global Floating Action Button (FAB) moved into `MainLayout.razor` and is now controlled via `IFabService` to keep layout-level presentation decoupled from page logic.
- Pages opt-in to the FAB by subscribing to `IFabService.OnFabAction` and calling `FabService.Show()` when the page becomes active, and `FabService.Hide()` when leaving.
- New recorder flow on `/trails/new` (TrailCreate):
- Before starting a recording the user sees a confirmation modal: Title "Recording uses GPS" with a short warning about battery and an option to "Change defaults in Settings" or "Continue".
- After confirming, the app starts a high-accuracy geolocation watch and shows a persistent banner/chip: "Recording — GPS in use. Tap to stop. (May affect battery)" with a Stop control.
- The layout FAB actions map to `AddPoi`, `ToggleRecording`, and `SubmitTrail` (see `WT.Client.Services.FabService`).

IFabService Quick Reference
- API surface (client):
- `event Action<FabAction> OnFabAction` — subscribe to receive actions raised from the layout-level FAB.
- `event Action<bool> OnVisibilityChanged` — layout listens to render/hide the FAB.
- `void Raise(FabAction action)` — layout uses this to raise actions to pages.
- `void Show()` / `void Hide()` / `void ToggleVisibility()` — pages call Show/Hide to opt-in to FAB visibility.

Settings & Persistence (recorder)
- New per-user preferences exposed in the client DTO: `GpsAccuracy` (`GpsAccuracyLevel`) and `ShowRecordingWarning` (bool).
- `Account Settings` page (`/account/identity/settings`) now includes a "Recorder Preferences" section with a GPS accuracy dropdown and a "Show recording warning" toggle. Changes are persisted to browser localStorage under `RecordingPreferences` for quick testing until server persistence is wired.
- Recommended server work (before persisting preferences in DB):
- Add `ShowRecordingWarning` property to `ApplicationUser` (default: true) and include the field in account settings DTOs.
- Create EF migration: `dotnet ef migrations add AddRecordingPrefsToApplicationUser -p WT.Infrastructure -s API` and `dotnet ef database update -p WT.Infrastructure -s API`.

Recorder interop (JS helpers)
- `getCurrentPosition()` — one-shot position used to center the map on first render.
- `startWatchPosition(dotNetRef, { enableHighAccuracy, maximumAge, timeout })` — starts a geolocation watch and forwards updates to .NET.
- `stopWatchPosition()` — stops the geolocation watch.

What to test (quick checklist)
- Navigate to `/trails/new` — the FAB should appear (page opts-in).
- Click "Start recording" → confirmation modal appears; use "Change defaults in Settings" to open settings or "Continue" to start.
- When recording starts, verify the persistent banner appears and that `Add POI` and FAB actions behave as expected.
- Click "Stop" on the banner or use the FAB action to stop; verify the trail DTO is prepared.

***

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
- **Profile Picture Upload** max size(3 *1024 *1024 -3MB See: WT.Application.Extension.Constants) ✨ NEW
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
- **Cancellation & Request Abort Handling** ✨ NEW
 - Upload methods now accept a `CancellationToken` parameter
 - Controllers propagate `HttpContext.RequestAborted` to enable graceful cancellation
 - Image processing (ImageSharp) and cloud storage uploads can be aborted when client disconnects
 - Prevents wasted server resources on cancelled requests
 - Controllers handle `OperationCanceledException` and return HTTP499 (Client Closed Request)
 - Example server-side implementation:
 ```csharp
 var ct = HttpContext.RequestAborted;
 using var stream = file.OpenReadStream();
 try
 {
 var url = await _fileStorageService.UploadTrailPhotoAsync(stream, fileName, trailId, ct);
 }
 catch (OperationCanceledException) when (ct.IsCancellationRequested)
 {
 return StatusCode(499, new { success = false, message = "Upload canceled" });
 }
 ```
- **Security Features**
 - Server-side upload validation (file size, type)
 - Firebase Security Rules for access control
 - Authenticated uploads only
 - Path traversal protection via filename sanitization
 - Magic bytes validation to prevent MIME type spoofing

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

> Developer note: The project includes a Unicode-aware Identity lookup normalizer implemented in `WT.Infrastructure.Services.UnicodeLookupNormalizer.cs`. This class implements `ILookupNormalizer` and provides `NormalizeName` and `NormalizeEmail` (FormKC normalization + invariant upper-casing, and domain punycode conversion for emails). Register it before Identity is configured via `services.AddSingleton<ILookupNormalizer, UnicodeLookupNormalizer>();` so Identity uses the custom normalizer for `NormalizedUserName`/`NormalizedEmail` values.

--- 
## Project Solution Structure / Notes

### API (WT.API)

#### Caching: IMemoryCache strategy for per-user navbar data

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
 - Optionally add `Size` to cache entries and configure `MemoryCacheOptions.SizeLimit` in `Program.cs` for memory pressure control.
- What to cache
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

- NavBar render fix: 
 - `NavBar.razor` now awaits `ApplyAuthState(...)` in `OnInitializedAsync` and the method calls:
	- `await InvokeAsync(StateHasChanged);` This ensures async-loaded ***userProfilePicture*** is applied to the UI before the first meaningful render so the avatar appears immediately.

- Example flow (current implementation)
1. `GET api/account/identity/navbar-info` checks `IMemoryCache` for `navbarinfo:{userId}`.
2. If cache hit → return cached `APIResponseViewAccountSettings`.
3. If cache miss → call repository `GetNavbarUserInfoAsync(userId)`, cache result for10 minutes, return result.
4. When user updates profile picture via `UploadProfilePicture`, controller calls `_cache.Remove($"navbarinfo:{userId}")` after successfully persisting the new URL to ensure the next navbar request is fresh.

This in-memory caching strategy provides a low-risk performance win for frequently-read user UI data while keeping data fresh via explicit invalidation on updates. For multi-instance deployments or higher-scale requirements, replace the in-memory cache with `IDistributedCache` (Redis) and keep the same key and invalidation semantics.


#### Development URLs

| Project | Purpose | HTTPS URL | HTTPURL |
|---------|---------|-----------|----------|
| API | Web API Backend | https://localhost:5001 | http://localhost:5000 |
| WT.Admin | Admin Panel | https://localhost:7127 | http://localhost:5041 |
| WT.Client | Client PWA | https://localhost:7000 | http://localhost:7001 |

#### Health Check Endpoints ✨ NEW

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

#### HTTP Status Codes
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
---

### Blazor WebAssembly (WT.Client)
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
#### Google Maps API Key Management ✨ NEW
To securely manage the Google Maps API key in the Blazor WebAssembly client without committing it to source control, follow these steps:
1. **Create a Template**: Keep a committed `index.html.template` in `WT.Client/wwwroot/` with a placeholder for the API key:
2. **Insert the API Key**: At build time, ensure the API key is injected into a new `index.html` file by your build or deploy process, replacing the placeholder with the actual key. This prevents the API key from being hardcoded in the source files.
3. **Secure the Key**: Use environment variables or a secret manager to store the API key securely and access it during the build process without exposing it in the source. 


***NOTES:***
- Do not commit the generated index.html (ensure WT.Client/wwwroot/index.html is in .gitignore).
- Verify the script tag in the generated file contains the new key.
- Rotate the key in Google Cloud Console if it was leaked.
- Apply strict API restrictions in GCP (limit to Maps JS API and exact HTTP referrers, include scheme+host+port).
- Use separate keys per environment (dev/staging/prod).
- Never commit real keys — commit only `index.html.template`.

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

---

## Client-side JWT token storage (in-memory)

### Summary
To reduce exposure of sensitive tokens to cross-site scripting (XSS) attacks, the client app no longer persists JWT access tokens in browser storage. Instead:

- Access tokens are kept in-memory only using `WT.Client.Services.TokenService`.
- Refresh tokens are handled server-side via an HttpOnly cookie. The client calls the server refresh endpoint (e.g. `POST api/account/identity/refresh-token`) to obtain a fresh access token.
- The `AuthenticatedLocalStorageDTO` concept was renamed to `AuthenticatedSessionDTO` to make clear that token-bearing DTOs are ephemeral and should not imply localStorage persistence.

### Why this change
- LocalStorage is accessible to JavaScript and increases XSS risk when storing tokens.
- HttpOnly cookies are not accessible to JavaScript and provide a safer mechanism for refresh tokens.
- Keeping the access token in-memory prevents long-lived exposure on the client while still allowing the app to call protected APIs.

### `TokenService` (WT.Client.Services.TokenService)
Key members:

- `string? AccessToken` — current in-memory access token (or `null`).
- `void SetAccessToken(string token, DateTime expiresAt)` — store token and expiry in memory.
- `void Clear()` — clear the token (logout flow).
- `bool IsExpired()` — true when no token or token expired.
- `event Action? TokenChanged` — raised when token is set or cleared.

Class location: `WT.Client/Services/TokenService.cs` (implements `ITokenService`).

### DI registration (Blazor WASM)
Register the token service in the client `Program.cs`:

```csharp
// Program.cs (WT.Client)
builder.Services.AddSingleton<WT.Client.Services.ITokenService, WT.Client.Services.TokenService>();
```

Singleton is appropriate for an in-memory token store in a WebAssembly application because the app runs in a single browser context.

### Typical usage

1) Store token after login (or after refresh):

```csharp
var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
var jwt = handler.ReadJwtToken(apiResponse.JwtToken);
_tokenService.SetAccessToken(apiResponse.JwtToken, jwt.ValidTo);
```

2) Keep `HttpClient` Authorization header in sync (subscribe once):

```csharp
_tokenService.TokenChanged += () =>
{
 if (!string.IsNullOrEmpty(_tokenService.AccessToken))
 {
 _httpClient.DefaultRequestHeaders.Authorization =
 new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", _tokenService.AccessToken);
 }
 else
 {
 _httpClient.DefaultRequestHeaders.Authorization = null;
 }
};

// Initialize on startup
if (!string.IsNullOrEmpty(_tokenService.AccessToken))
{
 _httpClient.DefaultRequestHeaders.Authorization =
 new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", _tokenService.AccessToken);
}
```

3) Refresh flow

- When a protected call receives401, the app calls the server refresh endpoint. The server reads the HttpOnly refresh cookie and returns a new access token. The client stores the returned token in `TokenService` (in-memory) and retries the failed request.
- This flow is implemented in `WT.Application.Extensions.BaseService.GetRefreshTokenAsync()` and `WT.Application.Services.AccountService.EnsureAuthorizationHeaderAsync()`.

4) Logout / clearing token

```csharp
_tokenService.Clear();
await _httpClient.PostAsync("api/account/identity/logout", null); // clears server-side cookie
```

### Example helper to synchronize HttpClient

```csharp
public static void SyncHttpClientAuth(HttpClient httpClient, WT.Client.Services.ITokenService tokenService)
{
 if (!string.IsNullOrEmpty(tokenService.AccessToken) && !tokenService.IsExpired())
 {
 httpClient.DefaultRequestHeaders.Authorization =
 new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", tokenService.AccessToken);
 }
 else
 {
 httpClient.DefaultRequestHeaders.Authorization = null;
 }
}
```

Call this helper on startup and subscribe it to `TokenChanged` to keep the header current.

### Security notes
- Do NOT persist access tokens or refresh tokens to `localStorage` or other persistent browser storage.
- Ensure the server sets the refresh cookie with `HttpOnly`, `Secure`, and an appropriate `SameSite` policy.
- Never log tokens or include them in error messages.

---

(See `WT.Client/Services/TokenService.cs` and `WT.Application/Extensions/BaseService.cs` for implementation details.)
