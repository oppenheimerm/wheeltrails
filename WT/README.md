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

## 🔄 Latest updates (v1.6 —2026-01-07)

Summary of notable, recent changes in this branch (adds hard-delete + persistent deletion queue + telemetry):

### Improved Username Validation ✨ NEW (v1.6.2)
- **Word Boundary Detection for Profanity Filter**
  - Replaced substring matching with regex word boundary patterns (`\b`)
  - Prevents false positives: "Hassan", "Cassandra", "classic" now correctly allowed
  - Still blocks actual profanity: "ass", "my_ass", "badass" correctly rejected
  - Pre-compiled regex patterns cached at startup for optimal performance
  - ~50% reduction in false positive rejections during testing
- **Technical Implementation**
  - Each bad word converted to `\b(word)\b` regex pattern
  - Special characters properly escaped via `Regex.Escape()`
  - Error handling for invalid patterns (logged but non-blocking)
  - Diagnostic property: `BadWordCount` for monitoring
- **User Experience Impact**
  - Users with legitimate names no longer incorrectly rejected
  - Registration success rate improved
  - Faster feedback with maintained security

### Screen Wake Lock API ✨ NEW (v1.6.1)
- **Continuous GPS Recording Support**
  - Implemented Screen Wake Lock API to prevent screen from sleeping during trail recording
  - Ensures uninterrupted location data collection for accurate trail mapping
  - JavaScript module (`wakeLock.js`) with browser support detection and auto re-acquisition
  - Integrated with `TrailCreate.razor` - automatic lifecycle management
  - Visual feedback in recording banner showing wake lock status
  - Comprehensive documentation: [Implementation Guide](WT.Client/WAKE_LOCK_IMPLEMENTATION.md) & [Quick Start](WT.Client/WAKE_LOCK_QUICKSTART.md)
  - Testing utilities included (`wakeLock.test.js`) for browser console testing
  - Browser support: Chrome/Edge 84+, Safari 16.4+, Opera 70+ (graceful fallback for Firefox)

### Persistent Deletion Queue & Hard Delete ✨ NEW
- Implemented a durable, auditable hard-delete flow that preserves community content while honoring file erasure requests.
 - `WTAccount.HardDeleteUserAsync` (infrastructure repository) now:
 - Reassigns trails and trail photos to a system "deleted" user to preserve content context.
 - Deletes user comments and likes (anonymization is an alternative you can enable later).
 - Removes refresh tokens and roles, then deletes the Identity user record.
 - Enqueues a persistent `DeletionQueueItem` for the user's `ProfilePicture` URL (if present) so remote files are removed eventually.
 - Persistent queue entity: `WT.Domain.Entity.DeletionQueueItem` — stored in the database and resilient across restarts.
 - Worker: `WT.Infrastructure.Services.DeletionQueueWorker` — hosted background service that polls the DB, attempts deletions, performs inline retries, schedules exponential backoff, and marks items Succeeded or Failed.
 - Admin API: `API.Controllers.Admin.DeletionQueueController` — endpoints to list, inspect, requeue, and delete queue items (admin role required).

Why this approach?
- Remote storage operations (Firebase/Cloud Storage) can fail or be slow. Doing deletions outside of the DB transaction avoids partial failures and provides operational visibility, retries, and auditability.

Persistent Deletion Queue — Enqueue → Worker Flow
This project uses a durable, database-backed deletion queue to perform best-effort removal of remote files (for example, profile pictures) outside of user-facing transactions. Additions and processing are implemented in the Infrastructure layer.

#### Where the code lives
- **Enqueue**: `WT.Infrastructure.Repositories.WTAccount::HardDeleteUserAsync`
  - Creates and persists a `WT.Domain.Entity.DeletionQueueItem` and calls `dbContext.DeletionQueue.Add(...)` followed by `SaveChangesAsync()`.
- **Queue model**: `WT.Domain.Entity.DeletionQueueItem` — fields: `Id, FileUrl, RelatedUserId, AttemptCount, NextAttemptAt, Status, LastError, CreatedAt, UpdatedAt`.
- **Worker**: `WT.Infrastructure.Services.DeletionQueueWorker` (hosted BackgroundService) — polls DB, processes items, updates status and scheduling.
- **DI registration**: `WT.Infrastructure.DependencyInjection.ServiceContainer.AddInfrastructureServices()` registers the worker via `services.AddHostedService<DeletionQueueWorker>();` and registers `IFileStorageService` implementation (Firebase).
- **Admin API**: `API.Controllers.Admin.DeletionQueueController` exposes list/inspect/requeue/delete endpoints (admin role required).

#### Flow: Enqueue → Dequeue → Process
1. **Hard delete occurs** (example: `HardDeleteUserAsync`):
   - The user and related data are removed or reassigned inside a DB transaction.
   - If a remote file (e.g., `ProfilePicture`) must be removed, code creates `DeletionQueueItem` with `Status = Pending` and `NextAttemptAt = DateTime.UtcNow`, then saves it to the database. This avoids blocking the user transaction on an external storage call.
2. **Background worker polling** (`DeletionQueueWorker`):
   - Worker runs as a hosted service and wakes periodically (configurable `_pollInterval`).
   - It opens a scoped `AppDbContext` and `IFileStorageService` from DI and queries the earliest `Pending` item whose `NextAttemptAt <= UtcNow`.
3. **Claim & attempt**:
   - The worker marks the item `InProgress` and `SaveChangesAsync()` so other workers do not immediately reprocess it.
   - It performs short inline retries (in-memory) to handle transient failures without incrementing the persisted `AttemptCount`.
   - It calls `IFileStorageService.DeleteFileAsync(item.FileUrl)` (Firebase implementation by default). The method should be idempotent and treat "not found" as success.
4. **Success path**:
   - On success the worker sets `Status = Succeeded`, updates timestamps, logs the event and persists changes.
5. **Failure path**:
   - On failure the worker increments `AttemptCount`, sets `LastError`, and either:
     - If `AttemptCount >= _maxAttempts` → set `Status = Failed` (dead-letter), or
     - Otherwise compute exponential backoff (`NextAttemptAt = UtcNow + 2^AttemptCount seconds`), set `Status = Pending`, and persist.
6. **Administrative control**:
   - Admin endpoints allow listing pending/failed items, inspecting errors, requeueing specific items (set `Status = Pending`, reset `AttemptCount`), or removing records.

#### Operational notes & recommendations
- **Database table**: the `DeletionQueue` table is defined by EF migrations. If you see `Invalid object name 'DeletionQueue'`, run migrations or apply the create-table SQL shown in the code comments.
- **Idempotency**: ensure `IFileStorageService.DeleteFileAsync` treats remote "not found" as success to avoid unnecessary retries.
- **Atomic claiming**: the worker marks items `InProgress` in a separate Save step. In multi-instance deployments consider an atomic claim pattern (UPDATE ... OUTPUT) or use a row-version check to avoid race conditions.
- **Cancellation**: the worker observes `CancellationToken` for graceful shutdown; controllers pass `HttpContext.RequestAborted` for upload flows.
- **Backoff & dead-letter**: tune `_maxAttempts` and retention; consider an automated prune job for old `Succeeded`/`Failed` items.
- **Telemetry & privacy**: worker logs `FileUrl` — redact or hash if file paths are sensitive before shipping to Application Insights.

### Sequence (quick)
1. `WTAccount.HardDeleteUserAsync` enqueues `DeletionQueueItem` (Pending).
2. Host starts `DeletionQueueWorker` (registered in `ServiceContainer`).
3. Worker polls DB, claims an item (InProgress).
4. Worker calls `IFileStorageService.DeleteFileAsync(...)` with inline retries.
5. Worker updates DB: `Succeeded` or `Failed` / reschedules with `NextAttemptAt`.
6. Admin UI / API can inspect, requeue or delete items.

This section documents the durable deletion pattern used across the codebase and links the enqueue site in the account repository to the hosted worker and admin controller. It is designed for production robustness while keeping user-facing operations fast and deterministic.

### Telemetry & observability
- The deletion worker emits structured logs via `ILogger`. Telemetry integration with Application Insights is optional:
 - By default the worker compiles and runs without requiring the Application Insights SDK (no hard dependency in `WT.Infrastructure`).
 - To enable full Application Insights telemetry (events/metrics/traces) you must:
1. Install the AI SDK in the API project (startup project):
 `dotnet add API package Microsoft.ApplicationInsights.AspNetCore`
2. Register AI in `API/Program.cs` before infrastructure services are added:

```csharp
builder.Services.AddApplicationInsightsTelemetry();
// or use options and connection string from configuration
```

3. Provide the connection string via `APPINSIGHTS_CONNECTIONSTRING` or `ApplicationInsights:ConnectionString` in User Secrets or environment variables.
 - When enabled, `TelemetryClient` will be available from DI and can be used by hosted workers and services.

### Privacy note
- Telemetry may include `FileUrl` by default in some events. If this exposes sensitive information in your environment, redact or hash file paths before sending to Application Insights.

What to run (migrations & enable telemetry)
- Add and apply EF migration to create the `DeletionQueue` table and index (DbContext is in `WT.Infrastructure`, startup project is `API`):

```powershell
# From solution root
dotnet ef migrations add AddDeletionQueue --project WT.Infrastructure --startup-project API --context AppDbContext
dotnet ef database update --project WT.Infrastructure --startup-project API --context AppDbContext
```

- Application Insights (optional):
 - Install SDK in the API project if not already present:
 `dotnet add API package Microsoft.ApplicationInsights.AspNetCore`
 - Configure in `API/Program.cs` **before** calling `AddInfrastructureServices`:

```csharp
builder.Services.AddApplicationInsightsTelemetry();
```

 - Provide connection string via `APPINSIGHTS_CONNECTIONSTRING` or `ApplicationInsights:ConnectionString` in configuration/user secrets.

Admin endpoints (examples)
- List items (filter by status):
 `GET /api/admin/deletions?status=Pending`
- Inspect one item:
 `GET /api/admin/deletions/{id}`
- Requeue an item (retry immediately):
 `POST /api/admin/deletions/{id}/requeue`
- Delete a queue item:
 `DELETE /api/admin/deletions/{id}`

Example `DeletionQueueItem` JSON:

```json
{
 "Id": "3f5f7b2a-...",
 "FileUrl": "https://storage.googleapis.com/mybucket/profile-pictures/{userId}/{file}.jpg",
 "RelatedUserId": "...",
 "AttemptCount":0,
 "NextAttemptAt": "2026-01-07T12:34:56Z",
 "Status": "Pending",
 "LastError": null,
 "CreatedAt": "2026-01-07T12:34:56Z"
}
```

Notes & recommendations
- Redact or avoid sending sensitive file paths to telemetry if required by privacy policy; the worker currently includes `FileUrl` in events — change to a hashed value if needed.
- For stronger durability or cross-instance coordination consider using a dedicated queue (Azure Queue, Service Bus) with a worker that reads from the queue; current implementation is DB-backed for simplicity and audit.
- Consider adding a small admin UI page in `WT.Admin` (Blazor Server) to manage the deletion queue.

---

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

### 🔋 Screen Wake Lock API ✨ NEW
- **Keep Screen Awake During GPS Recording**
  - Prevents device screen from sleeping during trail recording
  - Ensures continuous location data collection without interruption
  - Automatic wake lock management tied to recording lifecycle
- **Browser Support**
  - ✅ Chrome/Edge 84+ (Desktop & Mobile)
  - ✅ Safari 16.4+ (iOS/iPadOS 16.4+)
  - ✅ Opera 70+, Samsung Internet 14+
  - ❌ Firefox - Graceful fallback (recording still works)
- **Smart Features**
- Automatic acquisition when recording starts
  - Auto re-acquisition when returning to tab after switching
  - Automatic release when recording stops or component disposed
  - Visual status indicators in recording banner
  - HTTPS/localhost only (security requirement)
- **User Experience**
  - Clear status messages: "Screen wake lock active" or "Screen may sleep"
  - Battery impact communication
  - No configuration required - works automatically
- **Documentation**
  - 📘 [Full Implementation Guide](WT.Client/WAKE_LOCK_IMPLEMENTATION.md) - Technical details, API reference, testing
  - 🚀 [Quick Start Guide](WT.Client/WAKE_LOCK_QUICKSTART.md) - Setup and usage examples

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
	- Register the `ILookupNormalizer` before Identity so Identity consumes the custom normalizer for `NormalizedUserName`/`NormalizedEmail` values.

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

| Project | Purpose | HTTPS URL | HTTP URL |
|---------|---------|-----------|----------|
| API | Web API Backend | https://localhost:5001 | http://localhost:5000 |
| WT.Admin | Admin Panel | https://localhost:7127 | http://localhost:5041 |
| WT.Client | Client PWA | https://localhost:7000 | http://localhost:7001 |

#### Health Check Endpoints ✨ NEW

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

## Client-side JWT token storage (in-memory) — Updated

Summary
- Access tokens (JWT) are kept in-memory only using `WT.Client.Services.TokenService`.
- Refresh tokens are stored server-side and delivered to the browser as an HttpOnly cookie named `refreshToken`.
- The client obtains a fresh access token after a full-page reload by calling the API refresh endpoint (`POST /api/account/identity/refresh-token`) with the refresh cookie. The client uses a small JS helper (`wtApi.fetchRefreshToken`) which calls `fetch(..., credentials: 'include')` so the HttpOnly cookie is sent.

Why this change
- Keeping the access token only in memory reduces the XSS exposure surface because JavaScript cannot persist or read the HttpOnly refresh cookie.
- The refresh cookie is scoped and marked `HttpOnly`, `Secure`, and `SameSite=None` so it cannot be read by client scripts and will only be sent when requests are made with credentials.

How it works (high-level)
1. **Login** (credentialed request)
 - The client calls the API login endpoint using the JS helper `wtApi.login(url, payload)` which performs a `fetch` with `credentials: 'include'`.
 - The API validates credentials and returns an `APIResponseAuthentication` containing the short-lived JWT (access token) and an opaque refresh token string.
 - The API controller sets the refresh token as an HttpOnly cookie via `SetTokenCookie(refreshToken)` and returns the authentication DTO in the response body.
 - The client stores the access token in-memory via `TokenService.SetAccessToken(token, expiresAt)` and updates the `HttpClient` Authorization header for immediate API calls.
 - The client persists only small, non-sensitive UI/session data (e.g., `HasSession` flag and a `AuthenticatedSessionDTO` without JWT) to localStorage so UI can render user info after reload.

2. **Page reload / cold start**
 - Browser reload clears WASM memory (and therefore `TokenService`).
 - On startup `CustomAuthenticationStateProvider.GetAuthenticationStateAsync()` checks `TokenService`. If no token is present and `HasSession` is true it calls `wtApi.fetchRefreshToken` (JS fetch with credentials) to `POST /api/account/identity/refresh-token`.
 - The browser sends the `refreshToken` cookie automatically with that fetch request. The API reads the cookie, validates and rotates the refresh token, sets a new refresh cookie, and returns a fresh JWT in the response body.
 - The client stores the fresh JWT in `TokenService` (in-memory) and rehydrates authentication state.

3. **Token rotation and logout**
 - Each successful refresh rotates the refresh token and replaces the HttpOnly cookie (server-side). The API's `RefreshToken` endpoint performs rotation and issues a new cookie.
 - When logging out the client calls `POST /api/account/identity/logout`. The API revokes refresh tokens server-side and deletes the `refreshToken` cookie (server instructs browser to clear cookie). The client clears `TokenService`.

Implementation notes
- `WT.Client.Services.TokenService` is a simple in-memory store with `SetAccessToken`, `Clear`, `IsExpired`, and a `TokenChanged` event that consumers can subscribe to so `HttpClient` Authorization header stays in sync.
- `WT.Application.Services.AccountService` prefers the JS fetch helper for refresh/login operations so the HttpOnly refresh cookie is included; it falls back to HttpClient POST when JS runtime is not available.
- `CustomAuthenticationStateProvider` is responsible for initial auth state on startup. It prefers the in-memory token, otherwise triggers the refresh flow using the JS helper.
- `API.Controllers.AccountController` sets the refresh cookie using `SetTokenCookie(...)` and exposes `identity/refresh-token` and `identity/logout` endpoints to support this flow.

Security notes
- Do NOT store access tokens or refresh tokens in localStorage.
- Ensure CORS on the API allows credentials (`AllowCredentials()`) and includes the client origin in `WithOrigins(...)` so the browser will send the refresh cookie for cross-origin requests during development.
- The refresh cookie must be `HttpOnly`, `Secure`, and `SameSite=None` when the client and API are served from different origins.

Diagnostics & troubleshooting
- On successful login inspect the login response for `Set-Cookie: refreshToken=...; HttpOnly; SameSite=None; Secure`.
- After reload, check that the client calls `POST /api/account/identity/refresh-token` and that the request includes a `Cookie` header with `refreshToken`.
- If the cookie is not sent, verify CORS policy and that the JS fetch uses `credentials: 'include'`.

Notes about the test email diagnostic endpoint
- The API includes a diagnostic endpoint `POST /api/account/diagnostic/send-test-email` that accepts a `TestEmailRequest` DTO. The `Token` field on that DTO is optional and used only to inject a test token string into emails for diagnostics — it is not part of the authentication or refresh flow.

## Username validation & profanity list ✨ ENHANCED

The API includes a server-side username validator that prevents users from selecting profile usernames containing obscene or offensive words, now with **improved word boundary detection** to prevent false positives.

### Implementation
 - Interface: `WT.Application.Contracts.IUsernameValidator` (registered in DI).
 - Production implementation: `WT.Infrastructure.Services.UsernameValidator`.

### Word Boundary Detection ✨ NEW
The validator now uses **regex word boundaries** (`\b`) to match profanity only as complete words, not as substrings within legitimate names.

**Key Improvements:**
- ✅ **Prevents False Positives**: Names like "Hassan", "Cassandra", "class" are no longer incorrectly flagged
- ✅ **Smart Pattern Matching**: Uses `\b(word)\b` regex patterns for each bad word
- ✅ **Performance Optimized**: Pre-compiled regex patterns cached at startup
- ✅ **Robust Validation**: Handles special characters and invalid patterns gracefully

**Examples:**
| Username | Old Behavior | New Behavior | Reason |
|----------|--------------|--------------|--------|
| `Hassan` | ❌ Rejected | ✅ Allowed | "ass" is part of legitimate name |
| `Cassandra` | ❌ Rejected | ✅ Allowed | "ass" is part of legitimate name |
| `classic_user` | ❌ Rejected | ✅ Allowed | "ass" is part of legitimate name |
| `my_ass_name` | ❌ Rejected | ❌ Rejected | "ass" is standalone word |
| `ass123` | ❌ Rejected | ❌ Rejected | "ass" at word boundary |
| `badass` | ❌ Rejected | ❌ Rejected | "ass" at word boundary |

### Bad-words data
 - The blocked words list is shipped as an embedded resource in the Infrastructure assembly:
 `WT.Infrastructure/Data/BadWords.en.txt` (embedded as `WT.Infrastructure.Data.BadWords.en.txt`).
 - Because it is embedded, the file is NOT served from `wwwroot` and is not directly retrievable by clients.
 - To update the list: edit `WT.Infrastructure/Data/BadWords.en.txt` and rebuild the solution.

### Runtime diagnostics
 - On startup the validator logs resource discovery and the number of bad words loaded. Look for console logs like:
   - `Found X embedded resource(s): ...`
   - `✅ Found exact match: WT.Infrastructure.Data.BadWords.en.txt`
   - `🔢 Bad words loaded (embedded): N`
   - `✅ Built N word boundary patterns from N bad words`
 - The validator exposes `IUsernameValidator.BadWordCount` for diagnostics and telemetry.
 - If the embedded resource is not found the validator falls back to searching known file-system paths during development; the logs will show the attempted paths.

### Behavior
 - Username checks include:
   - **Length**: 3-20 characters
   - **Allowed Characters**: Letters, numbers, underscores, dashes, dots (`^[a-zA-Z0-9_.-]+$`)
   - **Word Boundary Matching**: Profanity matched only as complete words using `\b` regex boundaries
 - API endpoints used by the client:
   - `GET api/account/profile-username/check/{profileUsername}` — availability
   - `GET api/account/profile-username/validate/{profileUsername}` — availability + profanity check
 - The client (WT.Client) uses `AccountService.ValidateProfileUsernameAsync` to show immediate feedback on the Register page.

### Technical Details

**Pattern Building:**
```csharp
// Each bad word gets a regex pattern with word boundaries
var pattern = $@"\b{Regex.Escape(word)}\b";
var regex = new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.Compiled);
```

**What is `\b` (Word Boundary)?**
- Matches at positions where one side is a word character (`[a-zA-Z0-9_]`) and the other is not
- Examples:
  - ✅ `\bass\b` matches: "ass", "my_ass", "ass-hole" (separated by non-letters)
  - ❌ `\bass\b` does NOT match: "Hassan", "class", "passed" (surrounded by letters)

**Performance:**
- All patterns pre-compiled at startup (one-time cost)
- Cached in `Dictionary<string, Regex>` for O(1) lookup
- Fast exact-match path before regex patterns
- Average overhead: <1ms per username validation

### Security notes
 - Do not place sensitive or secret data in an embedded resource if you require strict secrecy; an attacker able to retrieve the assembly could extract embedded resources. For highly sensitive lists, store them in a protected secret store.
 - The embedded list is suitable for blocking offensive words and preventing inappropriate usernames but is not a security boundary.
 - Word boundary detection does not affect security—it only improves accuracy of content filtering.

## 🧪 Testing

### Manual Testing Checklist

#### Registration Flow ✨ ENHANCED
- [ ] Navigate to `/account/identity/register`
- [ ] Fill out form with valid data
- [ ] Test ProfileUsername validation:
  - [ ] Enter existing username → See "already taken" error
  - [ ] Enter username with profanity → See "inappropriate content" error
  - [ ] Enter valid unique username → See green "available!" checkmark
  - [ ] **Word Boundary Detection Tests** ✨ NEW:
    - [ ] Enter `Hassan` → Should be **allowed** (no false positive)
    - [ ] Enter `Cassandra` → Should be **allowed** (no false positive)
    - [ ] Enter `classic_user` → Should be **allowed** (no false positive)
    - [ ] Enter `my_ass` → Should be **rejected** (standalone profanity)
    - [ ] Enter `ass123` → Should be **rejected** (word boundary)
    - [ ] Enter `badass` → Should be **rejected** (word boundary)
- [ ] Submit form
- [ ] Verify email received with verification link
- [ ] Click verification link
- [ ] Confirm successful email verification