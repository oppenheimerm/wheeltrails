# WheelyTrails .Net MAUI App

# WT.Maui — Authentication, DI and Navigation Guide

**Purpose**
- Document the complete login/logout/refresh flow used by the MAUI app
- Explain how `AuthService` and `NativeTokenService` work together to manage tokens
- Show how `TryRefreshAsync()` handles automatic token refresh
- Provide clear patterns for adding new Pages and ViewModels
- Give copy/paste examples that match the project's architecture

This is your single reference for authentication, token management, navigation, and DI patterns in the WheelyTrails MAUI app.

---

## Table of Contents
1. [UI / UX — Material 3 Design System](#ui--ux--material-3-design-system)
2. [Authentication Flow Overview](#authentication-flow-overview)
3. [Token Management Architecture](#token-management-architecture)
4. [Detailed Flow: Login](#detailed-flow-login)
5. [Detailed Flow: Token Refresh](#detailed-flow-token-refresh)
6. [Detailed Flow: Logout](#detailed-flow-logout)
7. [Adding New Pages and ViewModels](#adding-new-pages-and-viewmodels)
8. [DI Registration Patterns](#di-registration-patterns)
9. [Navigation Best Practices](#navigation-best-practices)
10. [Troubleshooting](#troubleshooting)

---

## UI / UX — Material 3 Design System

### Design Philosophy

WheelyTrails follows [Material Design 3 (Material You)](https://m3.material.io/) guidelines to deliver a **consistent, accessible, and modern look** across:

- **WT.Client** — Blazor WebAssembly (PWA)
- **WT.Maui** — Android & iOS native apps

The same color tokens, typography scale, and component patterns are used in both platforms so users experience a unified brand regardless of device.

### Theme Source of Truth

The canonical theme is generated from **Material Theme Builder** and stored as CSS variables in the web client. The MAUI client mirrors these tokens in XAML resources.

| Platform | Light Theme | Dark Theme | Location |
|----------|-------------|------------|----------|
| **WT.Client** (Web) | `light.css` | `dark.css` | `WT.Client/wwwroot/css/material-theme/` |
| **WT.Maui** (Mobile) | `Colors.xaml` + `Styles.xaml` | Same files with `AppThemeBinding` | `WT.Maui/Resources/Styles/` |

### Color Token Mapping

The MAUI `Colors.xaml` defines color resources that match the CSS variables in `theme.css`:

| CSS Variable (Web) | XAML Resource (MAUI) | Light Value | Dark Value |
|--------------------|----------------------|-------------|------------|
| `--md-sys-color-primary` | `PrimaryLight` / `PrimaryDark` | `#36693D` | `#9DD49E` |
| `--md-sys-color-primary-container` | `PrimaryContainerLight` / `PrimaryContainerDark` | `#B8F1B9` | `#1E5128` |
| `--md-sys-color-on-primary-container` | `OnPrimaryContainerLight` / `OnPrimaryContainerDark` | `#1E5128` | `#B8F1B9` |
| `--md-sys-color-secondary` | `Secondary` | `#516350` | `#516350` |
| `--md-sys-color-error` | `Error` | `#BA1A1A` | `#BA1A1A` |
| `--md-sys-color-background` | `Background` | `#F7FBF2` | — |
| `--md-sys-color-surface` | `Surface` | `#F7FBF2` | — |
| `--md-sys-color-on-surface` | `OnSurface` / `OnSurfaceLight` / `OnSurfaceDark` | `#181D18` | `#E0E4DB` |
| `--md-sys-color-surface-container` | `SurfaceContainerLight` / `SurfaceContainerDark` | `#FFFFFF` | `#101510` |

### Theme-Aware Resources

MAUI does not support CSS variables, so we use two patterns to achieve light/dark theming:

#### 1. AppThemeBinding (for Color properties)

Use `AppThemeBinding` inline when a property expects a `Color`:
```xml
<Label Text="Hello, World!"
       TextColor="{AppThemeBinding Light={StaticResource PrimaryDark}, Dark={StaticResource PrimaryLight}}" />
```

#### 2. DynamicResource (for other properties)

Use `DynamicResource` for other cases, like `BackgroundColor`:
```xml
<ContentPage BackgroundColor="{DynamicResource Background}">
    <StackLayout>
        <Button Text="Click Me"
                BackgroundColor="{DynamicResource Primary}"
                TextColor="{DynamicResource OnPrimary}" />
    </StackLayout>
</ContentPage>
```

#### 2. Theme-Aware Brushes (for Brush properties)

Define `SolidColorBrush` resources with `AppThemeBinding` in `Colors.xaml`:

```xml
<SolidColorBrush x:Key="PrimaryBrush" Color="{AppThemeBinding Light={StaticResource PrimaryDark}, Dark={StaticResource PrimaryLight}}" />
<SolidColorBrush x:Key="SecondaryBrush" Color="{AppThemeBinding Light={StaticResource Secondary}, Dark={StaticResource Secondary}}" />
```


### Key Style Definitions (Styles.xaml)

| Style Key | Target | Purpose |
|-----------|--------|---------|
| `HeadlineLarge` | Label | Page titles (24pt, Bold) |
| `HeadlineMedium` | Label | Section headers (18pt, SemiBold) |
| `Body` | Label | Body text (14pt, Regular) |
| `FormLabel` | Label | Form field labels |
| `FormEntry` | Entry | Text input fields |
| `FormEditor` | Editor | Multi-line text areas |
| `PrimaryButton` | Button | Primary action (filled, theme primary color) |
| `SecondaryButton` | Button | Secondary action |
| `DangerButton` | Button | Destructive action (error color) |
| `CardStyle` | Border | Card container with elevation |
| `PrimaryBanner` | Border | Success/info banner |
| `ErrorBanner` | Border | Error message banner |
| `MutedLabel` | Label | De-emphasized text |

### Typography

Both platforms use the **Figtree** font family:

| Weight | MAUI FontFamily | Usage |
|--------|-----------------|-------|
| Regular | `FigtreeRegular` | Body text, form inputs |
| Medium | `FigtreeMedium` | Form labels |
| SemiBold | `FigtreeSemiBold` | Section headers, buttons |
| Bold | `FigtreeBold` | Page titles |

### Adding/Updating Theme Colors

When you update the Material Theme Builder output:

1. **Web (WT.Client)**: Replace/update files in `wwwroot/css/material-theme/`
2. **MAUI (WT.Maui)**: Update corresponding `<Color>` resources in `Colors.xaml`
3. Ensure light/dark variants are defined (e.g., `PrimaryLight`, `PrimaryDark`)
4. Update or add `SolidColorBrush` resources for Brush-based properties
5. Clean + Rebuild + Uninstall/Reinstall app on device (MAUI caches resources)

### Runtime Theme Switching

The app respects system theme by default. Users can override in Settings:

```xml
// SettingsViewModel.cs Application.Current.UserAppTheme = IsDarkMode ? AppTheme.Dark : AppTheme.Light; Preferences.Set("AppTheme", IsDarkMode ? "Dark" : "Light");
```


On startup, `SettingsViewModel.LoadPreferences()` restores the saved theme.

### Best Practices

| Do ✅ | Don't ❌ |
|------|---------|
| Use `{StaticResource PrimaryBrush}` for Brush properties | Hard-code hex colors in XAML |
| Use `{AppThemeBinding Light=..., Dark=...}` for Color properties | Use a single static color for both themes |
| Use `{DynamicResource OnSurface}` for text colors that must update at runtime | Use `{StaticResource}` for runtime-switching properties |
| Define new colors in `Colors.xaml` with Light/Dark variants | Scatter color definitions across multiple files |
| Reference styles by key (`Style="{StaticResource PrimaryButton}"`) | Duplicate style setters inline |

### File Reference

WT.Maui/ └── Resources/ └── Styles/ ├── Colors.xaml      ← Color tokens + theme-aware Brushes └── Styles.xaml      ← Typography, Button, Entry, Card styles
WT.Client/ └── wwwroot/ └── css/ └── material-theme/ ├── theme.css    ← CSS variables (light default + .dark overrides) ├── light.css    ← Light theme variables ├── dark.css     ← Dark theme variables ├── light-hc.css ← Light high-contrast ├── dark-hc.css  ← Dark high-contrast ├── light-mc.css ← Light medium-contrast └── dark-mc.css  ← Dark medium-contrastWT.Maui/ └── Resources/ └── Styles/ ├── Colors.xaml      ← Color tokens + theme-aware Brushes └── Styles.xaml      ← Typography, Button, Entry, Card styles
WT.Client/ └── wwwroot/ └── css/ └── material-theme/ ├── theme.css    ← CSS variables (light default + .dark overrides) ├── light.css    ← Light theme variables ├── dark.css     ← Dark theme variables ├── light-hc.css ← Light high-contrast ├── dark-hc.css  ← Dark high-contrast ├── light-mc.css ← Light medium-contrast └── dark-mc.css  ← Dark medium-contrast

---

## Authentication Flow Overview

+------------------+
|      App         |
+------------------+
         |
         v
+------------------+
|  LoginPage       |
+------------------+
         |
         | Login success
         v
+------------------+
|    AppShell      |
|  (Home/Trails/…) |
+------------------+
         |
         | Logout
         v
+------------------+
|  LoginPage       |
+------------------+

┌─────────────────────────────────────────────────────────────────┐ │                        App Startup                               │ │  App.CreateWindow() → Creates Window with AppShell              │ │  App checks AuthService.IsLoggedIn (fast, synchronous)          │ │  If false → Call AuthService.RestoreSessionAsync()              │ └─────────────────────────────────────────────────────────────────┘ ↓ ┌─────────┴──────────┐ │  Token exists?     │ └─────────┬──────────┘ ↓ ┌───────────────┴────────────────┐ ↓                                ↓ Yes (has refresh token)         No (no refresh token) ↓                                ↓ ┌─────────────────────┐          ┌────────────────────┐ │ TryRefreshAsync()   │          │ Navigate to Login  │ │ Call API refresh    │          │ //login route      │ │ endpoint            │          └────────────────────┘ └─────────┬───────────┘ ↓ ┌──────┴───────┐ │ Success?     │ └──────┬───────┘ ↓ ┌─────────┴──────────┐ ↓                    ↓ Yes                   No ↓                    ↓ Navigate to      Navigate to Login //HomePage       //login Store tokens



### 🧭 Why this is the best approach for WheelyTrails
- You’re building a real app with long‑term maintainability in mind
- You avoid mixing authentication logic into your main Shell
- You keep your navigation tree clean
- You avoid back‑stack bugs
- You can evolve the auth flow independently
- You can later add biometric login, token refresh, etc. without touching AppShell

- It’s the architecture used by most serious MAUI apps.

1. Start-up
   - `App.CreateWindow()` returns a `Window` that hosts an `AppShell`.
   - After the window exists, the app attempts a fast restore:
     - Check `AuthService.IsLoggedIn` (in-memory access token present and not expired).
     - If not, call `AuthService.RestoreSessionAsync()` which attempts token refresh using stored refresh token.
   - Navigate to the correct absolute route:
     - Authenticated: `await Shell.Current.GoToAsync("//HomePage")`
     - Unauthenticated: `await Shell.Current.GoToAsync("//login")`

2. Login
   - `LoginViewModel.LoginAsync(LoginDTO)` calls `AuthService.LoginAsync()`.
   - On success:
     - Store access token in memory (via `NativeTokenService.SetAccessToken`).
     - Persist refresh token via `SecureStorage` (via `NativeTokenService.SetRefreshTokenAsync`).
     - Navigate to Shell root: `await Shell.Current.GoToAsync("//HomePage")`.

3. Refresh
   - `AuthHandler` attaches the access token to outgoing requests.
   - On a 401 response, `AuthHandler` calls `AuthService.TryRefreshAsync()` once and retries the request with the new token.
   - `AuthService.TryRefreshAsync()` calls the native refresh endpoint (server must accept refresh token in request body for native clients).

4. Logout
   - `SettingsViewModel.LogoutAsync()` calls `AuthService.LogoutAsync()` (best-effort network call).
   - `AuthService` clears access token (memory) and refresh token (secure storage).
   - Navigate to login and clear stack: `await Shell.Current.GoToAsync("//login", animate: false)`.

---

## Token Management Architecture

### Key Components

1. **`NativeTokenService`** — Token storage manager
   - Access token: kept **in-memory only** (transient, cleared on app restart)
   - Refresh token: persisted in **platform SecureStorage** (survives app restart)
   - Provides: `SetAccessToken()`, `GetRefreshTokenAsync()`, `IsAccessTokenExpired()`

2. **`AuthService`** — Authentication orchestrator
   - Performs login/logout/refresh operations against the API
   - Coordinates with `NativeTokenService` to store/retrieve tokens
   - Exposes `IsLoggedIn` (fast sync check) and `RestoreSessionAsync()` (async restore)

3. **`AuthHandler`** — HTTP request interceptor (DelegatingHandler)
   - Attaches `Authorization: Bearer <token>` to outgoing API requests
   - Detects 401 responses and invokes `TryRefreshAsync()` once
   - Retries the original request with the new token

---

## Token Management Architecture

### Why Two Storage Strategies?

**Access Token (In-Memory)**
- Short-lived (typically 30 minutes)
- Contains user claims and permissions
- Cleared on app restart for security
- Managed by `NativeTokenService._accessToken` private field

**Refresh Token (Secure Storage)**
- Long-lived (7 days default)
- Used to obtain new access tokens without re-login
- Persists across app restarts
- Stored via MAUI `SecureStorage.Default` (platform keychain/keystore)

### NativeTokenService — Token Storage Implementation

```csharp
public class NativeTokenService { private string? _accessToken;          // ← In-memory only private DateTime _expiresAt;           // ← Access token expiry private const string RefreshKey = "wt_refresh_token"; // ← SecureStorage key
// Fast synchronous check: is access token valid?
public string? AccessToken => _accessToken;

// Set access token (called after login or refresh)
public void SetAccessToken(string token, DateTime expiresAt)
{
    _accessToken = token;
    _expiresAt = expiresAt;
}

// Check if access token is missing or expired
public bool IsAccessTokenExpired() 
    => string.IsNullOrEmpty(_accessToken) || DateTime.UtcNow >= _expiresAt;

// Persist refresh token to platform secure storage
public async Task SetRefreshTokenAsync(string refreshToken)
{
    if (string.IsNullOrEmpty(refreshToken))
        await SecureStorage.Default.SetAsync(RefreshKey, string.Empty);
    else
        await SecureStorage.Default.SetAsync(RefreshKey, refreshToken);
}

// Retrieve refresh token from secure storage
public async Task<string?> GetRefreshTokenAsync()
{
    try
    {
        var r = await SecureStorage.Default.GetAsync(RefreshKey);
        return string.IsNullOrWhiteSpace(r) ? null : r;
    }
    catch { return null; }
}

// Clear tokens (logout)
public void ClearAccessToken()
{
    _accessToken = null;
    _expiresAt = default;
}

public async Task ClearRefreshTokenAsync()
{
    try { SecureStorage.Default.Remove(RefreshKey); }
    catch { }
    await Task.CompletedTask;
}
}
```

- `NativeTokenService`
  - Access token: memory only, `SetAccessToken(string token, DateTime expiresAt)`.
  - Refresh token: stored in `SecureStorage` using `SetRefreshTokenAsync`.
  - Methods: `GetRefreshTokenAsync`, `ClearRefreshTokenAsync`, `IsAccessTokenExpired()`.

- `AuthService`
  - `LoginAsync(LoginDTO)`: calls API, sets tokens (access + refresh).
  - `TryRefreshAsync()`: uses refresh token to get new access token.
  - `RestoreSessionAsync()`: attempts to restore by refreshing if a refresh token exists.
  - `LogoutAsync()`: calls API logout and clears tokens.

- `AuthHandler` (Http DelegatingHandler)
  - Attaches `Authorization: Bearer <accessToken>` to outgoing requests.
  - On 401, invokes `AuthService.TryRefreshAsync()`, then retries the original request once.

---

## Detailed Flow: Login

1. **LoginPage**: User enters credentials and taps login.
2. **LoginViewModel.LoginAsync**:
   - Calls `AuthService.LoginAsync(LoginDTO)`.
   - On success:
     - Calls `NativeTokenService.SetAccessToken(token, expiresAt)` to cache access token in memory.
     - Calls `NativeTokenService.SetRefreshTokenAsync(refreshToken)` to persist refresh token in secure storage.
     - Navigates to home page: `await Shell.Current.GoToAsync("//HomePage")`.

```csharp
// LoginViewModel (snippet)
[RelayCommand]
public async Task LoginAsync()
{
    IsBusy = true;
    try
    {
        var dto = new LoginDTO { Email = Email, Password = Password };
        var ok = await _auth.LoginAsync(dto);
        if (!ok) { ErrorMessage = "Login failed, check credentials."; return; }

        // Navigate to app root (clears backstack)
        await Shell.Current.GoToAsync("//HomePage");
    }
    finally
    {
        IsBusy = false;
    }
}
```

---

## Detailed Flow: Token Refresh

1. **AuthHandler**: For every outgoing HTTP request, attaches `Authorization: Bearer <accessToken>` header.
2. **401 Unauthorized Response**:
   - **AuthHandler** catches 401 response.
   - Calls `AuthService.TryRefreshAsync()`:
     - Sends stored refresh token to the server to obtain a new access token.
     - On success, caches the new access token in memory and updates the refresh token in secure storage.
     -Retries the original HTTP request with the new access token.

```csharp
// AuthHandler (snippet)
protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
{
    // 1. Attach access token
    var token = await _tokenService.GetAccessTokenAsync();
    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

    // 2. Send request
    var response = await base.SendAsync(request, cancellationToken);

    // 3. On 401, try to refresh token once
    if (response.StatusCode == HttpStatusCode.Unauthorized)
    {
        if (await _authService.TryRefreshAsync())
        {
            // Retry original request with new token
            token = await _tokenService.GetAccessTokenAsync();
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            response = await base.SendAsync(request, cancellationToken);
        }
    }

    return response;
}
```

---

## Detailed Flow: Logout

1. **SettingsViewModel.LogoutAsync**:
   - Calls `AuthService.LogoutAsync()`:
     - Clears access token from memory.
     - Removes refresh token from secure storage.
     - Informs the server to invalidate the refresh token (optional, based on API design).
   - Navigates to login page: `await Shell.Current.GoToAsync("//login", animate: false)`.

```csharp
// SettingsViewModel (snippet) 
[RelayCommand] 
public async Task LogoutAsync() 
{ 
    if (IsBusy) return; 
    IsBusy = true; 
    try 
    { 
        await _auth.LogoutAsync().ConfigureAwait(false); 
        // Navigate to login route and clear stack 
        await Shell.Current.GoToAsync("//login", animate: false); 
    } 
    finally 
    { 
        IsBusy = false; 
    } 
}
```

---

## Adding New Pages and ViewModels

1. **Create View and ViewModel**:
   - Add a new XAML page (e.g., `ProfilePage.xaml`).
   - Add corresponding ViewModel (e.g., `ProfileViewModel`).
   - Ensure the ViewModel has a parameterless constructor or is properly configured for DI.

2. **Register in DI**:
   - In `MauiProgram.cs`, register the ViewModel and Page:
     ```csharp
     builder.Services.AddTransient<ProfileViewModel>();
     builder.Services.AddTransient<ProfilePage>();
     ```

3. **Add Shell Route**:
   - In `AppShell.xaml.cs`, register the route:
     ```csharp
     Routing.RegisterRoute("profile", typeof(ProfilePage));
     ```

4. **Navigate**:
   - Use `await Shell.Current.GoToAsync("//profile")` to navigate to the new page.

---

## DI Registration Patterns

Recommended DI registrations for a clean and maintainable setup:

```csharp
// MauiProgram.cs (snippet)
var apiBase = new Uri("https://api.wheelytrails.com/");

// Services
builder.Services.AddSingleton<NativeTokenService>(); 
builder.Services.AddSingleton<AuthService>();

// ViewModels
builder.Services.AddTransient<LoginViewModel>(); 
builder.Services.AddTransient<SettingsViewModel>(); 
builder.Services.AddTransient<HomeViewModel>();
builder.Services.AddTransient<ProfileViewModel>(); // Example: new ViewModel

// Pages (transient)
builder.Services.AddTransient<WT.Maui.Views.Auth.LoginPage>(); 
builder.Services.AddTransient<WT.Maui.Views.SettingsPage>(); 
builder.Services.AddTransient<WT.Maui.Views.HomePage>();
builder.Services.AddTransient<WT.Maui.Views.ProfilePage>(); // Example: new Page

// AppShell so it can be resolved by DI if needed 
builder.Services.AddSingleton<AppShell>();

// HttpClient + AuthHandler (named client) 
builder.Services.AddTransient<AuthHandler>();
builder.Services.AddHttpClient("ApiClient", client => { client.BaseAddress = apiBase; 
client.Timeout = TimeSpan.FromSeconds(30); }) .AddHttpMessageHandler<AuthHandler>();

// Create HttpClient on-demand (transient) via IHttpClientFactory 
builder.Services.AddTransient(sp => sp.GetRequiredService<IHttpClientFactory>().CreateClient("ApiClient"));
```

Notes
- Register pages/viewmodels as `Transient` so each navigation gets fresh instances.
- Register `AppShell` as `Singleton` because Shell is the app-scoped root UI.
- Prefer typed clients (`AddHttpClient<T>()`) for larger services; the code above provides a convenient named client.

---

## Navigation Best Practices

- **Use Shell Routes**: Always prefer navigating using Shell routes (e.g., `//home`, `//login`) instead of directly setting `MainPage` or using `new Page()`.
- **Clear Backstack on Auth Switch**: Use absolute routes (e.g., `//login`, `//HomePage`) to reset the navigation stack when switching between authenticated and unauthenticated states.
- **Parameterize Routes**: For pages that need parameters, use route parameters and bind them in the ViewModel (e.g., `await Shell.Current.GoToAsync("//profile?id=123")`).
- **Use Query Properties**: For optional parameters, leverage query properties in route definitions to avoid breaking changes (e.g., define `id` as a query property in the profile route).

---

## Troubleshooting

- Error: `There is no argument given that corresponds to the required parameter 'vm' of 'LoginPage.LoginPage(LoginViewModel)'`
  - Cause: code instantiates a page via `new LoginPage()` while its constructor expects a `LoginViewModel`. Fix by registering `LoginPage` in DI and navigating via route or resolving page from DI.
- Error: DI runtime “ValueFactory attempted to access the Value property of this instance”
  - Cause: creating a singleton HttpClient from `IHttpClientFactory` at registration time. Fix: register transient factory or typed client.
- If `Shell.Current` is null at startup: ensure `CreateWindow` returns a `Window` hosting `AppShell` before attempting `Shell.Current.GoToAsync()`.

- **Key Points:**
- `_accessToken` is a **private field** — never persisted to disk
- `SecureStorage.Default` uses platform APIs:
  - **iOS**: Keychain
  - **Android**: Keystore
  - **Windows**: Credential Locker
- Refresh token operations are async because they involve disk I/O
- Access token operations are sync for fast checks (`IsLoggedIn`)

---

## Detailed Flow: Login

### Step-by-Step Process

```cshaprp
 // 1. User taps "Login" button in LoginPage // 2. LoginViewModel.LoginCommand executes:
[RelayCommand] private async Task LoginAsync() { ErrorMessage = string.Empty; IsBusy = true;
try
{
    var dto = new LoginDTO { Email = Email, Password = Password };
    
    // 3. Call AuthService.LoginAsync()
    var ok = await _auth.LoginAsync(dto);
    
    if (!ok)
    {
        ErrorMessage = "Login failed. Check credentials.";
        return;
    }

    // 4. Navigate to app home (clears back stack)
    await MainThread.InvokeOnMainThreadAsync(() =>
    {
        Shell.Current.GoToAsync("//HomePage", animate: false);
    });
}
finally
{
    IsBusy = false;
}
}

```

### AuthService.LoginAsync() Implementation

```csharp
public async Task<bool> LoginAsync(LoginDTO model) { // 1. POST credentials to API var resp = await _http.PostAsJsonAsync("api/account/identity/login", model); if (!resp.IsSuccessStatusCode) return false;
// 2. Deserialize API response
var payload = await resp.Content.ReadFromJsonAsync<APIResponseAuthentication?>();
if (payload == null || string.IsNullOrEmpty(payload.JwtToken)) 
    return false;

// 3. Parse JWT to get expiry time
var accessToken = payload.JwtToken!;
var expiresAt = GetExpiryFromJwt(accessToken) ?? DateTime.UtcNow.AddMinutes(30);

// 4. Store access token in memory
_tokens.SetAccessToken(accessToken, expiresAt);

// 5. Persist refresh token to secure storage
if (!string.IsNullOrEmpty(payload.RefreshToken))
{
    await _tokens.SetRefreshTokenAsync(payload.RefreshToken);
}

return true; // ← LoginViewModel navigates to //HomePage
}

```

**What Happens:**
1. API validates credentials and returns `{ JwtToken, RefreshToken, User }`
2. `AuthService` extracts the JWT and parses the `exp` claim
3. Access token stored **in-memory** via `NativeTokenService.SetAccessToken()`
4. Refresh token stored **in SecureStorage** via `SetRefreshTokenAsync()`
5. `AuthHandler` will now attach this access token to all API requests

---

## Detailed Flow: Token Refresh

### When Refresh Happens

1. **App Startup** — `RestoreSessionAsync()` if no valid access token in memory
2. **During API Call** — `AuthHandler` detects 401 and invokes `TryRefreshAsync()`

### RestoreSessionAsync() — Called at App Startup

```csharp
// 2. Try to get refresh token from SecureStorage
var refresh = await _tokens.GetRefreshTokenAsync();
if (string.IsNullOrEmpty(refresh)) 
    return false; // ← No refresh token, user must login

// 3. Attempt to refresh the access token
return await TryRefreshAsync();
}

```### TryRefreshAsync() — The Core Refresh Logic

```csharp
public async Task<bool> TryRefreshAsync() { // 1. Get refresh token from secure storage var refresh = await _tokens.GetRefreshTokenAsync(); if (string.IsNullOrEmpty(refresh)) return false;
try
{
    // 2. POST refresh token to API native refresh endpoint
    var resp = await _http.PostAsJsonAsync(
        "api/account/identity/refresh-token-native", 
        new { refreshToken = refresh }
    );
    
    if (!resp.IsSuccessStatusCode) 
        return false;

    // 3. Deserialize response (contains new JWT + rotated refresh token)
    var payload = await resp.Content.ReadFromJsonAsync<APIResponseAuthentication?>();
    if (payload == null || string.IsNullOrEmpty(payload.JwtToken)) 
        return false;

    // 4. Parse new JWT expiry
    var accessToken = payload.JwtToken!;
    var expiresAt = GetExpiryFromJwt(accessToken) ?? DateTime.UtcNow.AddMinutes(30);

    // 5. Update in-memory access token
    _tokens.SetAccessToken(accessToken, expiresAt);
    
    // 6. Update refresh token (token rotation)
    if (!string.IsNullOrEmpty(payload.RefreshToken))
    {
        await _tokens.SetRefreshTokenAsync(payload.RefreshToken);
    }

    return true; // ← Refresh succeeded, API calls can continue
}
catch
{
    return false; // ← Network error or invalid token
}
}


**Critical Points:**
- **Token Rotation**: API returns a **new** refresh token on every refresh (security best practice)
- Old refresh token is invalidated server-side
- Both access token (memory) and refresh token (secure storage) are updated
- If refresh fails, user must re-login

### AuthHandler — Automatic 401 Handling

```csharp
public class AuthHandler : DelegatingHandler { private readonly AuthService _auth; private readonly NativeTokenService _tokens;
protected override async Task<HttpResponseMessage> SendAsync(
    HttpRequestMessage request, 
    CancellationToken ct)
{
    // 1. Attach current access token to request
    if (!string.IsNullOrEmpty(_tokens.AccessToken))
    {
        request.Headers.Authorization = 
            new AuthenticationHeaderValue("Bearer", _tokens.AccessToken);
    }

    // 2. Send request
    var response = await base.SendAsync(request, ct);

    // 3. If 401, try refresh ONCE and retry original request
    if (response.StatusCode == HttpStatusCode.Unauthorized)
    {
        var refreshed = await _auth.TryRefreshAsync();
        if (refreshed && !string.IsNullOrEmpty(_tokens.AccessToken))
        {
            // Clone and retry with new token
            request.Headers.Authorization = 
                new AuthenticationHeaderValue("Bearer", _tokens.AccessToken);
            response = await base.SendAsync(request, ct);
        }
    }

    return response;
}
}


```


**Why This Pattern?**
- Transparent to ViewModels — they just call API services
- Handles token expiry gracefully without user interaction
- Only attempts refresh **once** per request to avoid infinite loops
- If refresh fails, 401 propagates and app can navigate to login

---

## Detailed Flow: Logout

### Step-by-Step Process

```csharp
// 1. User taps "Logout" in SettingsPage // 2. SettingsViewModel.LogoutCommand executes:
[RelayCommand] public async Task LogoutAsync() { if (IsBusy) return; IsBusy = true;
try
{
    // 3. Call AuthService.LogoutAsync()
    await _auth.LogoutAsync();

    // 4. Navigate to login (clears back stack)
    await MainThread.InvokeOnMainThreadAsync(async () =>
    {
        await Shell.Current.GoToAsync("//login", animate: false);
    });
}
finally
{
    IsBusy = false;
}
}

```

### AuthService.LogoutAsync() Implementation

```csharp
public async Task LogoutAsync() { // 1. Best-effort: notify API to revoke tokens server-side try { await _http.PostAsync("api/account/identity/logout", null); } catch { /* ignore network errors during logout */ }
// 2. Clear in-memory access token
_tokens.ClearAccessToken();

// 3. Clear refresh token from secure storage
await _tokens.ClearRefreshTokenAsync();
}
```


**What Happens:**
1. API revokes refresh token server-side (security)
2. Local access token cleared from memory
3. Local refresh token removed from SecureStorage
4. User navigated to `//login` route (absolute navigation clears stack)
5. Next API call will fail with 401 (expected, user logged out)

---

## Adding New Pages and ViewModels

### Pattern: Page + ViewModel Pair

Every screen should follow this structure:

WT.Maui/ ├── Views/ │   ├── TrailDetailPage.xaml         ← XAML UI definition │   └── TrailDetailPage.xaml.cs      ← Code-behind (minimal) └── ViewModels/ └── TrailDetailViewModel.cs      ← Business logic, commands, state


### Step 1: Create the ViewModel

```csharp
// WT.Maui/ViewModels/TrailDetailViewModel.cs using CommunityToolkit.Mvvm.ComponentModel; using CommunityToolkit.Mvvm.Input;
namespace WT.Maui.ViewModels { public partial class TrailDetailViewModel : BaseViewModel { private readonly HttpClient _http; private readonly INavigationService _nav; // if using custom nav service
    // Constructor injection (DI will provide these)
    public TrailDetailViewModel(HttpClient http, INavigationService nav)
    {
        _http = http;
        _nav = nav;
    }

    // Observable properties (CommunityToolkit source generator)
    [ObservableProperty]
    private string trailName = string.Empty;

    [ObservableProperty]
    private string description = string.Empty;

    // Commands
    [RelayCommand]
    private async Task LoadTrailAsync(string trailId)
    {
        IsBusy = true;
        try
        {
            var trail = await _http.GetFromJsonAsync<TrailDTO>($"api/trails/{trailId}");
            if (trail != null)
            {
                TrailName = trail.Name;
                Description = trail.Description;
            }
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private async Task GoBackAsync()
    {
        await Shell.Current.GoToAsync("..");
    }
}
}
```
### Step 2: Create the Page XAML

```xml
<!-- WT.Maui/Views/TrailDetailPage.xaml --> <?xml version="1.0" encoding="utf-8" ?> <ContentPage xmlns="http://schemas.microsoft.com/dotnet/2021/maui" xmlns:x="http://schemas.microsoft.com/winfx/2009/xaml" xmlns:vm="clr-namespace:WT.Maui.ViewModels" x:Class="WT.Maui.Views.TrailDetailPage" x:DataType="vm:TrailDetailViewModel" Title="Trail Details">
<ScrollView>
    <VerticalStackLayout Padding="20" Spacing="10">
        <Label Text="{Binding TrailName}" 
               FontSize="24" 
               FontAttributes="Bold" />
        
        <Label Text="{Binding Description}" 
               FontSize="16" />
        
        <ActivityIndicator IsRunning="{Binding IsBusy}" 
                         IsVisible="{Binding IsBusy}" />
        
        <Button Text="Go Back" 
                Command="{Binding GoBackCommand}" />
    </VerticalStackLayout>
</ScrollView>
</ContentPage>
```

### Step 3: Create the Code-Behind (Minimal)

```csharp
// WT.Maui/Views/TrailDetailPage.xaml.cs using WT.Maui.ViewModels;
namespace WT.Maui.Views;
public partial class TrailDetailPage : ContentPage { public TrailDetailPage(TrailDetailViewModel vm) { InitializeComponent(); BindingContext = vm; } }
```


**Key Points:**
- Code-behind is **minimal** — just set BindingContext
- ViewModel injected via constructor (DI resolves it)
- No business logic in code-behind

### Step 4: Register in DI (MauiProgram.cs)

```csharp
// MauiProgram.cs (in CreateMauiApp)
// ViewModel (transient — new instance per navigation) builder.Services.AddTransient<TrailDetailViewModel>();
// Page (transient — DI will inject ViewModel) builder.Services.AddTransient<TrailDetailPage>();
```

### Step 5: Register Shell Route (AppShell.xaml.cs)

```csharp
// AppShell.xaml.cs public partial class AppShell : Shell { public AppShell() { InitializeComponent();
    // Register route for navigation
    Routing.RegisterRoute("traildetail", typeof(TrailDetailPage));
}
}
```


### Step 6: Navigate to the Page

```csharp
// From another ViewModel or code-behind await Shell.Current.GoToAsync("traildetail", new Dictionary<string, object> { { "trailId", "12345" } });
// Or with query parameters await Shell.Current.GoToAsync($"traildetail?trailId=12345");

```

---

## DI Registration Patterns

### Recommended Service Lifetimes

```csharp
// Singleton — One instance for app lifetime builder.Services.AddSingleton<NativeTokenService>(); builder.Services.AddSingleton<AuthService>(); builder.Services.AddSingleton<AppShell>();
// Transient — New instance every time builder.Services.AddTransient<LoginViewModel>(); builder.Services.AddTransient<SettingsViewModel>(); builder.Services.AddTransient<TrailDetailViewModel>(); builder.Services.AddTransient<LoginPage>(); builder.Services.AddTransient<SettingsPage>(); builder.Services.AddTransient<TrailDetailPage>();
// HttpClient with message handler builder.Services.AddTransient<AuthHandler>(); builder.Services.AddHttpClient("ApiClient", client => { client.BaseAddress = new Uri("https://api.wheelytrails.com/"); client.Timeout = TimeSpan.FromSeconds(30); }) .AddHttpMessageHandler<AuthHandler>();
// Convenience: Resolve named HttpClient builder.Services.AddTransient(sp => sp.GetRequiredService<IHttpClientFactory>().CreateClient("ApiClient"));

```


### When to Use Each Lifetime

| Lifetime | Use For | Example |
|----------|---------|---------|
| **Singleton** | App-wide state, long-lived services | `AuthService`, `NativeTokenService`, `AppShell` |
| **Transient** | Pages, ViewModels, per-request services | `LoginPage`, `LoginViewModel`, `HttpClient` |
| **Scoped** | Not applicable in MAUI (no request scope) | N/A |

---

## Navigation Best Practices

### Use Shell Routes (Recommended)

// ✅ GOOD: DI-aware navigation await Shell.Current.GoToAsync("traildetail");
// ✅ GOOD: Absolute route (clears back stack) await Shell.Current.GoToAsync("//login", animate: false);
// ✅ GOOD: Relative navigation (back) await Shell.Current.GoToAsync("..");
// ❌ AVOID: Direct page construction var page = new TrailDetailPage(); // ← ViewModel not injected! await Navigation.PushAsync(page);
// ❌ AVOID: Direct MainPage replacement Application.Current.MainPage = new LoginPage(); // ← Breaks Shell navigation


### Route Registration Patterns
```csharp
// AppShell.xaml.cs public AppShell() { InitializeComponent();
// Simple routes
Routing.RegisterRoute("login", typeof(LoginPage));
Routing.RegisterRoute("settings", typeof(SettingsPage));

// Detail/child routes
Routing.RegisterRoute("traildetail", typeof(TrailDetailPage));
Routing.RegisterRoute("traileditor", typeof(TrailEditorPage));
}
```


### Passing Parameters

```csharp
// Option 1: Query parameters (simple types) await Shell.Current.GoToAsync($"traildetail?trailId=12345&mode=edit");
// ViewModel receives via [QueryProperty] [QueryProperty(nameof(TrailId), "trailId")] [QueryProperty(nameof(Mode), "mode")] public partial class TrailDetailViewModel : BaseViewModel { [ObservableProperty] private string trailId = string.Empty;
[ObservableProperty]
private string mode = string.Empty;
}
// Option 2: Navigation dictionary (complex objects) await Shell.Current.GoToAsync("traildetail", new Dictionary<string, object> { { "trail", trailObject } });
// ViewModel receives via [QueryProperty] [QueryProperty(nameof(Trail), "trail")] public partial class TrailDetailViewModel : BaseViewModel { [ObservableProperty] private Trail? trail; }
```


---

## Troubleshooting

### Common Issues

#### 1. "The name 'InitializeComponent' does not exist"
**Cause:** XAML file not set to `MauiXaml` build action or namespace mismatch

**Fix:**
- Right-click XAML file → Properties → Build Action = `MauiXaml`
- Ensure `x:Class` matches code-behind namespace exactly
- Clean and rebuild solution

#### 2. "No argument given for required parameter 'vm'"
**Cause:** Page constructed with `new` instead of DI

**Fix:**

// ❌ WRONG var page = new LoginPage();
// ✅ RIGHT (via Shell route) await Shell.Current.GoToAsync("login");
// ✅ RIGHT (manual DI resolve) var page = serviceProvider.GetRequiredService<LoginPage>();


#### 3. "Shell.Current is null"
**Cause:** Trying to navigate before Window is created

**Fix:**

```csharp
// App.xaml.cs protected override Window CreateWindow(IActivationState? activationState) { var window = new Window(new AppShell());
// ✅ Perform navigation AFTER window exists
MainThread.BeginInvokeOnMainThread(async () =>
{
    await Task.Delay(100); // Let Shell initialize
    
    if (_auth.IsLoggedIn || await _auth.RestoreSessionAsync())
        await Shell.Current.GoToAsync("//HomePage");
    else
        await Shell.Current.GoToAsync("//login");
});

return window;
}

```


#### 4. Token Refresh Fails on Startup
**Cause:** API endpoint mismatch or expired refresh token

**Diagnostic:**

```csharp
public async Task<bool> RestoreSessionAsync() { if (IsLoggedIn) return true;
var refresh = await _tokens.GetRefreshTokenAsync();
if (string.IsNullOrEmpty(refresh))
{
    Console.WriteLine("⚠️ No refresh token found in SecureStorage");
    return false;
}

Console.WriteLine($"🔄 Attempting refresh with token: {refresh[..8]}...");
var result = await TryRefreshAsync();
Console.WriteLine($"Refresh result: {result}");
return result;
}
```


#### 5. HttpClient DI Error "ValueFactory attempted to access..."
**Cause:** Creating HttpClient singleton at registration time

**Fix:**

// ❌ WRONG (forces immediate factory resolution) builder.Services.AddSingleton(sp => sp.GetRequiredService<IHttpClientFactory>().CreateClient("ApiClient"));
// ✅ RIGHT (creates client per resolve) builder.Services.AddTransient(sp => sp.GetRequiredService<IHttpClientFactory>().CreateClient("ApiClient"));


---

## Quick Reference: Complete Authentication Checklist

### ✅ Initial Setup (Done Once)
- [ ] `NativeTokenService` registered as Singleton
- [ ] `AuthService` registered as Singleton
- [ ] `AuthHandler` registered as Transient
- [ ] HttpClient configured with `AuthHandler` message handler
- [ ] Login route registered in `AppShell`: `Routing.RegisterRoute("login", typeof(LoginPage))`
- [ ] HomePage route registered: `Routing.RegisterRoute("HomePage", typeof(HomePage))`

### ✅ Login Flow
- [ ] `LoginViewModel` calls `AuthService.LoginAsync(LoginDTO)`
- [ ] `AuthService` stores access token in memory via `NativeTokenService.SetAccessToken()`
- [ ] `AuthService` persists refresh token via `NativeTokenService.SetRefreshTokenAsync()`
- [ ] Navigate to `//HomePage` on success

### ✅ Token Refresh
- [ ] `AuthHandler` attaches access token to all outgoing requests
- [ ] `AuthHandler` detects 401 and calls `AuthService.TryRefreshAsync()`
- [ ] `TryRefreshAsync()` uses stored refresh token to get new access token
- [ ] Both tokens updated (access in memory, refresh in SecureStorage)

### ✅ Logout Flow
- [ ] `SettingsViewModel` calls `AuthService.LogoutAsync()`
- [ ] `AuthService` calls API logout endpoint (best-effort)
- [ ] `AuthService` clears access token (memory) and refresh token (secure storage)
- [ ] Navigate to `//login` to clear navigation stack

### ✅ New Page/ViewModel
- [ ] Create ViewModel in `ViewModels/` inheriting `BaseViewModel`
- [ ] Use `[ObservableProperty]` for bindable properties
- [ ] Use `[RelayCommand]` for commands
- [ ] Create Page XAML in `Views/`
- [ ] Create minimal code-behind accepting ViewModel via constructor
- [ ] Register both in DI as `Transient`
- [ ] Register Shell route in `AppShell.xaml.cs`
- [ ] Navigate using `Shell.Current.GoToAsync("route")`

---

## Summary

**Token Management:**
- Access tokens: **In-memory** (fast, cleared on restart) via `NativeTokenService._accessToken`
- Refresh tokens: **Secure Storage** (persistent, survives restart) via `SecureStorage.Default`

**Key Services:**
- `NativeTokenService`: Storage manager for tokens
- `AuthService`: Orchestrates login/logout/refresh operations
- `AuthHandler`: Automatic 401 handling and token refresh

**Navigation:**
- Use Shell routes: `await Shell.Current.GoToAsync("route")`
- Register Pages/ViewModels in DI as `Transient`
- Register routes in `AppShell` constructor
- Avoid direct `new Page()` or `MainPage` assignment

**Adding Pages:**
1. Create ViewModel (inherits `BaseViewModel`, uses CommunityToolkit attributes)
2. Create Page XAML with `x:DataType` binding
3. Create minimal code-behind with constructor injection
4. Register both in DI
5. Register Shell route
6. Navigate via `GoToAsync()`

---

**Last Updated:** 2025-01-16  
**Project:** WheelyTrails MAUI Client  
**Architecture:** Clean Architecture + MVVM + Shell Navigation + Secure Token Storage