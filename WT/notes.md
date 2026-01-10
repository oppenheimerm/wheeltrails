## Google Maps API Key — Runtime config (Implemented)

This project uses a simple, low-friction runtime-config approach so developers can keep local keys out of source control while CI injects the production key into the published artifact automatically.

Why this approach
- Browser-loaded Google Maps keys are public by design. Storing them in source is risky.
- This approach requires one small, one-time local setup per developer and one automatic CI step on deployment. No per-deploy manual work required.
- CI writes the production key into the published `wwwroot` only. Your local dev key stays uncommitted.

What was changed
- `WT/WT.Client/wwwroot/index.html` now loads `js/config.js` and creates the Maps <script> at runtime from `window.__WT_CONFIG__.GOOGLE_MAPS_API_KEY`.
- `WT/WT.Client/wwwroot/js/config.example.js` was added as a template for developers.
- `WT/WT.Client/.gitignore` updated to ignore `WT.Client/wwwroot/js/config.js` (local untracked file).
- Repository workflow `.github/workflows/deploy.yml` now generates `wwwroot/js/config.js` in the published output using the `GOOGLE_MAPS_API_KEY` secret.

Local developer setup (one-time)
1. Copy the example to create a local config (do NOT commit):
 - PowerShell:
 ```powershell
 Copy-Item WT/WT.Client/wwwroot/js/config.example.js WT/WT.Client/wwwroot/js/config.js
 notepad WT/WT.Client/wwwroot/js/config.js
 # replace '__GOOGLE_MAPS_API_KEY__' with your local key
 ```
 - Bash:
 ```bash
 cp WT/WT.Client/wwwroot/js/config.example.js WT/WT.Client/wwwroot/js/config.js
 sed -i "s/__GOOGLE_MAPS_API_KEY__/YOUR_LOCAL_KEY/" WT/WT.Client/wwwroot/js/config.js
 ```
2. Confirm `WT/WT.Client/wwwroot/js/config.js` is listed in `WT/WT.Client/.gitignore` so it won't be committed.
3. Run the client for local dev as before: `dotnet run --project WT/WT.Client` or run the full solution. The app will load the Maps script using your local key.

CI / Production deployment
1. Add the production Maps key to the repository Secrets:
 - Repository ? Settings ? Secrets and variables ? Actions ? New repository secret
 - Name: `GOOGLE_MAPS_API_KEY`
 - Value: (your production Maps API key)
2. The workflow `.github/workflows/deploy.yml` will:
 - `dotnet publish` the client project
 - create `WT/WT.Client/bin/Release/net9.0/publish/wwwroot/js/config.js` containing:
 ```js
 window.__WT_CONFIG__ = { GOOGLE_MAPS_API_KEY: "<your-secret>" };
 ```
 - upload the entire `publish/wwwroot` to Cloudflare Pages
3. No source files are changed by CI; the secret exists only in the publish artifact.

How to test the CI injection
- Trigger a run (push to `main` or use the Actions UI `Run workflow` for `workflow_dispatch`).
- In the Actions run logs, confirm the step `Create runtime config with Google Maps API Key in publish output` prints `Wrote runtime config to .../wwwroot/js/config.js`.
- After deployment, open the site and verify maps load. You can also inspect the published `js/config.js` file via the site or by downloading the published artifact from the workflow run (if needed).

Security notes
- Google Maps JS API keys are public to the browser. Restrict the key in Google Cloud Console by HTTP referrers (add exact allowed domains, including protocol and any hostnames).
- Use separate keys for local dev, staging, and production and rotate keys if they are exposed.
- Never commit secrets to source control.

If you want, I can also:
- Add a short smoke-test step in the workflow that checks `js/config.js` exists in the publish folder and prints a masked confirmation (it will not print the secret).
- Add a one-line PowerShell helper script under `scripts/` to help new devs create `js/config.js` from the example.

---

(End of Google Maps runtime config documentation)

# Custom Subdomain for Cross-Origin Cookie Support (Implemented - Jan 2025)

## Problem Statement

**Issue:** Login worked in production, but users were logged out after page reload.

**Root Cause:** Modern browsers block third-party cookies by default. When the client (`https://wheelytrails.com`) and API (`https://wheelytrails-api-...azurewebsites.net`) are on different domains, the browser treats refresh cookies as "third-party" and refuses to send them on subsequent requests.

**Symptoms:**
- ? Login successful (cookie set)
- ? After reload: `POST /api/account/identity/refresh-token` returns `204 No Content`
- ? Reason: Browser doesn't send `Cookie: refreshToken=...` header
- ? User forced to re-login on every page refresh

**Why localhost worked:** Both client and API were on `localhost` domain (same-origin), so cookies worked normally.

## Solution: Custom Subdomain with Shared Cookie Domain

### Architecture Change

**Before:**
```
Client:  https://wheelytrails.com (Cloudflare Pages)
API:     https://wheelytrails-api-d9gbhufjbug7hsee.westeurope-01.azurewebsites.net (Azure)
Result:  ? Different domains = Third-party cookie blocking
```

**After:**
```
Client:  https://wheelytrails.com (Cloudflare Pages)
API:     https://api.wheelytrails.com ? wheelytrails-api-...azurewebsites.net (Azure)
Cookie:  Domain=.wheelytrails.com (shared across subdomains)
Result:  ? Same parent domain = Cookies work!
```

### Implementation Steps

#### 1. DNS Configuration (Cloudflare)

Added two DNS records in Cloudflare dashboard:

**CNAME Record:**
```
Type: CNAME
Name: api
Target: wheelytrails-api-d9gbhufjbug7hsee.westeurope-01.azurewebsites.net
Proxy status: DNS only (gray cloud)
TTL: Auto
```

**TXT Record (Azure verification):**
```
Type: TXT
Name: asuid.api
Content: <Azure Custom Domain Verification ID>
TTL: Auto
```

#### 2. Azure App Service Configuration

1. **Custom Domain Setup:**
   - Azure Portal ? App Service ? Settings ? Custom domains
   - Added custom domain: `api.wheelytrails.com`
   - Validation method: DNS (TXT record)
   - Status: ? Validated

2. **SSL Certificate:**
   - Type: SNI SSL (Server Name Indication)
   - Certificate: App Service Managed Certificate (Free)
   - Status: ? Secured

#### 3. Code Changes

**File: `WT.Client/wwwroot/appsettings.Production.json`**
```json
{
  "ConnectionStrings": {
    "BaseApiUrl": "https://api.wheelytrails.com"
  }
}
```
*Changed from: `https://wheelytrails-api-d9gbhufjbug7hsee.westeurope-01.azurewebsites.net`*

**File: `API/Controllers/AccountController.cs` - `SetTokenCookie()` method**
```csharp
private void SetTokenCookie(string token)
{
    var isHttps = Request.IsHttps;

    var cookieOptions = new CookieOptions
    {
        HttpOnly = true,
        Secure = isHttps,
        SameSite = isHttps ? SameSiteMode.None : SameSiteMode.Lax,
        Expires = DateTime.UtcNow.AddDays(7),
        Path = "/"
    };

    // ? NEW: Set cookie domain for production
    var env = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT");
    
    if (!string.Equals(env, "Development", StringComparison.OrdinalIgnoreCase))
    {
        cookieOptions.Domain = ".wheelytrails.com"; // ? Added this
    }

    Response.Cookies.Append("refreshToken", token, cookieOptions);
}
```

**Key Points:**
- `Domain=.wheelytrails.com` (note the leading dot) shares cookie across:
  - `wheelytrails.com`
  - `api.wheelytrails.com`
  - `www.wheelytrails.com` (if used)
- Only applied in production (not Development)
- Requires `SameSite=None` and `Secure=true` for cross-subdomain cookies

### How It Works

#### Login Flow:
1. User logs in at `https://wheelytrails.com`
2. Client calls `https://api.wheelytrails.com/api/account/identity/login` via JS fetch with `credentials: 'include'`
3. API validates credentials and returns JWT in response body
4. API sets HttpOnly cookie: `Set-Cookie: refreshToken=...; Domain=.wheelytrails.com; HttpOnly; Secure; SameSite=None; Path=/`
5. Browser stores cookie for `.wheelytrails.com` domain

#### Refresh Flow (after reload):
1. Page reloads, in-memory JWT is lost
2. `CustomAuthenticationStateProvider` calls `wtApi.fetchRefreshToken()` 
3. JS fetch to `https://api.wheelytrails.com/api/account/identity/refresh-token` with `credentials: 'include'`
4. **Browser automatically sends `Cookie: refreshToken=...`** (because `api.wheelytrails.com` matches `.wheelytrails.com` domain)
5. API validates refresh token, rotates it, returns new JWT
6. User stays logged in! ?

### Browser Cookie Policy Compliance

Modern browsers require:
- ? **HTTPS on both client and API** (no mixed content)
- ? **`Secure=true`** flag on cookies
- ? **`SameSite=None`** for cross-subdomain cookies
- ? **Same parent domain** (e.g., `.wheelytrails.com`)

This implementation satisfies all requirements while maintaining security best practices.

### Security Considerations

**Why HttpOnly cookies are secure:**
- JavaScript cannot access `HttpOnly` cookies (prevents XSS attacks)
- Refresh tokens never stored in `localStorage` (XSS-proof)
- Access tokens (JWT) kept in-memory only (cleared on tab close)
- Cookie rotation on every refresh (prevents token reuse)

**Additional protections:**
- CORS policy restricts origins to `wheelytrails.com` and `www.wheelytrails.com`
- Refresh tokens revoked on logout and password reset
- 7-day refresh token expiry (configurable)
- 30-minute JWT expiry (short-lived)

### Testing Checklist

- [x] DNS propagation verified (`nslookup api.wheelytrails.com`)
- [x] SSL certificate active and valid
- [x] Login sets cookie with correct domain
- [x] Page reload maintains authentication
- [x] Cookie visible in DevTools under `api.wheelytrails.com` domain
- [x] Logout clears cookie properly
- [x] Works in Chrome, Edge, Safari, Firefox

### Troubleshooting Guide

**If login doesn't persist after reload:**

1. **Check DNS propagation:**
   ```sh
   nslookng api.wheelytrails.com
   # Should return: wheelytrails-api-...azurewebsites.net
   ```

2. **Verify cookie is set on login:**
   - DevTools ? Application ? Cookies ? `https://api.wheelytrails.com`
   - Should see: `refreshToken` with `HttpOnly`, `Secure`, `Domain=.wheelytrails.com`

3. **Check refresh request includes cookie:**
   - DevTools ? Network ? Find `refresh-token` request
- Request Headers should include: `Cookie: refreshToken=...`

4. **Verify API receives cookie:**
   - Check API logs for: `SetTokenCookie: Domain=.wheelytrails.com`
   - If cookie not received, check CORS configuration

5. **Common issues:**
   - Browser in "Block third-party cookies" mode (should work with same parent domain)
   - Mixed content (HTTP/HTTPS mismatch)
   - DNS not propagated (wait 5-30 minutes)
   - Cookie domain misconfigured (check for leading dot: `.wheelytrails.com`)

### Performance & Costs

- **DNS lookup**: Minimal overhead (~1-2ms)
- **Azure Custom Domain**: Free (included with App Service)
- **SSL Certificate**: Free (App Service Managed Certificate)
- **Cloudflare DNS**: Free tier sufficient

### Further Reading

- [MDN: SameSite Cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite)
- [MDN: Cookie Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#security)
- [Azure Custom Domains](https://learn.microsoft.com/en-us/azure/app-service/app-service-web-tutorial-custom-domain)
- [Cloudflare DNS Setup](https://developers.cloudflare.com/dns/manage-dns-records/how-to/create-dns-records/)
- [Chrome Third-Party Cookie Phase-Out](https://developers.google.com/privacy-sandbox/3pcd)
- [IETF RFC 6265 - HTTP State Management (Cookies)](https://datatracker.ietf.org/doc/html/rfc6265)

### Maintenance Notes

**When adding new subdomains:**
- Cookies will automatically work with any `*.wheelytrails.com` subdomain
- Example: `app.wheelytrails.com`, `admin.wheelytrails.com`, etc.

**When changing domains:**
- Update `cookieOptions.Domain` in `SetTokenCookie()`
- Update DNS CNAME records
- Update Azure custom domain configuration
- Update `appsettings.Production.json`

**Monitoring:**
- Watch for `204 No Content` responses on `/refresh-token` (indicates cookie not sent)
- Monitor auth failure rates in Application Insights
- Check SSL certificate renewal (auto-renews 30 days before expiry)

---

(End of Custom Subdomain documentation)

# Authentication & Token Flow (Detailed)

This document describes the login, refresh, and logout flow used by WheelyTrails and explains how `WT.Client.Services.TokenService` fits into the overall design. It is intended for developers and operators who need a clear, step-by-step reference for authentication behavior, debugging, and secure deployment.

## Goals
- Keep access tokens (JWT) out of persistent browser storage to reduce XSS risk.
- Use HttpOnly cookies for refresh tokens so they are not accessible to JavaScript.
- Provide a reliable mechanism to rehydrate client auth state after full page reloads.
- Ensure refresh token rotation and revocation are implemented server-side.

## Actors
- Client: Blazor WebAssembly app (`WT.Client`)
- API: ASP.NET Core Web API (`API`)
- TokenService: `WT.Client.Services.TokenService` (in-memory store)
- AuthenticationStateProvider: `CustomAuthenticationStateProvider` (manages Blazor auth state)
- JS helper: `wtApi.fetchRefreshToken` & `wtApi.login` in `WT.Client/wwwroot/js/fetchRefresh.js`

---

## Login Sequence (detailed)

1. User submits credentials in the Blazor login page.
2. Client calls `AccountService.LoginAsync(model)`.
 - If running in WASM with `IJSRuntime` available, `AccountService` uses the JS helper `wtApi.login(loginUrl, payload)` which performs a `fetch` with `credentials: 'include'`.
 - If JS runtime is not available, `AccountService` falls back to `HttpClient.PostAsJsonAsync`.
3. API validates credentials in `WTAccount.LoginWithIpAsync`.
4. On success the API:
 - Issues a short-lived JWT (expires in ~30 min).
 - Creates a refresh token (7-day TTL), saves it in the DB associated to the user, and returns it in the API response DTO.
 - Calls `SetTokenCookie(refreshToken)` to set an HttpOnly cookie named `refreshToken` with flags: `HttpOnly`, `Secure`, `SameSite=None`, `Path=/`, and **`Domain=.wheelytrails.com`** (in production).
 - Returns an `APIResponseAuthentication` containing the JWT in the response body (and user info).
5. Client receives the response. `AccountService` does the following:
 - Sets `HttpClient.DefaultRequestHeaders.Authorization = Bearer {jwt}` for immediate API calls.
 - Sets the in-memory `TokenService` via `TokenService.SetAccessToken(jwt, expiresAt)` so the app keeps the access token in-memory for the current browsing session.
 - Persists a small `AuthenticatedSessionDTO` and a `HasSession` boolean flag in `localStorage` so UI can render basic info after reload. **Critically, the JWT and refresh token are NOT stored in localStorage**.

## Cold start / Page reload (rehydration) sequence

1. Blazor WASM starts and `CustomAuthenticationStateProvider.GetAuthenticationStateAsync()` runs.
2. Provider checks `TokenService.AccessToken`. If token exists and is valid, build ClaimsPrincipal and return authenticated state.
3. If no in-memory token, provider checks `localStorage` for the `HasSession` flag. If absent/false, return anonymous state (no refresh attempt).
4. If `HasSession` is true, provider will attempt a credentialed refresh to obtain a new access token:
 - Prefer `IJSRuntime.InvokeAsync<string>("wtApi.fetchRefreshToken", refreshUrl)` which runs fetch with `credentials: 'include'`. This ensures the browser sends the HttpOnly `refreshToken` cookie to the API (**now works because both are under `.wheelytrails.com` domain**).
 - If JS helper fails or runtime is unavailable, fall back to `HttpClient.PostAsync("api/account/identity/refresh-token", null)` (may not include cookie in some environments).
5. API's `RefreshToken` endpoint reads the `refreshToken` cookie from `Request.Cookies["refreshToken"]`. If missing, returns 204 No Content. If present, server validates and rotates the token using `WTAccount.RefreshTokenWithIpAsync`:
 - If valid: generate new JWT, rotate refresh token, persist changes, call `SetTokenCookie(newRefreshToken)` to rotate cookie, and return `APIResponseAuthentication` with new JWT.
 - If invalid: return BadRequest/NoContent as appropriate.
6. Client receives JWT, sets `TokenService.SetAccessToken(jwt, expiresAt)`, builds ClaimsPrincipal, and the app moves to authenticated state.

## Token rotation & security
- Each refresh call rotates the refresh token: old token is revoked and the new token is persisted in DB and set in the HttpOnly cookie. This prevents reuse of leaked tokens.
- On sensitive events (password reset, explicit logout), the server revokes refresh tokens and clears cookie.
- **Cookie domain sharing** (`.wheelytrails.com`) enables same-site cookie policy while maintaining cross-subdomain authentication.

## Logout
- Client calls `POST /api/account/identity/logout`.
- Server revokes refresh tokens server-side (best-effort) and instructs browser to delete `refreshToken` cookie via `Response.Cookies.Delete("refreshToken")`.
- Client clears in-memory `TokenService.Clear()` and removes `HasSession` and session DTO from localStorage.

## WT.Client.Services.TokenService role
- `TokenService` is a singleton in WASM and stores only the current access token and expiry in memory.
- API surface:
 - `string? AccessToken { get; }`
 - `void SetAccessToken(string token, DateTime expiry)`
 - `void Clear()`
 - `bool IsExpired()`
 - `event Action? TokenChanged`
- Never persists to `localStorage` or any browser storage
- Cleared automatically when tab/browser closes
- Used by `CustomAuthenticationStateProvider` to maintain auth state during current session

---

(End of Authentication documentation)
