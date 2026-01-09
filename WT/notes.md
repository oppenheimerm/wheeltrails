
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
 - Calls `SetTokenCookie(refreshToken)` to set an HttpOnly cookie named `refreshToken` with flags: `HttpOnly`, `Secure`, `SameSite=None`, `Path=/`.
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
 - Prefer `IJSRuntime.InvokeAsync<string>("wtApi.fetchRefreshToken", refreshUrl)` which runs fetch with `credentials: 'include'`. This ensures the browser sends the HttpOnly `refreshToken` cookie to the API, even across origins.
 - If JS helper fails or runtime is unavailable, fall back to `HttpClient.PostAsync("api/account/identity/refresh-token", null)` (may not include cookie in some environments).
5. API's `RefreshToken` endpoint reads the `refreshToken` cookie from `Request.Cookies["refreshToken"]`. If missing, returns204 No Content. If present, server validates and rotates the token using `WTAccount.RefreshTokenWithIpAsync`:
 - If valid: generate new JWT, rotate refresh token, persist changes, call `SetTokenCookie(newRefreshToken)` to rotate cookie, and return `APIResponseAuthentication` with new JWT.
 - If invalid: return BadRequest/NoContent as appropriate.
6. Client receives JWT, sets `TokenService.SetAccessToken(jwt, expiresAt)`, builds ClaimsPrincipal, and the app moves to authenticated state.

## Token rotation & security
- Each refresh call rotates the refresh token: old token is revoked and the new token is persisted in DB and set in the HttpOnly cookie. This prevents reuse of leaked tokens.
- On sensitive events (password reset, explicit logout), the server revokes refresh tokens and clears cookie.

## Logout
- Client calls `POST /api/account/identity/logout`.
- Server revokes refresh tokens server-side (best-effort) and instructs browser to delete `refreshToken` cookie via `Response.Cookies.Delete("refreshToken")`.
- Client clears in-memory `TokenService.Clear()` and removes `HasSession` and session DTO from localStorage.

## WT.Client.Services.TokenService role
- `TokenService` is a singleton in WASM and stores only the current access token and expiry in memory.
- API surface:
 - `string? AccessToken { get; }`
 - `void SetAccessToken(string token, DateTime expiry
