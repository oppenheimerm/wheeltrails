WT.Admin — Admin UI conventions and deployment checklist

Purpose
-------
This document describes the conventions for the WT.Admin project and the small, intentional exception used for authentication.

Conventions
-----------
- `Pages/`
  - Server-only endpoints that require a traditional HTTP GET/POST lifecycle (antiforgery token, browser form POST, server-issued cookies).
  - Examples: `Pages/Account/Login.cshtml` — the login page is a Razor Page intentionally. It renders an antiforgery token and enables the Admin host to issue an HttpOnly authentication cookie.

- `Components/` (or `Components/Pages/`)
  - Blazor interactive UI (`.razor`) used by the Admin panel. All interactive pages, dashboards and management UI belong here.
  - Use Blazor layouts (e.g., `Components/Layout/AuthLayout.razor`, `MainLayout.razor`) for consistent UI.

Why the login is a Razor Page
----------------------------
- A browser stores HttpOnly cookies only when the Set-Cookie header is present in an HTTP response the browser receives. A Blazor Server `EditForm` submits over SignalR and server-side HttpClient calls do not cause the browser to receive Set-Cookie from remote endpoints.
- The Razor Page login is the simplest, reliable adapter: browser GET -> Razor Page renders antiforgery token -> browser POST -> server calls API, stores tokens server-side (or issues cookie) and calls `HttpContext.SignInAsync` so the browser receives a cookie.
- This is a small, well-documented exception to the general component-first rule and avoids fragile CORS/cookie pitfalls.

Deployment checklist
--------------------
- HTTPS
  - Always serve Admin over HTTPS in production. Cookie `Secure` must be true.

- Antiforgery
  - Ensure `builder.Services.AddAntiforgery()` and `app.UseAntiforgery()` are configured and that Razor Pages which render antiforgery tokens are mapped.

- IHttpContextAccessor
  - Register `builder.Services.AddHttpContextAccessor()` if server code needs HttpContext for antiforgery/token flows.

- Cookie settings
  - For production, set `Cookie.Secure = Always` and configure `SameSite` appropriately:
    - If Admin and API are same origin: `SameSite=Lax` is often sufficient for top-level form POSTs.
    - If API and Admin are on different subdomains and you need cross-site credentials, use `SameSite=None; Secure; Domain=.yourdomain.com` and ensure CORS allows credentials.
  - Keep cookies HttpOnly where appropriate (especially refresh cookies).

- CORS and credentials (when browser posts directly to API)
  - If any UI must POST directly to the API and rely on API Set-Cookie, the API must enable CORS with credentials:
    - `builder.Services.AddCors(...)` with `AllowCredentials()` and allowed origin(s)
    - `app.UseCors(...)` configured before endpoints
  - Prefer the server-side adapter (Razor Page login or Admin endpoint) to avoid cross-origin cookie complexity.

- Token storage & refresh
  - For Admin (Blazor Server) keep tokens server-side (e.g., `IServerTokenService` scoped per user). Attach access tokens from server when calling API.
  - For WASM (WT.Client) use access-in-memory + HttpOnly refresh cookie on API; reuse API refresh endpoints and rotation.

Server token management (IServerTokenService)
-------------------------------------------
WT.Admin includes a server-scoped token manager (`IServerTokenService` / `ServerTokenService`) that stores the
API access token (JWT) and a refresh token for the currently signed-in admin user. Key responsibilities:

- Store access and refresh tokens in a scoped, in-memory service (per Blazor Server circuit or request).
- Expose `AccessToken`, `RefreshToken`, and `ExpiresAt` for outgoing server-side API calls.
- Provide `SetTokens(accessToken, refreshToken, expiresAt)` to populate tokens after a successful API login.
- Provide `TryRefreshAsync(IHttpClientFactory)` which calls the API refresh endpoint and updates tokens on success.
- Raise a `TokenChanged` event when token values change so registered consumers can update their state.

Usage example (set tokens after login):

```csharp
// After successful API login and parsing APIResponseAuthentication
var serverTokenService = httpContext.RequestServices.GetRequiredService<IServerTokenService>();
var expiresAt = DateTime.UtcNow.AddMinutes(30); // compute from token or API response
serverTokenService.SetTokens(apiResponse.JwtToken, apiResponse.RefreshToken, expiresAt);
```

Behavioral notes
- The default implementation stores tokens in-memory; for multi-node deployments consider backing with a distributed cache (Redis) or DB.
- `TryRefreshAsync` expects the API to return an `APIResponseAuthentication` with `JwtToken` and optionally a rotated `RefreshToken`.

Bearer token handler (BearerTokenHandler)
----------------------------------------
`BearerTokenHandler` is a DelegatingHandler that is added to the named `ApiClient` HttpClient used for API calls.
Its responsibilities:

- Attach the current access token (from `IServerTokenService.AccessToken`) to outgoing requests as `Authorization: Bearer <token>`.
- When a response returns `401 Unauthorized`, it calls `IServerTokenService.TryRefreshAsync(...)` to attempt a token refresh.
- If refresh succeeds it clones the original request, attaches the new token and retries once.

Registration example (Program.cs):

```csharp
builder.Services.AddScoped<IServerTokenService, ServerTokenService>();
builder.Services.AddTransient<BearerTokenHandler>();

builder.Services.AddHttpClient("ApiClient", client =>
{
    client.BaseAddress = new Uri(configuration["ConnectionStrings:BaseApiUrl"]);
}).AddHttpMessageHandler<BearerTokenHandler>();
```

Notes and best practices
- The handler retries once after a successful refresh to avoid refresh storms.
- Log refresh failures and consider forcing user sign-out when refresh fails repeatedly.
- Keep refresh tokens secure; do not expose them to the browser.

Integration with login flow
---------------------------
- The Razor Page login handler (or Admin controller) should call `IServerTokenService.SetTokens(...)` after a successful API login so subsequent server-side API calls use the access token.
- Example in a Razor Page POST handler:

```csharp
var tokenService = HttpContext.RequestServices.GetRequiredService<IServerTokenService>();
tokenService.SetTokens(authResult.JwtToken, authResult.RefreshToken, expiresAt);
await HttpContext.SignInAsync(...); // create admin cookie
```

This keeps tokens server-side and allows the Blazor Server UI to remain authenticated via the server cookie while API calls use JWT bearer tokens attached by `BearerTokenHandler`.

Logging & secrets
----------------
- Use user-secrets for local JWT keys and connection strings. Do not commit secrets.
- Log errors with the `LogException` utility and avoid logging sensitive tokens/passwords.

Notes & alternatives
--------------------
- If you prefer a single token model across Admin + Client, convert Admin to JWT-based flow. That requires changes to how Blazor Server authenticates (SignalR/bearer or server token handling) and implementing secure refresh/rotation server-side — it is a larger refactor.

Contact
-------
If you want, I can: (A) add a short integration test that verifies login POST → cookie is set, (B) add `package.json`/`npm` scripts to build Tailwind output, or (C) produce a migration plan to convert Admin to JWT-only.
