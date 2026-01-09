/*
 * wtApi.fetchRefreshToken / wtApi.login
 * ------------------------------------
 * Lightweight JS helper used by the Blazor WebAssembly client to perform
 * credentialed fetches that include browser cookies (HttpOnly refresh token).
 *
 * Purpose
 * - Provide a small, reliable way for the WASM client to call API endpoints
 * that require the browser to send HttpOnly cookies (refresh token) using
 * `fetch(..., credentials: 'include')`.
 * - Avoid depending on HttpClient behavior which may not send cookies across
 * origins in some hosting scenarios. This helper is the preferred path in
 * `AccountService` and `CustomAuthenticationStateProvider` when `IJSRuntime`
 * is available.
 *
 * Files
 * - Location: `WT.Client/wwwroot/js/fetchRefresh.js`
 *
 * API
 * - `wtApi.fetchRefreshToken(url?)`
 * Performs a `POST` to the refresh endpoint and returns the response body
 * string (JSON) or `null` when there is no content or on error.
 * - `url` (optional): absolute or relative URL. Default: `/api/account/identity/refresh-token`.
 * - Returns: `string | null` (JSON text from server) — caller should `JSON.parse` or
 * otherwise deserialize to the expected DTO.
 *
 * - `wtApi.login(url, payload)`
 * Performs a `POST` to the login endpoint with credentials included so the
 * server can set the HttpOnly refresh cookie. Returns a JSON string containing
 * `{ status, body }` where `status` is the HTTP status code and `body` is the
 * raw response text from the server.
 * - `url` (required): absolute or relative URL to the login endpoint.
 * - `payload` (required): JavaScript object to be serialized to JSON.
 * - Returns: `string` containing a JSON object with `status` and `body`.
 *
 * Usage examples
 * - Refresh on startup (Blazor WASM):
 * const json = await DotNet.invokeMethodAsync('WT.Client', 'FetchRefreshToken', apiUrl);
 * // or via IJSRuntime: jsRuntime.InvokeAsync<string>("wtApi.fetchRefreshToken")
 *
 * - Login (ensures refresh cookie is set by server):
 * const jsResponse = await jsRuntime.InvokeAsync<string>("wtApi.login", loginUrl, credentials);
 * // parse jsResponse (JSON string) -> { status, body }
 *
 * Security notes
 * - The helper specifically uses `credentials: 'include'` to ensure cookies are
 * sent and received by the browser. This is necessary for HttpOnly refresh
 * cookie flows but requires correct CORS configuration on the API:
 * - `AllowCredentials()` must be enabled and the client origin must be
 * allowed via `WithOrigins(...)`.
 * - The refresh cookie must be set with: `HttpOnly = true`, `Secure = true`,
 * `SameSite = None` when using cross-origin requests.
 * - Do NOT expose tokens in console logs in production. The helper logs only
 * errors to console for troubleshooting.
 *
 * Troubleshooting
 * - If refresh does not work after a reload:
 *1. Inspect the login response for `Set-Cookie: refreshToken=...; HttpOnly; SameSite=None; Secure`.
 *2. On reload, inspect the request to `/api/account/identity/refresh-token` — it must include
 * the `Cookie: refreshToken=...` header.
 *3. If the cookie is not sent, confirm CORS and that `fetch(..., credentials: 'include')` is being used.
 *4. Server-side diagnostic log added to `RefreshToken` endpoint records whether the cookie arrived.
 */

window.wtApi = {
    /**
     * Performs a fetch to the refresh endpoint with credentials included and returns JSON string.
     * If `url` is provided it will be used as absolute endpoint (useful in WASM when API is on another origin).
     *
     * @param {string} [url] - Optional absolute or relative URL to the refresh endpoint.
     * @returns {Promise<string|null>} JSON string from the server or null on204/no-content or error.
     */
    fetchRefreshToken: async function (url) {
        try {
            const endpoint = url || '/api/account/identity/refresh-token';
            const resp = await fetch(endpoint, {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Accept': 'application/json'
                }
            });

            if (resp.status === 204) return null; // No content -> not logged in
            if (!resp.ok) return null;
            const json = await resp.text();
            return json;
        } catch (err) {
            console.log('fetchRefreshToken error', err);
            return null;
        }
    },

    /**
     * Performs a login POST with credentials included so HttpOnly refresh cookie is set by the server.
     * `url` should be an absolute URL when API is hosted on a different origin than the client.
     *
     * Returns a JSON stringified object: { status: number, body: string }
     * where `body` is the raw text response from the server (often a JSON payload).
     *
     * @param {string} url - Absolute or relative URL to POST login payload to.
     * @param {object} payload - Plain object that will be JSON-stringified as request body.
     * @returns {Promise<string>} JSON-stringified result with HTTP status and body text.
     */
    login: async function (url, payload) {
        try {
            const resp = await fetch(url, {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify(payload)
            });

            const text = await resp.text();
            return JSON.stringify({ status: resp.status, body: text });
        } catch (err) {
            console.log('wtApi.login error', err);
            return JSON.stringify({ status: 0, body: null });
        }
    }
};
