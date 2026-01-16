using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using WT.Application.DTO.Response;
using WT.Maui.Services;

namespace WT.Maui.Handlers
{
    /// <summary>
    /// DelegatingHandler that attaches the access token and attempts a single refresh+retry on 401.
    /// Uses a dedicated refresh client ("ApiRefreshClient") to avoid circular DI.
    /// </summary>
    public class AuthHandler : DelegatingHandler
    {
        private readonly NativeTokenService _tokens;
        private readonly IHttpClientFactory _httpFactory;

        public AuthHandler(NativeTokenService tokens, IHttpClientFactory httpFactory)
        {
            _tokens = tokens ?? throw new ArgumentNullException(nameof(tokens));
            _httpFactory = httpFactory ?? throw new ArgumentNullException(nameof(httpFactory));
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (!string.IsNullOrEmpty(_tokens.AccessToken))
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _tokens.AccessToken);
            }

            var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);

            if (response.StatusCode != HttpStatusCode.Unauthorized) return response;

            // Try refresh once using refresh-only client (no AuthHandler attached)
            var refreshed = await TryRefreshAsync(cancellationToken).ConfigureAwait(false);
            if (!refreshed) return response;

            // Retry original request with new token
            var retry = await CloneRequestAsync(request).ConfigureAwait(false);
            if (!string.IsNullOrEmpty(_tokens.AccessToken))
                retry.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _tokens.AccessToken);

            return await base.SendAsync(retry, cancellationToken).ConfigureAwait(false);
        }

        private async Task<bool> TryRefreshAsync(CancellationToken cancellationToken)
        {
            try
            {
                var refreshToken = await _tokens.GetRefreshTokenAsync().ConfigureAwait(false);
                if (string.IsNullOrEmpty(refreshToken)) return false;

                var client = _httpFactory.CreateClient("ApiRefreshClient");

                var resp = await client.PostAsJsonAsync("api/account/identity/refresh-token-native", new { refreshToken }, cancellationToken).ConfigureAwait(false);
                if (!resp.IsSuccessStatusCode) return false;

                var payload = await resp.Content.ReadFromJsonAsync<APIResponseAuthentication?>().ConfigureAwait(false);
                if (payload == null || string.IsNullOrEmpty(payload.JwtToken)) return false;

                var newAccess = payload.JwtToken;
                var expires = GetExpiryFromJwt(newAccess) ?? DateTime.UtcNow.AddMinutes(30);

                _tokens.SetAccessToken(newAccess, expires);

                if (!string.IsNullOrEmpty(payload.RefreshToken))
                {
                    await _tokens.SetRefreshTokenAsync(payload.RefreshToken).ConfigureAwait(false);
                }

                return true;
            }
            catch
            {
                return false;
            }
        }

        private static async Task<HttpRequestMessage> CloneRequestAsync(HttpRequestMessage req)
        {
            var clone = new HttpRequestMessage(req.Method, req.RequestUri)
            {
                Version = req.Version
            };

            if (req.Content != null)
            {
                var ms = new MemoryStream();
                await req.Content.CopyToAsync(ms).ConfigureAwait(false);
                ms.Position = 0;
                clone.Content = new StreamContent(ms);
                foreach (var h in req.Content.Headers)
                    clone.Content.Headers.TryAddWithoutValidation(h.Key, h.Value);
            }

            foreach (var header in req.Headers)
                clone.Headers.TryAddWithoutValidation(header.Key, header.Value);

            return clone;
        }

        private static DateTime? GetExpiryFromJwt(string jwt)
        {
            try
            {
                var parts = jwt.Split('.');
                if (parts.Length < 2) return null;
                var payload = parts[1];
                int pad = 4 - (payload.Length % 4);
                if (pad < 4) payload += new string('=', pad);
                var bytes = Convert.FromBase64String(payload);
                using var doc = JsonDocument.Parse(bytes);
                if (doc.RootElement.TryGetProperty("exp", out var expEl) && expEl.TryGetInt64(out var exp))
                    return DateTimeOffset.FromUnixTimeSeconds(exp).UtcDateTime;
            }
            catch { }
            return null;
        }
    }
}
