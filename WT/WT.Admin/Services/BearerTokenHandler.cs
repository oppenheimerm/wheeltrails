using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;

namespace WT.Admin.Services
{
    /// <summary>
    /// HTTP message handler that attaches a Bearer token from <see cref="IServerTokenService"/>
    /// to outgoing HTTP requests and attempts a single refresh+retry on 401 responses.
    ///
    /// Behavior:
    /// 1. If a current access token exists it is attached to the Authorization header.
    /// 2. The request is sent to the inner handler.
    /// 3. If the response is 401 Unauthorized, the handler calls
    ///    <see cref="IServerTokenService.TryRefreshAsync(IHttpClientFactory, CancellationToken)"/>
    ///    to attempt token rotation using the API refresh endpoint.
    /// 4. When refresh succeeds the original request is cloned, the new token attached and retried once.
    ///
    /// Notes:
    /// - The handler performs a single refresh attempt to avoid refresh storms.
    /// - For multi-node deployments persist refresh tokens in a distributed cache or database.
    /// - Register the handler as a transient service and add it to the named HttpClient used for API calls.
    /// </summary>
    public class BearerTokenHandler : DelegatingHandler
    {
        private readonly IServerTokenService _tokenService;
        private readonly IHttpClientFactory _httpFactory;

        public BearerTokenHandler(IServerTokenService tokenService, IHttpClientFactory httpFactory)
        {
            _tokenService = tokenService;
            _httpFactory = httpFactory;
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            // Attach current token if available
            if (!string.IsNullOrEmpty(_tokenService.AccessToken))
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _tokenService.AccessToken);
            }

            var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);

            if (response.StatusCode != HttpStatusCode.Unauthorized)
                return response;

            // Try refresh once
            var refreshed = await _tokenService.TryRefreshAsync(_httpFactory, cancellationToken).ConfigureAwait(false);
            if (!refreshed)
                return response;

            // Clone original request and retry with new token
            var retry = await CloneHttpRequestMessageAsync(request).ConfigureAwait(false);
            if (!string.IsNullOrEmpty(_tokenService.AccessToken))
                retry.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _tokenService.AccessToken);

            return await base.SendAsync(retry, cancellationToken).ConfigureAwait(false);
        }

        private static async Task<HttpRequestMessage> CloneHttpRequestMessageAsync(HttpRequestMessage req)
        {
            var clone = new HttpRequestMessage(req.Method, req.RequestUri)
            {
                Version = req.Version
            };

            // Copy the request content (if any)
            if (req.Content != null)
            {
                var ms = new System.IO.MemoryStream();
                await req.Content.CopyToAsync(ms).ConfigureAwait(false);
                ms.Position = 0;
                clone.Content = new StreamContent(ms);
                foreach (var header in req.Content.Headers)
                    clone.Content.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }

            foreach (var header in req.Headers)
                clone.Headers.TryAddWithoutValidation(header.Key, header.Value);

            return clone;
        }
    }
}
