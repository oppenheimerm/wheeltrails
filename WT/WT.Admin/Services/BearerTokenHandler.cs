using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;

namespace WT.Admin.Services
{
    /// <summary>
    /// HTTP message handler that attaches a Bearer token from <see cref="IServerTokenService"/>
    /// to outgoing HTTP requests when an access token is available.
    /// Register this handler as transient and add it to the named HttpClient used for API calls.
    /// </summary>
    public class BearerTokenHandler : DelegatingHandler
    {
        private readonly IServerTokenService _tokenService;

        /// <summary>
        /// Creates a new instance of <see cref="BearerTokenHandler"/>.
        /// </summary>
        /// <param name="tokenService">Scoped token service that provides the current access token.</param>
        public BearerTokenHandler(IServerTokenService tokenService)
        {
            _tokenService = tokenService;
        }

        /// <summary>
        /// Attaches the Authorization header if a token is available and forwards the request.
        /// </summary>
        /// <param name="request">The outgoing HTTP request message.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>The HTTP response task from the inner handler.</returns>
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var token = _tokenService.AccessToken;
            if (!string.IsNullOrEmpty(token))
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            }
            return base.SendAsync(request, cancellationToken);
        }
    }
}
