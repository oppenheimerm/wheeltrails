using System.Net.Http;
using WT.Application.Common.Paging;
using WT.Application.DTO.Response;
using WT.Application.Services;

namespace WT.Admin.Services
{
    public interface ITrailService
    {
        Task<PagedList<TrailDTO>?> GetAllTrailsAsync(PagingParameters pagingParameters, CancellationToken cancellationToken = default);
    }

    public class TrailService : ITrailService
    {
        private readonly HttpClient _httpClient;

        public TrailService(HttpClient httpClient)
        {
            _httpClient = httpClient;
        }

        public async Task<PagedList<TrailDTO>?> GetAllTrailsAsync(PagingParameters pagingParameters, CancellationToken cancellationToken = default)
        {
            try
            {
                // Build query string from PagingParameters
                var queryParams = new List<string>
                {
                    $"PageNumber={pagingParameters.PageNumber}",
                    $"PageSize={pagingParameters.PageSize}"
                };

                if (!string.IsNullOrWhiteSpace(pagingParameters.Search))
                {
                    queryParams.Add($"Search={Uri.EscapeDataString(pagingParameters.Search)}");
                }

                if (!string.IsNullOrWhiteSpace(pagingParameters.OrderBy))
                {
                    queryParams.Add($"OrderBy={Uri.EscapeDataString(pagingParameters.OrderBy)}");
                }

                var queryString = string.Join("&", queryParams);
                var endpoint = $"api/trails/all?{queryString}";

                // Make HTTP call with cancellation token
                var response = await _httpClient.GetFromJsonAsync<PagedList<TrailDTO>>(endpoint, cancellationToken);
                return response;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                // Request was cancelled
                Console.WriteLine("Trail fetch operation was cancelled");
                throw; // Re-throw to let caller handle
            }
            catch (HttpRequestException ex)
            {
                // Log error
                Console.WriteLine($"Error fetching trails: {ex.Message}");
                return null;
            }
        }


        public async Task<TrailDTO?> GetTrailByIdAsync(Guid id, CancellationToken cancellationToken = default)
        {
            try
            {
                // Make HTTP call with cancellation token
                var response = await _httpClient.GetFromJsonAsync<TrailDTO>($"api/trails/{id}", cancellationToken); return response;


            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                // Request was cancelled
                Console.WriteLine("Trail fetch operation was cancelled");
                throw; // Re-throw to let caller handle
            }
            catch (HttpRequestException ex)
            {
                Console.WriteLine($"Error fetching trail {id}: {ex.Message}");
                return null;
            }
        }

    }
}