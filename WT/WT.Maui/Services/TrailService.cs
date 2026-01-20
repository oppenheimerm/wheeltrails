using System.Net.Http.Headers;
using System.Net.Http.Json;
using WT.Application.APIServiceLogs;
using WT.Application.DTO.Request.Trail;
using WT.Application.DTO.Response;
using WT.Application.Services;

namespace WT.Maui.Services
{
    public class TrailService
    {
        private readonly IAuthService _authService;
        private readonly HttpClient _httpClient;

        public TrailService(IAuthService authService, HttpClient httpClient)
        {
            _authService = authService ?? throw new ArgumentNullException(nameof(authService));
            _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        }

        public async Task<APIResponseCreateTrail> CreateTrailAsync(CreateTrailDTO model, CancellationToken cancellationToken)
        {
            const int maxRetries = 3; // For transient errors only
            int currentAttempt = 0;

            // validate model client-side before sending to API
            var modelValid = IsCreateTrailRequestValid(model);
            if (modelValid.Success == false)
            {
                return new APIResponseCreateTrail
                {
                    Success = false,
                    Message = modelValid.ValidationMessage
                };
            }

            try
            {
                // Ensure Authorization header is set using AuthService (which may refresh token)
                if (!await EnsureAuthorizationHeaderAsync())
                {
                    return new APIResponseCreateTrail { Success = false, Message = "User is not authenticated" };
                }

                Console.WriteLine($"🔑 Attempting to create a new trail: {model.Title} (Attempt 1/{maxRetries})");
                LogException.LogToConsole($"🔑 Attempting to create a new trail: {model.Title} (Attempt 1/{maxRetries})");

                HttpResponseMessage? response = null;
                bool tokenWasRefreshed = false;

                // Retry loop for transient errors
                while (currentAttempt < maxRetries)
                {
                    currentAttempt++;

                    try
                    {
                        // POST to the correct endpoint 'api/trails'
                        response = await _httpClient.PostAsJsonAsync("api/trails", model, cancellationToken);
                        Console.WriteLine($"📡 Response status (Attempt {currentAttempt}/{maxRetries}): {response.StatusCode}");
                        LogException.LogToConsole($"📡 Response status in CreateTrailAsync (Attempt {currentAttempt}/{maxRetries}): {response.StatusCode}");

                        if (response.IsSuccessStatusCode)
                        {
                            break;
                        }

                        // Handle 5xx transient errors
                        if ((int)response.StatusCode >= 500 || response.StatusCode == System.Net.HttpStatusCode.RequestTimeout)
                        {
                            if (currentAttempt < maxRetries)
                            {
                                var delayMs = currentAttempt * 1000;
                                Console.WriteLine($"⚠️ Server error {response.StatusCode}, retrying in {delayMs}ms...");
                                await Task.Delay(delayMs, cancellationToken);
                                continue;
                            }
                            else
                            {
                                Console.WriteLine($"❌ Max retries ({maxRetries}) reached for server error");
                                break;
                            }
                        }

                        // For client errors (4xx), don't retry
                        Console.WriteLine($"❌ Client error {response.StatusCode} - not retrying");
                        break;
                    }
                    catch (OperationCanceledException)
                    {
                        // Cancellation requested
                        Console.WriteLine("⚠️ CreateTrailAsync was cancelled");
                        return new APIResponseCreateTrail { Success = false, Message = "Trail creation was cancelled." };
                    }
                    catch (HttpRequestException ex)
                    {
                        Console.WriteLine($"⚠️ Network error on attempt {currentAttempt}/{maxRetries}: {ex.Message}");
                        LogException.LogToConsole($"⚠️ Network error on attempt {currentAttempt}/{maxRetries} in CreateTrailAsync: {ex.Message}");

                        if (currentAttempt < maxRetries)
                        {
                            var delayMs = currentAttempt * 1000;
                            Console.WriteLine($"Retrying in {delayMs}ms...");
                            await Task.Delay(delayMs, cancellationToken);
                            continue; // Retry
                        }
                        else
                        {
                            Console.WriteLine($"❌ Max retries ({maxRetries}) reached for network error");
                            return new APIResponseCreateTrail { Success = false, Message = "Network error. Please check your connection and try again." };
                        }
                    }
                }

                // Final check
                if (response == null || !response.IsSuccessStatusCode)
                {
                    var errorContent = response != null ? await response.Content.ReadAsStringAsync(cancellationToken) : "No response received";
                    Console.WriteLine($"❌ Final response failed: {response?.StatusCode}");
                    Console.WriteLine($"Error details: {errorContent}");
                    return new APIResponseCreateTrail { Success = false, Message = $"Unable to create trail. Status: {response?.StatusCode}" };
                }

                var result = await response.Content.ReadFromJsonAsync<APIResponseCreateTrail>(cancellationToken: cancellationToken);
                return result ?? new APIResponseCreateTrail { Success = false, Message = "Failed to parse server response." };
            }
            catch (OperationCanceledException)
            {
                Console.WriteLine("⚠️ CreateTrailAsync cancelled by caller");
                return new APIResponseCreateTrail { Success = false, Message = "Trail creation was cancelled." };
            }
            catch (Exception ex)
            {
                Console.WriteLine($"🔥 Exception in CreateTrailAsync: {ex.Message}");
                LogException.LogExceptions(ex);
                return new APIResponseCreateTrail { Success = false, Message = "An unexpected error occurred while creating trail." };
            }
        }

        private async Task<bool> EnsureAuthorizationHeaderAsync()
        {
            // Delegate to centralized auth service which can refresh and set the Authorization header
            try
            {
                return await _authService.EnsureAuthorizationHeaderAsync(_httpClient).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                LogException.LogExceptions(ex);
                return false;
            }
        }

        /// <summary>
        /// Helper method to validate CreateTrailDTO on client side before sending to API.
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        private (bool Success, string ValidationMessage) IsCreateTrailRequestValid(CreateTrailDTO model)
        {
            if (model == null)
            {
                return (false, "Form is null");
            }

            // Additional domain checks not covered by attributes
            if (model.Start == null)
                return (false, "Start coordinate is required.");

            if (model.End == null)
                return (false, "End coordinate is required.");

            if (model.Waypoints == null || model.Waypoints.Count < 2)
                return (false, "Waypoints must contain at least two coordinates (start and end).");

            if (model.LengthMeters <= 0)
                return (false, "LengthMeters must be greater zero.");
            if (model.Title != null && model.Title.Length > 150)
            {
                return (false, "Title exceeds maximum length of 150 characters.");
            }
            if (model.Description != null && model.Description.Length > 600)
            {
                return (false, "Description exceeds maximum length of 600 characters.");
            }
            //test if waypoints are not null
            if (model.Waypoints.Any(wp => wp == null))
            {
                return (false, "Waypoints cannot contain null values.");
            }
            // Waypoint automatically checks for valid lat/lng in WTLatLng struct
            else
            {
                return (true, "");
            }
        }

        public async Task LogoutAsync()
        {
            try
            {
                var response = await _httpClient.PostAsync("api/account/identity/logout", null);
                if (!response.IsSuccessStatusCode)
                {
                    var friendly = await response.Content.ReadFromJsonAsync<BaseAPIResponseDTO>();
                    LogException.LogToConsole($"Logout failed: {friendly?.Message ?? response.StatusCode.ToString()}");
                }
            }
            catch (Exception ex)
            {
                LogException.LogExceptions(ex);
            }
        }
    }
}
