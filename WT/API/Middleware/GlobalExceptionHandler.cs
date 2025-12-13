using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using WT.Application.APIServiceLogs;

namespace API.Middleware
{
    /// <summary>
    /// Global exception handler for production environments.
    /// Logs exceptions and returns safe error responses without exposing internal details.
    /// </summary>
    public class GlobalExceptionHandler : IExceptionHandler
    {
        private readonly ILogger<GlobalExceptionHandler> _logger;

        public GlobalExceptionHandler(ILogger<GlobalExceptionHandler> logger)
        {
            _logger = logger;
        }

        public async ValueTask<bool> TryHandleAsync(
            HttpContext httpContext,
            Exception exception,
            CancellationToken cancellationToken)
        {
            // Log the full exception
            LogException.LogExceptions(exception);
            _logger.LogError(exception,
                "Unhandled exception occurred. Path: {Path}",
                httpContext.Request.Path);

            // Return safe error response
            var problemDetails = new ProblemDetails
            {
                Status = StatusCodes.Status500InternalServerError,
                Title = "An error occurred while processing your request.",
                Detail = "Please try again later or contact support if the problem persists.",
                Instance = httpContext.Request.Path
            };

            httpContext.Response.StatusCode = StatusCodes.Status500InternalServerError;
            await httpContext.Response.WriteAsJsonAsync(problemDetails, cancellationToken);

            return true; // Exception handled
        }
    }
}
