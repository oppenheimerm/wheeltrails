using API.Middleware;
using Scalar.AspNetCore;
using WT.Infrastructure.DependencyInjection;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using WT.Infrastructure.Data;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.EntityFrameworkCore; // Add this using directive at the top of the file

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();

// Add after builder.Services.AddControllers()
builder.Services.AddApplicationInsightsTelemetry(options =>
{
    options.ConnectionString = builder.Configuration["ApplicationInsights:ConnectionString"];
});

// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

// Add Service
builder.Services.AddInfrastructureServices(builder.Configuration);

builder.Services.AddOpenApi();
builder.Services.AddExceptionHandler<GlobalExceptionHandler>();
builder.Services.AddProblemDetails();

// ✅ ADD CORS POLICY
builder.Services.AddCors(options =>
{
    options.AddPolicy("ProductionPolicy", policy =>
    {
        var allowedOrigins = builder.Configuration
            .GetSection("AllowedOrigins")
            .Get<string[]>() ?? Array.Empty<string>();

        if (allowedOrigins.Length > 0)
        {
            policy.WithOrigins(allowedOrigins)
                .AllowAnyMethod()
                .AllowAnyHeader()
                .AllowCredentials();
        }
        else
        {
            // Development fallback
            policy.WithOrigins(
                "https://localhost:7186",  // WT.Client (Blazor WASM)
                "https://localhost:7127",  // WT.Admin (Blazor Server)
                "http://localhost:5041"    // WT.Admin HTTP fallback
            )
            .AllowAnyMethod()
            .AllowAnyHeader()
            .AllowCredentials(); // Important for cookies/authentication
        }
    });
});

// ✅ ADD HEALTH CHECKS
builder.Services.AddHealthChecks()
    .AddDbContextCheck<AppDbContext>("database") // This requires Microsoft.EntityFrameworkCore
    .AddCheck("api", () => HealthCheckResult.Healthy("API is running"));

// ✅ ADD RATE LIMITING
// Rate limiting to protect against abuse and DoS attacks by limiting the number of requests
// a client can make in a given time period.
builder.Services.AddRateLimiter(options =>
{
    // ✅ Global rate limit (100 requests per minute per IP)
    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 100,
                Window = TimeSpan.FromMinutes(1),
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 10
            }));

    // ✅ Strict rate limit for auth endpoints
    options.AddPolicy("AuthPolicy", context =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 10,
                Window = TimeSpan.FromMinutes(1),
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 2
            }));

    options.OnRejected = async (context, token) =>
    {
        context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
        await context.HttpContext.Response.WriteAsJsonAsync(new
        {
            success = false,
            message = "Too many requests. Please try again later."
        }, cancellationToken: token);
    };
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference();
}

app.UseHttpsRedirection();

// ✅ USE CORS - Must be BEFORE UseAuthentication/UseAuthorization
app.UseCors("ProductionPolicy");

app.UseRateLimiter();

// Add BEFORE app.UseAuthentication()
app.UseRateLimiter();

app.UseAuthentication();
app.UseAuthorization();

app.UseExceptionHandler(); // ✅ Uses GlobalExceptionHandler

app.MapControllers();

// ADD Health Checks Endpoint
app.MapHealthChecks("/health");
// Health Checks for readiness and liveness probes
app.MapHealthChecks("/health/ready", new HealthCheckOptions
{
    Predicate = check => check.Tags.Contains("ready")
});

app.Run();
