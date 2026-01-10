using API.Middleware;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Scalar.AspNetCore;
using System.Threading.RateLimiting;
using WT.Application.Contracts; // ✅ ADD THIS
using WT.Infrastructure.Data;
using WT.Infrastructure.DependencyInjection;
using static System.Net.WebRequestMethods;

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

// ✅ NOTE: CORS policy is registered in WT.Infrastructure.DependencyInjection.ServiceContainer as "DefaultCorsPolicy".
// Do not re-register here to avoid duplication/conflicts.

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

//  10/01/2026
//  In ASP.NET Core, all service registrations must happen before; builder.Build().Anything added
//  after that point is ignored.
//  ✔ This ensures Azure’s X-Forwarded-Proto: https header is honored.
//  ✔ Request.IsHttps will now be true inside your controllers.
//  ✔ Your cookie will now be sent with Secure=true.

builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders =
        ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;

    options.KnownNetworks.Clear();
    options.KnownProxies.Clear();
});

var app = builder.Build();

// ✅ FORCE USERNAME VALIDATOR TO LOAD AT STARTUP
using (var scope = app.Services.CreateScope())
{
    var usernameValidator = scope.ServiceProvider.GetRequiredService<IUsernameValidator>();

    // ✅ Test 1: Valid username
    var validResult = usernameValidator.IsUsernameAllowed("testuser");
    Console.WriteLine($"✅ Valid username 'testuser': {validResult}");

    // ✅ Test 2: Bad word (should be rejected)
    var badResult = usernameValidator.IsUsernameAllowed("asshole");
    Console.WriteLine($"❌ Bad username 'asshole': {badResult}");

    // ✅ Test 3: Contains bad word
    var containsBadResult = usernameValidator.IsUsernameAllowed("myasshole123");
    Console.WriteLine($"❌ Username containing bad word 'myasshole123': {containsBadResult}");

    Console.WriteLine($"🎯 UsernameValidator loaded and tested successfully!");
}


//  Our API has a friendly, lightweight landing response.  It givees a clear indication that the API is running.
// and has zero security implications.  This also plays well with uptime monitoring services, tool like
// Azure Monitor, Pingdom, UptimeRobot, etc., can ping this endpoint to verify that the API is operational.
app.MapGet("/", () =>
    Results.Json(new
    {
        status = "WheelyTrails API is running",
        environment = app.Environment.EnvironmentName
    })
);

// Configure the HTTP request pipeline.
app.MapOpenApi(); // always expose JSON

if (app.Environment.IsDevelopment())
{
    app.MapScalarApiReference(); // UI only in dev
}



//  10/01/2026
//  Must be BEFORE UseHttpsRedirection
app.UseForwardedHeaders();

app.UseHttpsRedirection();

// ✅ USE CORS - Must be BEFORE UseAuthentication/UseAuthorization
app.UseCors("DefaultCorsPolicy");

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
