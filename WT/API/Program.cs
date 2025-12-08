using Scalar.AspNetCore;
using WT.Infrastructure.DependencyInjection;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

// Add Service
builder.Services.AddInfrastructureServices(builder.Configuration);



// ✅ ADD CORS POLICY
builder.Services.AddCors(options =>
{
    options.AddPolicy("BlazorWasmPolicy", policy =>
    {
        policy.WithOrigins(
            "https://localhost:7186",  // WT.Client (Blazor WASM)
            "https://localhost:7127",  // WT.Admin (Blazor Server)
            "http://localhost:5041"    // WT.Admin HTTP fallback
        )
        .AllowAnyMethod()
        .AllowAnyHeader()
        .AllowCredentials(); // Important for cookies/authentication
    });
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
app.UseCors("BlazorWasmPolicy");

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
