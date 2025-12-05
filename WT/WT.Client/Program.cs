using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using Microsoft.AspNetCore.Components.Authorization;
using WT.Application.DependencyInjection;
using WT.Client;

var builder = WebAssemblyHostBuilder.CreateDefault(args);

builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

// Register HttpClient with specific base address for WT.Client
builder.Services.AddScoped(sp => new HttpClient 
{ 
    BaseAddress = new Uri(builder.HostEnvironment.BaseAddress) 
});

// OR if calling external API:
// builder.Services.AddScoped(sp => new HttpClient 
// { 
//     BaseAddress = new Uri("https://localhost:5001") // Your API URL
// });

// Register Application Services (includes auth, local storage, etc.)
builder.Services.AddApplicationServices();

await builder.Build().RunAsync();
