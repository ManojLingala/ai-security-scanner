using AISecurityScanner.Infrastructure.Configuration;
using AISecurityScanner.Infrastructure.Data;
using AISecurityScanner.Domain.Interfaces;
using AISecurityScanner.Application.Interfaces;
using AISecurityScanner.Application.Services;
using AISecurityScanner.Infrastructure.Services;
using AISecurityScanner.Infrastructure.AIProviders;
using AISecurityScanner.Infrastructure.CodeAnalysis;
using AISecurityScanner.API.Hubs;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Serilog;
using Serilog.Events;
using FluentValidation;
using FluentValidation.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

// Configure Serilog
Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Debug()
    .MinimumLevel.Override("Microsoft", LogEventLevel.Information)
    .MinimumLevel.Override("Microsoft.AspNetCore", LogEventLevel.Warning)
    .Enrich.FromLogContext()
    .WriteTo.Console()
    .WriteTo.File("logs/aisecurityscanner-.txt", rollingInterval: RollingInterval.Day)
    .CreateLogger();

builder.Host.UseSerilog();

// Add services to the container.
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new Microsoft.OpenApi.Models.OpenApiInfo
    {
        Title = "AI Security Scanner API",
        Version = "v1",
        Description = "API for scanning code repositories for security vulnerabilities with AI-enhanced detection",
        Contact = new Microsoft.OpenApi.Models.OpenApiContact
        {
            Name = "AI Security Scanner Team",
            Email = "support@aisecurityscanner.com"
        },
        License = new Microsoft.OpenApi.Models.OpenApiLicense
        {
            Name = "MIT License",
            Url = new Uri("https://opensource.org/licenses/MIT")
        }
    });

    // Add JWT Authentication to Swagger
    c.AddSecurityDefinition("Bearer", new Microsoft.OpenApi.Models.OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme. Enter 'Bearer' [space] and then your token in the text input below.",
        Name = "Authorization",
        In = Microsoft.OpenApi.Models.ParameterLocation.Header,
        Type = Microsoft.OpenApi.Models.SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });

    c.AddSecurityRequirement(new Microsoft.OpenApi.Models.OpenApiSecurityRequirement
    {
        {
            new Microsoft.OpenApi.Models.OpenApiSecurityScheme
            {
                Reference = new Microsoft.OpenApi.Models.OpenApiReference
                {
                    Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });

    // Include XML documentation
    var xmlFile = $"{System.Reflection.Assembly.GetExecutingAssembly().GetName().Name}.xml";
    var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
    if (File.Exists(xmlPath))
    {
        c.IncludeXmlComments(xmlPath);
    }

    // Configure operation tags
    c.TagActionsBy(api =>
    {
        if (api.GroupName != null)
        {
            return new[] { api.GroupName };
        }

        var controllerName = api.ActionDescriptor is Microsoft.AspNetCore.Mvc.Controllers.ControllerActionDescriptor controllerActionDescriptor
            ? controllerActionDescriptor.ControllerName
            : throw new InvalidOperationException("Unable to determine tag for endpoint.");

        return new[] { controllerName };
    });
});

// Configure RavenDB
var ravenDbConfig = builder.Configuration.GetSection("RavenDb").Get<RavenDbConfiguration>() 
    ?? throw new InvalidOperationException("RavenDB configuration is missing");
builder.Services.AddSingleton(ravenDbConfig);
builder.Services.AddSingleton<IRavenDbContext, RavenDbContext>();

// Register Unit of Work
builder.Services.AddScoped<IUnitOfWork, RavenUnitOfWork>();

// Register Seeder
builder.Services.AddScoped<IRavenDbSeeder, RavenDbSeeder>();

// Register Application Services
builder.Services.AddScoped<ISecurityScannerService, SecurityScannerService>();
builder.Services.AddScoped<IRepositoryService, RepositoryService>();
builder.Services.AddScoped<IAIProviderService, AIProviderService>();
builder.Services.AddScoped<ITeamManagementService, TeamManagementService>();
builder.Services.AddScoped<IVulnerabilityAnalysisService, VulnerabilityAnalysisService>();
builder.Services.AddScoped<IPackageVulnerabilityService, PackageVulnerabilityService>();

// Register Infrastructure Services
builder.Services.AddScoped<IStaticCodeAnalyzer, StaticCodeAnalyzer>();

// Register Package Scanning Services
builder.Services.AddHttpClient();
builder.Services.AddScoped<INuGetPackageScanner, AISecurityScanner.Infrastructure.PackageScanning.NuGetPackageScanner>();
builder.Services.AddScoped<INpmPackageScanner, AISecurityScanner.Infrastructure.PackageScanning.NpmPackageScanner>();
builder.Services.AddScoped<IHallucinationDetectionService, AISecurityScanner.Infrastructure.AIProviders.HallucinationDetectionService>();

// Register AI Providers
builder.Services.AddHttpClient<OpenAIProvider>();
builder.Services.AddHttpClient<ClaudeProvider>();
builder.Services.Configure<OpenAIConfiguration>(builder.Configuration.GetSection("AIProviders:OpenAI"));
builder.Services.Configure<ClaudeConfiguration>(builder.Configuration.GetSection("AIProviders:Claude"));
builder.Services.AddScoped<IAIProvider, OpenAIProvider>();
builder.Services.AddScoped<IAIProvider, ClaudeProvider>();

// Register AutoMapper
builder.Services.AddAutoMapper(typeof(Program), typeof(AISecurityScanner.Application.Mappings.DomainToDtoProfile));

// Register FluentValidation
builder.Services.AddFluentValidationAutoValidation();
builder.Services.AddValidatorsFromAssemblyContaining<AISecurityScanner.Application.Validators.StartScanRequestValidator>();

// Configure JWT Authentication
var jwtConfig = builder.Configuration.GetSection("Jwt");
var key = Encoding.UTF8.GetBytes(jwtConfig["Secret"] ?? throw new InvalidOperationException("JWT Secret not configured"));

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwtConfig["Issuer"],
        ValidAudience = jwtConfig["Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(key),
        ClockSkew = TimeSpan.Zero
    };

    // Configure JWT for SignalR
    options.Events = new JwtBearerEvents
    {
        OnMessageReceived = context =>
        {
            var accessToken = context.Request.Query["access_token"];
            var path = context.HttpContext.Request.Path;
            
            if (!string.IsNullOrEmpty(accessToken) && path.StartsWithSegments("/hubs"))
            {
                context.Token = accessToken;
            }
            
            return Task.CompletedTask;
        }
    };
});

builder.Services.AddAuthorization();

// Add SignalR
builder.Services.AddSignalR(options =>
{
    options.EnableDetailedErrors = builder.Environment.IsDevelopment();
    options.KeepAliveInterval = TimeSpan.FromSeconds(15);
    options.ClientTimeoutInterval = TimeSpan.FromSeconds(30);
});

// Configure CORS
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowSpecificOrigin",
        policy =>
        {
            policy.WithOrigins("http://localhost:3000", "http://localhost:5173")
                  .AllowAnyHeader()
                  .AllowAnyMethod()
                  .AllowCredentials();
        });
});

var app = builder.Build();

// Initialize RavenDB indexes and seed data
using (var scope = app.Services.CreateScope())
{
    var ravenContext = scope.ServiceProvider.GetRequiredService<IRavenDbContext>();
    await ravenContext.EnsureIndexesCreatedAsync();
    
    // Temporarily disable seeding due to ID convention issues
    // var seeder = scope.ServiceProvider.GetRequiredService<IRavenDbSeeder>();
    // await seeder.SeedAsync();
}

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "AI Security Scanner API v1");
    });
}

app.UseSerilogRequestLogging();
app.UseHttpsRedirection();
app.UseCors("AllowSpecificOrigin");
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

// Map SignalR Hubs
app.MapHub<ScanProgressHub>("/hubs/scanprogress");

try
{
    Log.Information("Starting AI Security Scanner API");
    app.Run();
}
catch (Exception ex)
{
    Log.Fatal(ex, "Application terminated unexpectedly");
}
finally
{
    Log.CloseAndFlush();
}

public partial class Program { }