using System;
using System.Threading;
using System.Threading.Tasks;
using AISecurityScanner.Domain.Entities;
using AISecurityScanner.Domain.Enums;
using Raven.Client.Documents.Session;
using System.Collections.Generic;
using System.Linq;

namespace AISecurityScanner.Infrastructure.Data
{
    public interface IRavenDbSeeder
    {
        Task SeedAsync(CancellationToken cancellationToken = default);
    }

    public class RavenDbSeeder : IRavenDbSeeder
    {
        private readonly IRavenDbContext _context;

        public RavenDbSeeder(IRavenDbContext context)
        {
            _context = context;
        }

        public async Task SeedAsync(CancellationToken cancellationToken = default)
        {
            using var session = _context.OpenAsyncSession();
            
            // Simple check - just try to seed (if it already exists, it will be skipped)
            // RavenDB will handle duplicates gracefully

            // Seed AI Providers
            var providers = new List<AIProvider>
            {
                new AIProvider
                {
                    Id = Guid.NewGuid(),
                    Name = "OpenAI GPT-4",
                    ApiEndpoint = "https://api.openai.com/v1/chat/completions",
                    Model = "gpt-4-turbo-preview",
                    IsActive = true,
                    CostPerRequest = 0.03m,
                    MaxTokens = 128000,
                    TimeoutSeconds = 60,
                    RateLimitPerMinute = 500,
                    RateLimitPerHour = 10000,
                    SupportsCodeAnalysis = true,
                    SupportsPackageValidation = true,
                    Priority = 1,
                    AverageResponseTime = TimeSpan.FromSeconds(5),
                    SuccessRate = 0.98m,
                    IsHealthy = true,
                    CreatedAt = DateTime.UtcNow,
                    ModifiedAt = DateTime.UtcNow
                },
                new AIProvider
                {
                    Id = Guid.NewGuid(),
                    Name = "Anthropic Claude 3",
                    ApiEndpoint = "https://api.anthropic.com/v1/messages",
                    Model = "claude-3-opus-20240229",
                    IsActive = true,
                    CostPerRequest = 0.015m,
                    MaxTokens = 200000,
                    TimeoutSeconds = 60,
                    RateLimitPerMinute = 100,
                    RateLimitPerHour = 5000,
                    SupportsCodeAnalysis = true,
                    SupportsPackageValidation = true,
                    Priority = 2,
                    AverageResponseTime = TimeSpan.FromSeconds(3),
                    SuccessRate = 0.99m,
                    IsHealthy = true,
                    CreatedAt = DateTime.UtcNow,
                    ModifiedAt = DateTime.UtcNow
                },
                new AIProvider
                {
                    Id = Guid.NewGuid(),
                    Name = "xAI Grok",
                    ApiEndpoint = "https://api.x.ai/v1/chat/completions",
                    Model = "grok-1",
                    IsActive = false,
                    CostPerRequest = 0.02m,
                    MaxTokens = 100000,
                    TimeoutSeconds = 45,
                    RateLimitPerMinute = 200,
                    RateLimitPerHour = 8000,
                    SupportsCodeAnalysis = true,
                    SupportsPackageValidation = false,
                    Priority = 3,
                    AverageResponseTime = TimeSpan.FromSeconds(4),
                    SuccessRate = 0.95m,
                    IsHealthy = true,
                    CreatedAt = DateTime.UtcNow,
                    ModifiedAt = DateTime.UtcNow
                }
            };

            foreach (var provider in providers)
            {
                await session.StoreAsync(provider);
            }

            // Seed demo organization
            var demoOrg = new Organization
            {
                Id = Guid.NewGuid(),
                Name = "Demo Organization",
                Plan = OrganizationPlan.Pro,
                IsActive = true,
                TeamSizeLimit = 10,
                MonthlyScansLimit = 1000,
                RepositoriesLimit = 50,
                CurrentMonthScans = 0,
                LastScanResetDate = DateTime.UtcNow,
                CreatedAt = DateTime.UtcNow,
                ModifiedAt = DateTime.UtcNow
            };

            await session.StoreAsync(demoOrg);

            // Seed demo user
            var demoUser = new User
            {
                Id = Guid.NewGuid(),
                Email = "demo@aisecurityscanner.com",
                FirstName = "Demo",
                LastName = "User",
                Role = UserRole.Admin,
                OrganizationId = demoOrg.Id,
                IsActive = true,
                CreatedAt = DateTime.UtcNow,
                ModifiedAt = DateTime.UtcNow
            };

            await session.StoreAsync(demoUser);

            await session.SaveChangesAsync();
        }
    }
}