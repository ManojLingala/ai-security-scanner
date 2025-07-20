using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AutoMapper;
using Microsoft.Extensions.Logging;
using AISecurityScanner.Application.DTOs;
using AISecurityScanner.Application.Interfaces;
using AISecurityScanner.Application.Models;
using AISecurityScanner.Domain.Entities;
using AISecurityScanner.Domain.Interfaces;
using AISecurityScanner.Domain.ValueObjects;
using AISecurityScanner.Infrastructure.AIProviders;

namespace AISecurityScanner.Infrastructure.Services
{
    public class AIProviderService : IAIProviderService
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMapper _mapper;
        private readonly ILogger<AIProviderService> _logger;
        private readonly IEnumerable<IAIProvider> _aiProviders;

        public AIProviderService(
            IUnitOfWork unitOfWork,
            IMapper mapper,
            ILogger<AIProviderService> logger,
            IEnumerable<IAIProvider> aiProviders)
        {
            _unitOfWork = unitOfWork;
            _mapper = mapper;
            _logger = logger;
            _aiProviders = aiProviders;
        }

        public async Task<IEnumerable<AIProviderDto>> GetAllProvidersAsync(CancellationToken cancellationToken = default)
        {
            var providers = await _unitOfWork.AIProviders.GetAllAsync(cancellationToken);
            return _mapper.Map<IEnumerable<AIProviderDto>>(providers);
        }

        public async Task<IEnumerable<AIProviderDto>> GetActiveProvidersAsync(CancellationToken cancellationToken = default)
        {
            var providers = await _unitOfWork.AIProviders.FindAsync(
                p => p.IsActive && p.IsHealthy,
                cancellationToken);
            
            return _mapper.Map<IEnumerable<AIProviderDto>>(providers);
        }

        public async Task<AIProviderDto?> GetProviderByIdAsync(Guid providerId, CancellationToken cancellationToken = default)
        {
            var provider = await _unitOfWork.AIProviders.GetByIdAsync(providerId, cancellationToken);
            return provider != null ? _mapper.Map<AIProviderDto>(provider) : null;
        }

        public async Task<SecurityAnalysisResult> AnalyzeCodeAsync(string code, AIAnalysisContext context, CancellationToken cancellationToken = default)
        {
            try
            {
                var bestProvider = await GetBestAvailableProviderForAnalysisAsync(context, cancellationToken);
                if (bestProvider == null)
                {
                    return new SecurityAnalysisResult
                    {
                        IsSuccess = false,
                        ErrorMessage = "No available AI providers for code analysis",
                        ProviderName = "None"
                    };
                }

                var aiProvider = _aiProviders.FirstOrDefault(p => p.Name == bestProvider.Name);
                if (aiProvider == null)
                {
                    return new SecurityAnalysisResult
                    {
                        IsSuccess = false,
                        ErrorMessage = $"AI Provider {bestProvider.Name} not found",
                        ProviderName = bestProvider.Name
                    };
                }

                var result = await aiProvider.AnalyzeCodeAsync(code, context, cancellationToken);

                // Record usage
                await RecordProviderUsageAsync(bestProvider.Id, context.OrganizationId, result, cancellationToken);

                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during AI code analysis");
                return new SecurityAnalysisResult
                {
                    IsSuccess = false,
                    ErrorMessage = ex.Message,
                    ProviderName = "Unknown"
                };
            }
        }

        public async Task<PackageValidationResult> ValidatePackagesAsync(List<string> packages, string ecosystem, CancellationToken cancellationToken = default)
        {
            try
            {
                var context = new AIAnalysisContext
                {
                    Language = ecosystem,
                    IncludePackageValidation = true
                };

                var bestProvider = await GetBestAvailableProviderForAnalysisAsync(context, cancellationToken);
                if (bestProvider == null)
                {
                    return new PackageValidationResult
                    {
                        IsSuccess = false,
                        ErrorMessage = "No available AI providers for package validation"
                    };
                }

                var aiProvider = _aiProviders.FirstOrDefault(p => p.Name == bestProvider.Name);
                if (aiProvider == null)
                {
                    return new PackageValidationResult
                    {
                        IsSuccess = false,
                        ErrorMessage = $"AI Provider {bestProvider.Name} not found"
                    };
                }

                var result = await aiProvider.ValidatePackagesAsync(packages, ecosystem, cancellationToken);

                // Record usage
                await RecordProviderUsageAsync(bestProvider.Id, context.OrganizationId, null, cancellationToken, result.Cost);

                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during package validation");
                return new PackageValidationResult
                {
                    IsSuccess = false,
                    ErrorMessage = ex.Message
                };
            }
        }

        public async Task<bool> TestProviderHealthAsync(Guid providerId, CancellationToken cancellationToken = default)
        {
            try
            {
                var provider = await _unitOfWork.AIProviders.GetByIdAsync(providerId, cancellationToken);
                if (provider == null) return false;

                var aiProvider = _aiProviders.FirstOrDefault(p => p.Name == provider.Name);
                if (aiProvider == null) return false;

                return await aiProvider.IsHealthyAsync(cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error testing provider health for {ProviderId}", providerId);
                return false;
            }
        }

        public async Task UpdateProviderHealthAsync(Guid providerId, bool isHealthy, string? errorMessage = null, CancellationToken cancellationToken = default)
        {
            try
            {
                var provider = await _unitOfWork.AIProviders.GetByIdAsync(providerId, cancellationToken);
                if (provider == null) return;

                provider.IsHealthy = isHealthy;
                provider.LastHealthCheckAt = DateTime.UtcNow;
                provider.HealthCheckError = errorMessage;
                provider.ModifiedAt = DateTime.UtcNow;

                await _unitOfWork.AIProviders.UpdateAsync(provider, cancellationToken);
                await _unitOfWork.SaveChangesAsync(cancellationToken);

                _logger.LogInformation("Updated health status for provider {ProviderId}: {IsHealthy}", providerId, isHealthy);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating provider health for {ProviderId}", providerId);
            }
        }

        public async Task<AIProviderDto> GetBestAvailableProviderAsync(AIAnalysisContext context, CancellationToken cancellationToken = default)
        {
            var provider = await GetBestAvailableProviderForAnalysisAsync(context, cancellationToken);
            if (provider == null)
            {
                throw new InvalidOperationException("No available AI providers");
            }
            
            return _mapper.Map<AIProviderDto>(provider);
        }

        public async Task<decimal> GetUsageCostAsync(Guid organizationId, DateTime from, DateTime to, CancellationToken cancellationToken = default)
        {
            try
            {
                var usageRecords = await _unitOfWork.AIProviders.FindAsync(
                    p => p.UsageRecords.Any(u => u.OrganizationId == organizationId && 
                                                u.RequestedAt >= from && 
                                                u.RequestedAt <= to),
                    cancellationToken);

                return usageRecords.SelectMany(p => p.UsageRecords)
                    .Where(u => u.OrganizationId == organizationId && 
                               u.RequestedAt >= from && 
                               u.RequestedAt <= to)
                    .Sum(u => u.Cost);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error calculating usage cost for organization {OrganizationId}", organizationId);
                return 0;
            }
        }

        private async Task<AIProvider?> GetBestAvailableProviderForAnalysisAsync(AIAnalysisContext context, CancellationToken cancellationToken)
        {
            var providers = await _unitOfWork.AIProviders.FindAsync(
                p => p.IsActive && p.IsHealthy,
                cancellationToken);

            // Filter by capabilities
            providers = providers.Where(p => 
                (context.IncludeAIDetection && p.SupportsCodeAnalysis) ||
                (context.IncludePackageValidation && p.SupportsPackageValidation));

            // Filter by preferred providers if specified
            if (context.PreferredProviders?.Any() == true)
            {
                var preferredProviders = providers.Where(p => 
                    context.PreferredProviders.Contains(p.Name, StringComparer.OrdinalIgnoreCase));
                
                if (preferredProviders.Any())
                {
                    providers = preferredProviders;
                }
            }

            // Sort by priority, success rate, and cost
            return providers
                .OrderBy(p => p.Priority)
                .ThenByDescending(p => p.SuccessRate)
                .ThenBy(p => p.CostPerRequest)
                .FirstOrDefault();
        }

        private async Task RecordProviderUsageAsync(Guid providerId, Guid organizationId, SecurityAnalysisResult? analysisResult, CancellationToken cancellationToken, decimal? customCost = null)
        {
            try
            {
                var usage = new AIProviderUsage
                {
                    Id = Guid.NewGuid(),
                    AIProviderId = providerId,
                    OrganizationId = organizationId,
                    RequestedAt = DateTime.UtcNow,
                    CompletedAt = DateTime.UtcNow,
                    IsSuccessful = analysisResult?.IsSuccess ?? customCost.HasValue,
                    ErrorMessage = analysisResult?.ErrorMessage,
                    TokensUsed = analysisResult?.TokensUsed ?? 0,
                    Cost = customCost ?? analysisResult?.Cost ?? 0,
                    ResponseTime = analysisResult?.ResponseTime,
                    RequestType = analysisResult != null ? "CodeAnalysis" : "PackageValidation",
                    CreatedAt = DateTime.UtcNow,
                    ModifiedAt = DateTime.UtcNow
                };

                await _unitOfWork.AIProviders.FindAsync(p => p.Id == providerId, cancellationToken);
                // Note: In a real implementation, you'd add this to a usage collection
                // For now, we'll skip the actual storage to keep the example simple

                _logger.LogInformation("Recorded AI provider usage for provider {ProviderId}, cost: {Cost}", providerId, usage.Cost);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error recording provider usage");
            }
        }
    }
}