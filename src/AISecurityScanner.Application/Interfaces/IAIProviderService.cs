using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AISecurityScanner.Application.DTOs;
using AISecurityScanner.Application.Models;
using AISecurityScanner.Domain.ValueObjects;

namespace AISecurityScanner.Application.Interfaces
{
    public interface IAIProviderService
    {
        Task<IEnumerable<AIProviderDto>> GetAllProvidersAsync(CancellationToken cancellationToken = default);
        Task<IEnumerable<AIProviderDto>> GetActiveProvidersAsync(CancellationToken cancellationToken = default);
        Task<AIProviderDto?> GetProviderByIdAsync(Guid providerId, CancellationToken cancellationToken = default);
        Task<SecurityAnalysisResult> AnalyzeCodeAsync(string code, AIAnalysisContext context, CancellationToken cancellationToken = default);
        Task<PackageValidationResult> ValidatePackagesAsync(List<string> packages, string ecosystem, CancellationToken cancellationToken = default);
        Task<bool> TestProviderHealthAsync(Guid providerId, CancellationToken cancellationToken = default);
        Task UpdateProviderHealthAsync(Guid providerId, bool isHealthy, string? errorMessage = null, CancellationToken cancellationToken = default);
        Task<AIProviderDto> GetBestAvailableProviderAsync(AIAnalysisContext context, CancellationToken cancellationToken = default);
        Task<decimal> GetUsageCostAsync(Guid organizationId, DateTime from, DateTime to, CancellationToken cancellationToken = default);
    }

    // Note: SecurityAnalysisResult, PackageValidationResult, and AIAnalysisContext 
    // are defined in AISecurityScanner.Domain.ValueObjects namespace
}