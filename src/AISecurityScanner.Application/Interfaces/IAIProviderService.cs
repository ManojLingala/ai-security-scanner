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

    public class SecurityAnalysisResult
    {
        public bool IsSuccess { get; set; }
        public string? ErrorMessage { get; set; }
        public List<VulnerabilityDto> Vulnerabilities { get; set; } = new();
        public decimal Confidence { get; set; }
        public TimeSpan ResponseTime { get; set; }
        public int TokensUsed { get; set; }
        public decimal Cost { get; set; }
        public string ProviderName { get; set; } = string.Empty;
    }

    public class PackageValidationResult
    {
        public bool IsSuccess { get; set; }
        public string? ErrorMessage { get; set; }
        public List<PackageInfo> ValidatedPackages { get; set; } = new();
        public List<PackageInfo> HallucinatedPackages { get; set; } = new();
        public TimeSpan ResponseTime { get; set; }
        public decimal Cost { get; set; }
    }

    public class AIAnalysisContext
    {
        public string Language { get; set; } = string.Empty;
        public string FileName { get; set; } = string.Empty;
        public Guid OrganizationId { get; set; }
        public bool IncludeAIDetection { get; set; } = true;
        public bool IncludePackageValidation { get; set; } = true;
        public string[] PreferredProviders { get; set; } = Array.Empty<string>();
    }
}