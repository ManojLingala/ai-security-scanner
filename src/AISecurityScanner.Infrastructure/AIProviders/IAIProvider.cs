using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AISecurityScanner.Application.Interfaces;
using AISecurityScanner.Domain.ValueObjects;

namespace AISecurityScanner.Infrastructure.AIProviders
{
    public interface IAIProvider
    {
        string Name { get; }
        decimal CostPerRequest { get; }
        TimeSpan TypicalResponseTime { get; }
        bool SupportsCodeAnalysis { get; }
        bool SupportsPackageValidation { get; }
        
        Task<SecurityAnalysisResult> AnalyzeCodeAsync(string code, AIAnalysisContext context, CancellationToken cancellationToken = default);
        Task<PackageValidationResult> ValidatePackagesAsync(List<string> packages, string ecosystem, CancellationToken cancellationToken = default);
        Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default);
        Task<ProviderHealthStatus> GetHealthStatusAsync(CancellationToken cancellationToken = default);
    }

    public class ProviderHealthStatus
    {
        public bool IsHealthy { get; set; }
        public string? ErrorMessage { get; set; }
        public TimeSpan ResponseTime { get; set; }
        public DateTime CheckedAt { get; set; }
        public decimal SuccessRate { get; set; }
    }
}