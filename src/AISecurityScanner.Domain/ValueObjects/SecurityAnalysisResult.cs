using System;
using System.Collections.Generic;
using AISecurityScanner.Domain.Enums;

namespace AISecurityScanner.Domain.ValueObjects
{
    public class SecurityAnalysisResult
    {
        public bool IsSuccess { get; set; }
        public string? ErrorMessage { get; set; }
        public string ProviderName { get; set; } = string.Empty;
        public List<SecurityVulnerability> DetectedVulnerabilities { get; set; } = new();
        public decimal ConfidenceScore { get; set; }
        public TimeSpan ResponseTime { get; set; }
        public int TokensUsed { get; set; }
        public decimal Cost { get; set; }
        public string? MLModelUsed { get; set; }
        public Dictionary<string, object> AnalysisMetadata { get; set; } = new();
    }

    public class SecurityVulnerability
    {
        public string Id { get; set; } = string.Empty;
        public string Type { get; set; } = string.Empty;
        public VulnerabilitySeverity Severity { get; set; }
        public decimal Confidence { get; set; }
        public string Description { get; set; } = string.Empty;
        public int LineNumber { get; set; }
        public string Code { get; set; } = string.Empty;
        public string? CweId { get; set; }
        public string? Recommendation { get; set; }
        public bool MLDetected { get; set; }
        public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
        public Dictionary<string, object> Metadata { get; set; } = new();
    }

    public class PackageValidationResult
    {
        public bool IsSuccess { get; set; }
        public string? ErrorMessage { get; set; }
        public List<PackageVulnerabilityInfo> VulnerablePackages { get; set; } = new();
        public int TotalPackagesScanned { get; set; }
        public int VulnerablePackageCount { get; set; }
        public decimal Cost { get; set; }
        public string ProviderName { get; set; } = string.Empty;
    }

    public class PackageVulnerability
    {
        public string Id { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public VulnerabilitySeverity Severity { get; set; }
        public decimal Confidence { get; set; }
    }

    public class PackageVulnerabilityInfo
    {
        public string PackageName { get; set; } = string.Empty;
        public string Ecosystem { get; set; } = string.Empty;
        public bool HasVulnerabilities { get; set; }
        public List<PackageVulnerability> Vulnerabilities { get; set; } = new();
    }

    public class AIAnalysisContext
    {
        public string? Language { get; set; }
        public Guid OrganizationId { get; set; }
        public bool IncludeAIDetection { get; set; } = true;
        public bool IncludePackageValidation { get; set; } = false;
        public List<string>? PreferredProviders { get; set; }
        public Dictionary<string, object> AdditionalMetadata { get; set; } = new();
    }
}