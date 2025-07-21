using System;
using System.Collections.Generic;
using AISecurityScanner.Domain.Enums;

namespace AISecurityScanner.Domain.Entities
{
    public class ComplianceFramework : BaseEntity
    {
        public string Name { get; set; } = string.Empty;
        public string Version { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public ComplianceFrameworkType Type { get; set; }
        public bool IsActive { get; set; } = true;
        
        public List<ComplianceRequirement> Requirements { get; set; } = new();
        public ComplianceConfiguration Configuration { get; set; } = new();
    }

    public class ComplianceRequirement : BaseEntity
    {
        public string RequirementId { get; set; } = string.Empty;
        public string Title { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public ComplianceFrameworkType Framework { get; set; }
        public ComplianceSeverity Severity { get; set; }
        public string Category { get; set; } = string.Empty;
        public string Subcategory { get; set; } = string.Empty;
        
        public List<ComplianceRule> Rules { get; set; } = new();
        public List<ComplianceControl> Controls { get; set; } = new();
    }

    public class ComplianceRule : BaseEntity
    {
        public string RuleId { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public ComplianceRuleType Type { get; set; }
        public string Pattern { get; set; } = string.Empty;
        public bool IsRegex { get; set; }
        public ComplianceSeverity Severity { get; set; }
        public List<string> FileExtensions { get; set; } = new();
        public List<string> ExcludePaths { get; set; } = new();
        
        public string RemediationGuidance { get; set; } = string.Empty;
        public List<string> References { get; set; } = new();
        public Dictionary<string, object> Metadata { get; set; } = new();
    }

    public class ComplianceControl : BaseEntity
    {
        public string ControlId { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public ComplianceControlType Type { get; set; }
        public bool IsRequired { get; set; }
        public bool IsImplemented { get; set; }
        
        public List<ComplianceRule> Rules { get; set; } = new();
        public string ImplementationGuidance { get; set; } = string.Empty;
        public List<string> EvidenceRequirements { get; set; } = new();
    }

    public class ComplianceConfiguration
    {
        public bool EnableDataClassification { get; set; } = true;
        public bool EnableEncryptionChecks { get; set; } = true;
        public bool EnableAccessControlChecks { get; set; } = true;
        public bool EnableAuditingChecks { get; set; } = true;
        public bool EnableIntegrityChecks { get; set; } = true;
        
        public List<string> SensitiveDataPatterns { get; set; } = new();
        public List<string> RequiredSecurityHeaders { get; set; } = new();
        public Dictionary<string, object> CustomSettings { get; set; } = new();
    }

    public class ComplianceScanResult : BaseEntity
    {
        public Guid ScanId { get; set; }
        public Guid OrganizationId { get; set; }
        public ComplianceFrameworkType Framework { get; set; }
        public DateTime ScanDate { get; set; }
        
        public ComplianceScore OverallScore { get; set; } = new();
        public List<ComplianceViolation> Violations { get; set; } = new();
        public List<ComplianceEvidence> Evidence { get; set; } = new();
        public ComplianceRecommendations Recommendations { get; set; } = new();
        
        public TimeSpan ScanDuration { get; set; }
        public int FilesScanned { get; set; }
        public int RulesEvaluated { get; set; }
    }

    public class ComplianceViolation : BaseEntity
    {
        public string RequirementId { get; set; } = string.Empty;
        public string RuleId { get; set; } = string.Empty;
        public string Title { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public ComplianceSeverity Severity { get; set; }
        public ComplianceStatus Status { get; set; }
        
        public string FilePath { get; set; } = string.Empty;
        public int LineNumber { get; set; }
        public string CodeSnippet { get; set; } = string.Empty;
        
        public string RemediationGuidance { get; set; } = string.Empty;
        public List<string> References { get; set; } = new();
        public DateTime DetectedAt { get; set; }
        public DateTime? ResolvedAt { get; set; }
        public string? ResolutionNotes { get; set; }
    }

    public class ComplianceEvidence
    {
        public string ControlId { get; set; } = string.Empty;
        public string EvidenceType { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public bool IsCompliant { get; set; }
        public string FilePath { get; set; } = string.Empty;
        public Dictionary<string, object> Details { get; set; } = new();
    }

    public class ComplianceScore
    {
        public decimal OverallScore { get; set; }
        public int TotalRequirements { get; set; }
        public int PassedRequirements { get; set; }
        public int FailedRequirements { get; set; }
        public int NotApplicableRequirements { get; set; }
        
        public Dictionary<string, decimal> CategoryScores { get; set; } = new();
        public Dictionary<ComplianceSeverity, int> ViolationsBySeverity { get; set; } = new();
    }

    public class ComplianceRecommendations
    {
        public List<string> HighPriorityActions { get; set; } = new();
        public List<string> MediumPriorityActions { get; set; } = new();
        public List<string> LowPriorityActions { get; set; } = new();
        public List<string> BestPractices { get; set; } = new();
        public string Summary { get; set; } = string.Empty;
    }
}