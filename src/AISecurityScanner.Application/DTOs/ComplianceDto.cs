using System;
using System.Collections.Generic;
using AISecurityScanner.Application.Interfaces;
using AISecurityScanner.Domain.Enums;

namespace AISecurityScanner.Application.DTOs
{
    public class ComplianceFrameworkDto
    {
        public Guid Id { get; set; }
        public string Name { get; set; } = string.Empty;
        public string Version { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public ComplianceFrameworkType Type { get; set; }
        public bool IsActive { get; set; }
        public int RequirementCount { get; set; }
        public DateTime LastUpdated { get; set; }
    }

    public class ComplianceScanResultDto
    {
        public Guid Id { get; set; }
        public Guid ScanId { get; set; }
        public Guid OrganizationId { get; set; }
        public ComplianceFrameworkType Framework { get; set; }
        public DateTime ScanDate { get; set; }
        public TimeSpan ScanDuration { get; set; }
        
        public ComplianceScoreDto OverallScore { get; set; } = new();
        public List<ComplianceViolationDto> Violations { get; set; } = new();
        public List<ComplianceEvidenceDto> Evidence { get; set; } = new();
        public ComplianceRecommendationsDto Recommendations { get; set; } = new();
        
        public int FilesScanned { get; set; }
        public int RulesEvaluated { get; set; }
        public string Status { get; set; } = string.Empty;
    }

    public class ComplianceViolationDto
    {
        public Guid Id { get; set; }
        public string RequirementId { get; set; } = string.Empty;
        public string RuleId { get; set; } = string.Empty;
        public string Title { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public ComplianceSeverity Severity { get; set; }
        public ComplianceStatus Status { get; set; }
        public ComplianceFrameworkType Framework { get; set; }
        
        public string FilePath { get; set; } = string.Empty;
        public int LineNumber { get; set; }
        public string CodeSnippet { get; set; } = string.Empty;
        
        public string RemediationGuidance { get; set; } = string.Empty;
        public List<string> References { get; set; } = new();
        public DateTime DetectedAt { get; set; }
        public DateTime? ResolvedAt { get; set; }
        public string? ResolutionNotes { get; set; }
        public string Category { get; set; } = string.Empty;
    }

    public class ComplianceEvidenceDto
    {
        public Guid Id { get; set; }
        public string ControlId { get; set; } = string.Empty;
        public string EvidenceType { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public bool IsCompliant { get; set; }
        public string FilePath { get; set; } = string.Empty;
        public DateTime CollectedAt { get; set; }
        public Dictionary<string, object> Details { get; set; } = new();
    }

    public class ComplianceScoreDto
    {
        public decimal OverallScore { get; set; }
        public string Grade { get; set; } = string.Empty;
        public int TotalRequirements { get; set; }
        public int PassedRequirements { get; set; }
        public int FailedRequirements { get; set; }
        public int NotApplicableRequirements { get; set; }
        
        public Dictionary<string, decimal> CategoryScores { get; set; } = new();
        public Dictionary<ComplianceSeverity, int> ViolationsBySeverity { get; set; } = new();
        public decimal CompliancePercentage => TotalRequirements > 0 ? (decimal)PassedRequirements / TotalRequirements * 100 : 0;
    }

    public class ComplianceRecommendationsDto
    {
        public List<string> HighPriorityActions { get; set; } = new();
        public List<string> MediumPriorityActions { get; set; } = new();
        public List<string> LowPriorityActions { get; set; } = new();
        public List<string> BestPractices { get; set; } = new();
        public string Summary { get; set; } = string.Empty;
        public int EstimatedEffortHours { get; set; }
    }

    public class ComplianceReportDto
    {
        public Guid Id { get; set; }
        public Guid OrganizationId { get; set; }
        public List<ComplianceFrameworkType> Frameworks { get; set; } = new();
        public DateTime GeneratedAt { get; set; }
        public DateTime CoverageFromDate { get; set; }
        public DateTime CoverageToDate { get; set; }
        
        public ComplianceExecutiveSummaryDto ExecutiveSummary { get; set; } = new();
        public List<ComplianceFrameworkReportDto> FrameworkReports { get; set; } = new();
        public ComplianceTrendAnalysisDto TrendAnalysis { get; set; } = new();
        public List<ComplianceRecommendationsDto> Recommendations { get; set; } = new();
        
        public string ReportUrl { get; set; } = string.Empty;
        public ComplianceReportFormat Format { get; set; }
    }

    public class ComplianceExecutiveSummaryDto
    {
        public decimal OverallComplianceScore { get; set; }
        public string ComplianceGrade { get; set; } = string.Empty;
        public int TotalViolations { get; set; }
        public int CriticalViolations { get; set; }
        public int HighViolations { get; set; }
        public int ResolvedViolations { get; set; }
        public decimal ImprovementPercentage { get; set; }
        public List<string> KeyRisks { get; set; } = new();
        public List<string> Achievements { get; set; } = new();
    }

    public class ComplianceFrameworkReportDto
    {
        public ComplianceFrameworkType Framework { get; set; }
        public string FrameworkName { get; set; } = string.Empty;
        public ComplianceScoreDto Score { get; set; } = new();
        public List<ComplianceViolationDto> Violations { get; set; } = new();
        public List<ComplianceRequirementStatusDto> RequirementStatus { get; set; } = new();
        public ComplianceRecommendationsDto Recommendations { get; set; } = new();
    }

    public class ComplianceRequirementStatusDto
    {
        public string RequirementId { get; set; } = string.Empty;
        public string Title { get; set; } = string.Empty;
        public string Category { get; set; } = string.Empty;
        public bool IsCompliant { get; set; }
        public ComplianceSeverity Severity { get; set; }
        public int ViolationCount { get; set; }
        public string Status { get; set; } = string.Empty;
        public string Notes { get; set; } = string.Empty;
    }

    public class ComplianceDashboardDto
    {
        public Guid OrganizationId { get; set; }
        public DateTime LastUpdated { get; set; }
        
        public ComplianceOverviewDto Overview { get; set; } = new();
        public List<ComplianceFrameworkStatusDto> FrameworkStatus { get; set; } = new();
        public List<ComplianceViolationSummaryDto> RecentViolations { get; set; } = new();
        public ComplianceTrendDataDto TrendData { get; set; } = new();
        public List<ComplianceActionItemDto> ActionItems { get; set; } = new();
    }

    public class ComplianceOverviewDto
    {
        public decimal OverallScore { get; set; }
        public string Grade { get; set; } = string.Empty;
        public int ActiveFrameworks { get; set; }
        public int TotalViolations { get; set; }
        public int CriticalViolations { get; set; }
        public int OpenViolations { get; set; }
        public decimal MonthlyImprovement { get; set; }
    }

    public class ComplianceFrameworkStatusDto
    {
        public ComplianceFrameworkType Framework { get; set; }
        public string Name { get; set; } = string.Empty;
        public decimal Score { get; set; }
        public string Grade { get; set; } = string.Empty;
        public int ViolationCount { get; set; }
        public DateTime LastScanned { get; set; }
        public string Status { get; set; } = string.Empty;
    }

    public class ComplianceViolationSummaryDto
    {
        public Guid Id { get; set; }
        public string Title { get; set; } = string.Empty;
        public ComplianceSeverity Severity { get; set; }
        public ComplianceFrameworkType Framework { get; set; }
        public DateTime DetectedAt { get; set; }
        public string Status { get; set; } = string.Empty;
        public string Category { get; set; } = string.Empty;
    }

    public class ComplianceTrendDataDto
    {
        public Dictionary<DateTime, decimal> ScoreHistory { get; set; } = new();
        public Dictionary<DateTime, int> ViolationHistory { get; set; } = new();
        public Dictionary<ComplianceSeverity, List<int>> SeverityTrends { get; set; } = new();
        public decimal TrendDirection { get; set; }
        public string TrendDescription { get; set; } = string.Empty;
    }

    public class ComplianceTrendAnalysisDto
    {
        public DateTime AnalysisDate { get; set; }
        public ComplianceTrendDataDto TrendData { get; set; } = new();
        public List<ComplianceTrendInsightDto> Insights { get; set; } = new();
        public List<string> Predictions { get; set; } = new();
        public ComplianceRiskAssessmentDto RiskAssessment { get; set; } = new();
    }

    public class ComplianceTrendInsightDto
    {
        public string Category { get; set; } = string.Empty;
        public string Insight { get; set; } = string.Empty;
        public string Impact { get; set; } = string.Empty;
        public string Recommendation { get; set; } = string.Empty;
        public decimal Confidence { get; set; }
    }

    public class ComplianceRiskAssessmentDto
    {
        public string OverallRisk { get; set; } = string.Empty;
        public List<ComplianceRiskFactorDto> RiskFactors { get; set; } = new();
        public List<string> Mitigation { get; set; } = new();
        public decimal RiskScore { get; set; }
    }

    public class ComplianceRiskFactorDto
    {
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string Impact { get; set; } = string.Empty;
        public decimal Probability { get; set; }
        public string Severity { get; set; } = string.Empty;
    }

    public class ComplianceActionItemDto
    {
        public Guid Id { get; set; }
        public string Title { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public ComplianceSeverity Priority { get; set; }
        public DateTime DueDate { get; set; }
        public string AssignedTo { get; set; } = string.Empty;
        public string Status { get; set; } = string.Empty;
        public ComplianceFrameworkType Framework { get; set; }
    }

    public class ComplianceRemediationGuidanceDto
    {
        public Guid ViolationId { get; set; }
        public string Title { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public List<ComplianceRemediationStepDto> Steps { get; set; } = new();
        public List<string> BestPractices { get; set; } = new();
        public List<string> References { get; set; } = new();
        public int EstimatedEffortHours { get; set; }
        public string Difficulty { get; set; } = string.Empty;
    }

    public class ComplianceRemediationStepDto
    {
        public int Order { get; set; }
        public string Title { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string CodeExample { get; set; } = string.Empty;
        public List<string> Tools { get; set; } = new();
        public bool IsCompleted { get; set; }
    }

    public class ComplianceRemediationTemplateDto
    {
        public Guid Id { get; set; }
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public ComplianceFrameworkType Framework { get; set; }
        public string ViolationType { get; set; } = string.Empty;
        public List<ComplianceRemediationStepDto> Steps { get; set; } = new();
        public string Template { get; set; } = string.Empty;
    }
    
    // Note: ComplianceReportFormat is defined in IComplianceService.cs
}