using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AISecurityScanner.Application.DTOs;
using AISecurityScanner.Application.Models;
using AISecurityScanner.Domain.Entities;
using AISecurityScanner.Domain.Enums;

namespace AISecurityScanner.Application.Interfaces
{
    public interface IComplianceService
    {
        // Framework Management
        Task<List<ComplianceFrameworkDto>> GetAvailableFrameworksAsync(CancellationToken cancellationToken = default);
        Task<ComplianceFrameworkDto?> GetFrameworkAsync(ComplianceFrameworkType framework, CancellationToken cancellationToken = default);
        Task<bool> EnableFrameworkAsync(Guid organizationId, ComplianceFrameworkType framework, CancellationToken cancellationToken = default);
        Task<bool> DisableFrameworkAsync(Guid organizationId, ComplianceFrameworkType framework, CancellationToken cancellationToken = default);

        // Compliance Scanning
        Task<ComplianceScanResultDto> ScanForComplianceAsync(ComplianceScanRequest request, CancellationToken cancellationToken = default);
        Task<ComplianceScanResultDto> ScanRepositoryAsync(Guid repositoryId, List<ComplianceFrameworkType> frameworks, CancellationToken cancellationToken = default);
        Task<List<ComplianceScanResultDto>> GetComplianceScanHistoryAsync(Guid organizationId, ComplianceFrameworkType? framework = null, CancellationToken cancellationToken = default);

        // Compliance Reporting
        Task<ComplianceReportDto> GenerateComplianceReportAsync(ComplianceReportRequest request, CancellationToken cancellationToken = default);
        Task<ComplianceDashboardDto> GetComplianceDashboardAsync(Guid organizationId, CancellationToken cancellationToken = default);
        Task<ComplianceTrendAnalysisDto> GetComplianceTrendsAsync(Guid organizationId, DateTime fromDate, DateTime toDate, CancellationToken cancellationToken = default);

        // Violation Management
        Task<PagedResult<ComplianceViolationDto>> GetViolationsAsync(Guid organizationId, ComplianceViolationFilter filter, PaginationRequest pagination, CancellationToken cancellationToken = default);
        Task<bool> UpdateViolationStatusAsync(Guid violationId, ComplianceStatus status, string? notes = null, CancellationToken cancellationToken = default);
        Task<bool> BulkUpdateViolationsAsync(List<Guid> violationIds, ComplianceStatus status, string? notes = null, CancellationToken cancellationToken = default);

        // Remediation Guidance
        Task<ComplianceRemediationGuidanceDto> GetRemediationGuidanceAsync(Guid violationId, CancellationToken cancellationToken = default);
        Task<List<ComplianceRemediationTemplateDto>> GetRemediationTemplatesAsync(ComplianceFrameworkType framework, CancellationToken cancellationToken = default);

        // Evidence Collection
        Task<List<ComplianceEvidenceDto>> CollectComplianceEvidenceAsync(Guid organizationId, ComplianceFrameworkType framework, CancellationToken cancellationToken = default);
        Task<bool> AddManualEvidenceAsync(ComplianceEvidenceRequest request, CancellationToken cancellationToken = default);
    }

    public class ComplianceScanRequest
    {
        public Guid OrganizationId { get; set; }
        public List<Guid> RepositoryIds { get; set; } = new();
        public List<ComplianceFrameworkType> Frameworks { get; set; } = new();
        public List<string> FilePaths { get; set; } = new();
        public ComplianceScanOptions Options { get; set; } = new();
    }

    public class ComplianceScanOptions
    {
        public bool IncludeTestFiles { get; set; } = false;
        public bool IncludeThirdPartyCode { get; set; } = false;
        public bool EnableDeepScan { get; set; } = true;
        public bool GenerateEvidence { get; set; } = true;
        public List<string> ExcludePatterns { get; set; } = new();
        public Dictionary<string, object> CustomSettings { get; set; } = new();
    }

    public class ComplianceReportRequest
    {
        public Guid OrganizationId { get; set; }
        public List<ComplianceFrameworkType> Frameworks { get; set; } = new();
        public DateTime? FromDate { get; set; }
        public DateTime? ToDate { get; set; }
        public ComplianceReportFormat Format { get; set; } = ComplianceReportFormat.Html;
        public bool IncludeExecutiveSummary { get; set; } = true;
        public bool IncludeDetailedFindings { get; set; } = true;
        public bool IncludeRemediation { get; set; } = true;
        public bool IncludeEvidence { get; set; } = false;
    }

    public class ComplianceViolationFilter
    {
        public ComplianceFrameworkType? Framework { get; set; }
        public ComplianceSeverity? Severity { get; set; }
        public ComplianceStatus? Status { get; set; }
        public string? RequirementId { get; set; }
        public string? Category { get; set; }
        public Guid? RepositoryId { get; set; }
        public DateTime? FromDate { get; set; }
        public DateTime? ToDate { get; set; }
        public string? SearchTerm { get; set; }
    }

    public class ComplianceEvidenceRequest
    {
        public Guid OrganizationId { get; set; }
        public ComplianceFrameworkType Framework { get; set; }
        public string ControlId { get; set; } = string.Empty;
        public string EvidenceType { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public List<string> FilePaths { get; set; } = new();
        public Dictionary<string, object> Metadata { get; set; } = new();
    }

    public enum ComplianceReportFormat
    {
        Html,
        Pdf,
        Excel,
        Json,
        Csv
    }
}