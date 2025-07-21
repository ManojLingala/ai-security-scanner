using System;
using System.Collections.Generic;
using AISecurityScanner.Domain.Enums;

namespace AISecurityScanner.Application.Models
{

    // Note: Using ComplianceScanRequest, ComplianceReportRequest, ComplianceViolationFilter,
    // ComplianceEvidenceRequest, and PaginationRequest from Interfaces namespace

    public class ComplianceMonitoringRequest
    {
        public Guid OrganizationId { get; set; }
        public string RepositoryPath { get; set; } = string.Empty;
        public List<ComplianceFrameworkType> Frameworks { get; set; } = new();
        public ComplianceMonitoringOptions Options { get; set; } = new();
    }

    public class ComplianceMonitoringOptions
    {
        public bool EnableRealTimeScanning { get; set; } = true;
        public bool EnablePeriodicScanning { get; set; } = true;
        public int PeriodicScanIntervalMinutes { get; set; } = 60;
        public bool NotifyOnCriticalViolations { get; set; } = true;
        public bool AutoRemediateSimpleIssues { get; set; } = false;
        public List<string> WatchPaths { get; set; } = new();
        public List<string> IgnorePaths { get; set; } = new();
    }

    public class ComplianceBulkUpdateRequest
    {
        public List<Guid> ViolationIds { get; set; } = new();
        public ComplianceStatus NewStatus { get; set; }
        public string? Notes { get; set; }
        public string? AssignedTo { get; set; }
        public DateTime? DueDate { get; set; }
    }

    public class ComplianceExportRequest
    {
        public Guid OrganizationId { get; set; }
        public List<ComplianceFrameworkType> Frameworks { get; set; } = new();
        public ComplianceExportFormat Format { get; set; } = ComplianceExportFormat.CSV;
        public bool IncludeViolations { get; set; } = true;
        public bool IncludeEvidence { get; set; } = true;
        public bool IncludeRecommendations { get; set; } = true;
        public DateTime? FromDate { get; set; }
        public DateTime? ToDate { get; set; }
    }

    public enum ComplianceExportFormat
    {
        CSV,
        JSON,
        XML,
        Excel
    }

    public class ComplianceNotificationRequest
    {
        public Guid OrganizationId { get; set; }
        public ComplianceNotificationType Type { get; set; }
        public string Recipient { get; set; } = string.Empty;
        public ComplianceSeverity? MinimumSeverity { get; set; }
        public List<ComplianceFrameworkType> Frameworks { get; set; } = new();
    }

    public enum ComplianceNotificationType
    {
        Email,
        Webhook,
        Slack,
        Teams,
        SMS
    }

    public class ComplianceApiKeyRequest
    {
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public List<string> Permissions { get; set; } = new();
        public DateTime? ExpiresAt { get; set; }
        public List<ComplianceFrameworkType> AllowedFrameworks { get; set; } = new();
    }

    public class ComplianceWebhookRequest
    {
        public string Name { get; set; } = string.Empty;
        public string Url { get; set; } = string.Empty;
        public string Secret { get; set; } = string.Empty;
        public List<ComplianceWebhookEvent> Events { get; set; } = new();
        public bool IsActive { get; set; } = true;
    }

    public enum ComplianceWebhookEvent
    {
        ViolationDetected,
        ViolationResolved,
        ScanCompleted,
        ReportGenerated,
        ComplianceScoreChanged,
        CriticalViolation
    }

    public class ComplianceScheduleRequest
    {
        public Guid OrganizationId { get; set; }
        public string Name { get; set; } = string.Empty;
        public List<ComplianceFrameworkType> Frameworks { get; set; } = new();
        public ComplianceScheduleFrequency Frequency { get; set; }
        public TimeSpan TimeOfDay { get; set; }
        public List<DayOfWeek>? DaysOfWeek { get; set; }
        public int? DayOfMonth { get; set; }
        public bool IsActive { get; set; } = true;
    }

    public enum ComplianceScheduleFrequency
    {
        Daily,
        Weekly,
        BiWeekly,
        Monthly,
        Quarterly,
        Annually
    }
}