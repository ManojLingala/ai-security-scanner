using System;
using AISecurityScanner.Domain.Enums;

namespace AISecurityScanner.Application.DTOs
{
    public class SecurityScanDto
    {
        public Guid Id { get; set; }
        public Guid RepositoryId { get; set; }
        public string RepositoryName { get; set; } = string.Empty;
        public Guid UserId { get; set; }
        public string UserName { get; set; } = string.Empty;
        public DateTime StartedAt { get; set; }
        public DateTime? CompletedAt { get; set; }
        public ScanStatus Status { get; set; }
        public ScanType ScanType { get; set; }
        public string? TriggerSource { get; set; }
        public string? Branch { get; set; }
        public string? CommitHash { get; set; }
        public long TotalLinesScanned { get; set; }
        public long AILinesDetected { get; set; }
        public decimal AICodePercentage => TotalLinesScanned > 0 ? (decimal)AILinesDetected / TotalLinesScanned * 100 : 0;
        public TimeSpan? ScanDuration { get; set; }
        public string? AIProviderUsed { get; set; }
        public int VulnerabilitiesFound { get; set; }
        public int CriticalCount { get; set; }
        public int HighCount { get; set; }
        public int MediumCount { get; set; }
        public int LowCount { get; set; }
        public int InfoCount { get; set; }
        public string? ErrorMessage { get; set; }
        public DateTime CreatedAt { get; set; }
    }
}