using System;
using AISecurityScanner.Domain.Enums;

namespace AISecurityScanner.Application.Models
{
    public class StartScanRequest
    {
        public Guid RepositoryId { get; set; }
        public ScanType ScanType { get; set; } = ScanType.Manual;
        public string? Branch { get; set; }
        public string? CommitHash { get; set; }
        public string? TriggerSource { get; set; }
        public bool IncludeAIAnalysis { get; set; } = true;
        public bool CheckPackageHallucination { get; set; } = true;
        public string[]? PreferredAIProviders { get; set; }
    }
}