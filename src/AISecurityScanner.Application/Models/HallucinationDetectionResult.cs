using System;
using System.Collections.Generic;
using AISecurityScanner.Domain.Enums;

namespace AISecurityScanner.Application.Models
{
    public class HallucinationDetectionResult
    {
        public string PackageName { get; set; } = "";
        public string PackageManager { get; set; } = "";
        public string? Version { get; set; }
        public bool IsHallucinated { get; set; }
        public decimal Confidence { get; set; }
        public string? Reason { get; set; }
        public VulnerabilitySeverity Severity { get; set; }
        public bool ExistsInRegistry { get; set; }
        public decimal PatternMatchScore { get; set; }
        public decimal TyposquattingRisk { get; set; }
        public decimal MetadataScore { get; set; }
        public List<string> SuspiciousPatterns { get; set; } = new();
        public DateTime CheckedAt { get; set; }
    }
}