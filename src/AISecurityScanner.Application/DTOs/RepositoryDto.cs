using System;

namespace AISecurityScanner.Application.DTOs
{
    public class RepositoryDto
    {
        public Guid Id { get; set; }
        public string Name { get; set; } = string.Empty;
        public string GitUrl { get; set; } = string.Empty;
        public Guid OrganizationId { get; set; }
        public string Language { get; set; } = string.Empty;
        public DateTime? LastScanAt { get; set; }
        public int TotalScans { get; set; }
        public decimal AICodePercentage { get; set; }
        public string? DefaultBranch { get; set; }
        public bool IsPrivate { get; set; }
        public bool AutoScanEnabled { get; set; }
        public long TotalLinesOfCode { get; set; }
        public long AIGeneratedLines { get; set; }
        public DateTime CreatedAt { get; set; }
        
        // Latest scan info
        public int? LatestVulnerabilityCount { get; set; }
        public string? LatestScanStatus { get; set; }
    }
}