using System;
using System.Collections.Generic;
using AISecurityScanner.Application.DTOs;

namespace AISecurityScanner.Application.Models
{
    public class ScanResult
    {
        public Guid ScanId { get; set; }
        public bool IsSuccess { get; set; }
        public string? ErrorMessage { get; set; }
        public SecurityScanDto? ScanDetails { get; set; }
        public List<VulnerabilityDto> Vulnerabilities { get; set; } = new();
        public ScanMetrics Metrics { get; set; } = new();
    }

    public class ScanMetrics
    {
        public long TotalFiles { get; set; }
        public long TotalLines { get; set; }
        public long AIGeneratedLines { get; set; }
        public decimal AICodePercentage => TotalLines > 0 ? (decimal)AIGeneratedLines / TotalLines * 100 : 0;
        public int TotalVulnerabilities { get; set; }
        public int CriticalVulnerabilities { get; set; }
        public int HighVulnerabilities { get; set; }
        public int MediumVulnerabilities { get; set; }
        public int LowVulnerabilities { get; set; }
        public int InfoVulnerabilities { get; set; }
        public TimeSpan ScanDuration { get; set; }
        public decimal VulnerabilityDensity => TotalLines > 0 ? (decimal)TotalVulnerabilities / TotalLines * 1000 : 0;
        public string[] AIProvidersUsed { get; set; } = Array.Empty<string>();
        public decimal TotalCost { get; set; }
    }
}