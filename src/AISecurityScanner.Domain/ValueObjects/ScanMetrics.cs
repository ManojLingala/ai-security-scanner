using System;

namespace AISecurityScanner.Domain.ValueObjects
{
    public class ScanMetrics
    {
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
    }
}