using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AISecurityScanner.Application.DTOs;
using AISecurityScanner.Application.Models;

namespace AISecurityScanner.Application.Interfaces
{
    public interface IRepositoryService
    {
        Task<PagedResult<RepositoryDto>> GetRepositoriesAsync(Guid organizationId, PaginationRequest pagination, CancellationToken cancellationToken = default);
        Task<RepositoryDto?> GetRepositoryAsync(Guid repositoryId, CancellationToken cancellationToken = default);
        Task<RepositoryDto> CreateRepositoryAsync(CreateRepositoryRequest request, CancellationToken cancellationToken = default);
        Task<RepositoryDto> UpdateRepositoryAsync(Guid repositoryId, UpdateRepositoryRequest request, CancellationToken cancellationToken = default);
        Task<bool> DeleteRepositoryAsync(Guid repositoryId, CancellationToken cancellationToken = default);
        Task<bool> SetupWebhookAsync(Guid repositoryId, CancellationToken cancellationToken = default);
        Task<bool> TestRepositoryConnectionAsync(Guid repositoryId, CancellationToken cancellationToken = default);
        Task<RepositoryMetrics> GetRepositoryMetricsAsync(Guid repositoryId, CancellationToken cancellationToken = default);
        Task<List<RepositoryDto>> GetRecentlyScannedRepositoriesAsync(Guid organizationId, int limit = 10, CancellationToken cancellationToken = default);
        Task<bool> UpdateRepositoryStatsAsync(Guid repositoryId, long totalLines, long aiLines, CancellationToken cancellationToken = default);
    }

    public class CreateRepositoryRequest
    {
        public string Name { get; set; } = string.Empty;
        public string GitUrl { get; set; } = string.Empty;
        public Guid OrganizationId { get; set; }
        public string Language { get; set; } = string.Empty;
        public string? DefaultBranch { get; set; }
        public bool IsPrivate { get; set; } = true;
        public bool AutoScanEnabled { get; set; } = false;
        public string? GitHubInstallationId { get; set; }
    }

    public class UpdateRepositoryRequest
    {
        public string? Name { get; set; }
        public string? Language { get; set; }
        public string? DefaultBranch { get; set; }
        public bool? AutoScanEnabled { get; set; }
    }

    public class RepositoryMetrics
    {
        public Guid RepositoryId { get; set; }
        public string RepositoryName { get; set; } = string.Empty;
        public int TotalScans { get; set; }
        public DateTime? LastScanAt { get; set; }
        public long TotalLinesOfCode { get; set; }
        public long AIGeneratedLines { get; set; }
        public decimal AICodePercentage { get; set; }
        public int TotalVulnerabilities { get; set; }
        public int OpenVulnerabilities { get; set; }
        public int ResolvedVulnerabilities { get; set; }
        public Dictionary<string, int> VulnerabilitiesBySeverity { get; set; } = new();
        public Dictionary<string, int> VulnerabilitiesByType { get; set; } = new();
        public List<ScanTrend> ScanHistory { get; set; } = new();
        public decimal VulnerabilityTrend { get; set; }
        public bool IsVulnerabilityTrendIncreasing { get; set; }
    }

    public class ScanTrend
    {
        public DateTime Date { get; set; }
        public int VulnerabilityCount { get; set; }
        public long LinesScanned { get; set; }
        public TimeSpan ScanDuration { get; set; }
    }
}