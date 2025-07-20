using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AISecurityScanner.Application.DTOs;
using AISecurityScanner.Application.Models;

namespace AISecurityScanner.Application.Interfaces
{
    public interface ISecurityScannerService
    {
        Task<ScanResult> StartScanAsync(StartScanRequest request, Guid userId, CancellationToken cancellationToken = default);
        Task<SecurityScanDto?> GetScanAsync(Guid scanId, CancellationToken cancellationToken = default);
        Task<PagedResult<SecurityScanDto>> GetScansAsync(Guid organizationId, PaginationRequest pagination, CancellationToken cancellationToken = default);
        Task<PagedResult<SecurityScanDto>> GetRepositoryScansAsync(Guid repositoryId, PaginationRequest pagination, CancellationToken cancellationToken = default);
        Task<bool> CancelScanAsync(Guid scanId, Guid userId, CancellationToken cancellationToken = default);
        Task<ScanResult> GetScanResultAsync(Guid scanId, CancellationToken cancellationToken = default);
        Task<List<VulnerabilityDto>> GetScanVulnerabilitiesAsync(Guid scanId, CancellationToken cancellationToken = default);
        Task<ScanMetrics> GetScanMetricsAsync(Guid scanId, CancellationToken cancellationToken = default);
        Task<bool> RetryFailedScanAsync(Guid scanId, Guid userId, CancellationToken cancellationToken = default);
    }
}