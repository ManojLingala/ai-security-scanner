using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AutoMapper;
using Microsoft.Extensions.Logging;
using AISecurityScanner.Application.DTOs;
using AISecurityScanner.Application.Interfaces;
using AISecurityScanner.Application.Models;
using AISecurityScanner.Domain.Entities;
using AISecurityScanner.Domain.Enums;
using AISecurityScanner.Domain.Interfaces;

namespace AISecurityScanner.Application.Services
{
    public class SecurityScannerService : ISecurityScannerService
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMapper _mapper;
        private readonly ILogger<SecurityScannerService> _logger;
        private readonly IAIProviderService _aiProviderService;

        public SecurityScannerService(
            IUnitOfWork unitOfWork,
            IMapper mapper,
            ILogger<SecurityScannerService> logger,
            IAIProviderService aiProviderService)
        {
            _unitOfWork = unitOfWork;
            _mapper = mapper;
            _logger = logger;
            _aiProviderService = aiProviderService;
        }

        public async Task<ScanResult> StartScanAsync(StartScanRequest request, Guid userId, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation("Starting scan for repository {RepositoryId} by user {UserId}", request.RepositoryId, userId);

                // Validate repository exists and user has access
                var repository = await _unitOfWork.Repositories.GetByIdAsync(request.RepositoryId, cancellationToken);
                if (repository == null)
                {
                    return new ScanResult
                    {
                        IsSuccess = false,
                        ErrorMessage = "Repository not found"
                    };
                }

                // Check organization scan limits
                var canScan = await _unitOfWork.Organizations.CanPerformScanAsync(repository.OrganizationId, cancellationToken);
                if (!canScan)
                {
                    return new ScanResult
                    {
                        IsSuccess = false,
                        ErrorMessage = "Monthly scan limit exceeded"
                    };
                }

                // Create scan entity
                var scan = new SecurityScan
                {
                    Id = Guid.NewGuid(),
                    RepositoryId = request.RepositoryId,
                    UserId = userId,
                    StartedAt = DateTime.UtcNow,
                    Status = ScanStatus.Pending,
                    ScanType = request.ScanType,
                    TriggerSource = request.TriggerSource,
                    Branch = request.Branch ?? repository.DefaultBranch,
                    CommitHash = request.CommitHash,
                    CreatedAt = DateTime.UtcNow,
                    ModifiedAt = DateTime.UtcNow
                };

                await _unitOfWork.SecurityScans.AddAsync(scan, cancellationToken);
                await _unitOfWork.Organizations.IncrementMonthlyScansAsync(repository.OrganizationId, cancellationToken);

                // Update repository last scan
                repository.LastScanAt = DateTime.UtcNow;
                repository.TotalScans++;
                await _unitOfWork.Repositories.UpdateAsync(repository, cancellationToken);

                await _unitOfWork.SaveChangesAsync(cancellationToken);

                _logger.LogInformation("Scan {ScanId} created successfully", scan.Id);

                return new ScanResult
                {
                    ScanId = scan.Id,
                    IsSuccess = true,
                    ScanDetails = _mapper.Map<SecurityScanDto>(scan)
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error starting scan for repository {RepositoryId}", request.RepositoryId);
                return new ScanResult
                {
                    IsSuccess = false,
                    ErrorMessage = "Failed to start scan"
                };
            }
        }

        public async Task<SecurityScanDto?> GetScanAsync(Guid scanId, CancellationToken cancellationToken = default)
        {
            var scan = await _unitOfWork.SecurityScans.GetByIdAsync(scanId, cancellationToken);
            return scan != null ? _mapper.Map<SecurityScanDto>(scan) : null;
        }

        public async Task<PagedResult<SecurityScanDto>> GetScansAsync(Guid organizationId, PaginationRequest pagination, CancellationToken cancellationToken = default)
        {
            var scans = await _unitOfWork.SecurityScans.FindAsync(
                s => s.Repository.OrganizationId == organizationId,
                cancellationToken);

            var totalCount = scans.Count();
            var pagedScans = scans
                .Skip((pagination.PageNumber - 1) * pagination.PageSize)
                .Take(pagination.PageSize);

            return new PagedResult<SecurityScanDto>
            {
                Items = _mapper.Map<IEnumerable<SecurityScanDto>>(pagedScans),
                TotalCount = totalCount,
                PageNumber = pagination.PageNumber,
                PageSize = pagination.PageSize
            };
        }

        public async Task<PagedResult<SecurityScanDto>> GetRepositoryScansAsync(Guid repositoryId, PaginationRequest pagination, CancellationToken cancellationToken = default)
        {
            var scans = await _unitOfWork.SecurityScans.FindAsync(
                s => s.RepositoryId == repositoryId,
                cancellationToken);

            var totalCount = scans.Count();
            var pagedScans = scans
                .Skip((pagination.PageNumber - 1) * pagination.PageSize)
                .Take(pagination.PageSize);

            return new PagedResult<SecurityScanDto>
            {
                Items = _mapper.Map<IEnumerable<SecurityScanDto>>(pagedScans),
                TotalCount = totalCount,
                PageNumber = pagination.PageNumber,
                PageSize = pagination.PageSize
            };
        }

        public async Task<bool> CancelScanAsync(Guid scanId, Guid userId, CancellationToken cancellationToken = default)
        {
            try
            {
                var scan = await _unitOfWork.SecurityScans.GetByIdAsync(scanId, cancellationToken);
                if (scan == null || scan.Status != ScanStatus.InProgress)
                {
                    return false;
                }

                scan.Status = ScanStatus.Cancelled;
                scan.CompletedAt = DateTime.UtcNow;
                scan.ModifiedAt = DateTime.UtcNow;

                await _unitOfWork.SecurityScans.UpdateAsync(scan, cancellationToken);
                await _unitOfWork.SaveChangesAsync(cancellationToken);

                _logger.LogInformation("Scan {ScanId} cancelled by user {UserId}", scanId, userId);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error cancelling scan {ScanId}", scanId);
                return false;
            }
        }

        public async Task<ScanResult> GetScanResultAsync(Guid scanId, CancellationToken cancellationToken = default)
        {
            var scan = await _unitOfWork.SecurityScans.GetByIdAsync(scanId, cancellationToken);
            if (scan == null)
            {
                return new ScanResult
                {
                    IsSuccess = false,
                    ErrorMessage = "Scan not found"
                };
            }

            var vulnerabilities = await _unitOfWork.Vulnerabilities.FindAsync(
                v => v.SecurityScanId == scanId,
                cancellationToken);

            var metrics = new ScanMetrics
            {
                TotalLines = scan.TotalLinesScanned,
                AIGeneratedLines = scan.AILinesDetected,
                TotalVulnerabilities = scan.VulnerabilitiesFound,
                CriticalVulnerabilities = scan.CriticalCount,
                HighVulnerabilities = scan.HighCount,
                MediumVulnerabilities = scan.MediumCount,
                LowVulnerabilities = scan.LowCount,
                InfoVulnerabilities = scan.InfoCount,
                ScanDuration = scan.ScanDuration ?? TimeSpan.Zero,
                AIProvidersUsed = !string.IsNullOrEmpty(scan.AIProviderUsed) ? new[] { scan.AIProviderUsed } : Array.Empty<string>()
            };

            return new ScanResult
            {
                ScanId = scanId,
                IsSuccess = true,
                ScanDetails = _mapper.Map<SecurityScanDto>(scan),
                Vulnerabilities = _mapper.Map<List<VulnerabilityDto>>(vulnerabilities),
                Metrics = metrics
            };
        }

        public async Task<List<VulnerabilityDto>> GetScanVulnerabilitiesAsync(Guid scanId, CancellationToken cancellationToken = default)
        {
            var vulnerabilities = await _unitOfWork.Vulnerabilities.FindAsync(
                v => v.SecurityScanId == scanId,
                cancellationToken);

            return _mapper.Map<List<VulnerabilityDto>>(vulnerabilities);
        }

        public async Task<ScanMetrics> GetScanMetricsAsync(Guid scanId, CancellationToken cancellationToken = default)
        {
            var scan = await _unitOfWork.SecurityScans.GetByIdAsync(scanId, cancellationToken);
            if (scan == null)
            {
                return new ScanMetrics();
            }

            return new ScanMetrics
            {
                TotalLines = scan.TotalLinesScanned,
                AIGeneratedLines = scan.AILinesDetected,
                TotalVulnerabilities = scan.VulnerabilitiesFound,
                CriticalVulnerabilities = scan.CriticalCount,
                HighVulnerabilities = scan.HighCount,
                MediumVulnerabilities = scan.MediumCount,
                LowVulnerabilities = scan.LowCount,
                InfoVulnerabilities = scan.InfoCount,
                ScanDuration = scan.ScanDuration ?? TimeSpan.Zero,
                AIProvidersUsed = !string.IsNullOrEmpty(scan.AIProviderUsed) ? new[] { scan.AIProviderUsed } : Array.Empty<string>()
            };
        }

        public async Task<bool> RetryFailedScanAsync(Guid scanId, Guid userId, CancellationToken cancellationToken = default)
        {
            try
            {
                var scan = await _unitOfWork.SecurityScans.GetByIdAsync(scanId, cancellationToken);
                if (scan == null || scan.Status != ScanStatus.Failed)
                {
                    return false;
                }

                scan.Status = ScanStatus.Pending;
                scan.ErrorMessage = null;
                scan.ModifiedAt = DateTime.UtcNow;

                await _unitOfWork.SecurityScans.UpdateAsync(scan, cancellationToken);
                await _unitOfWork.SaveChangesAsync(cancellationToken);

                _logger.LogInformation("Scan {ScanId} queued for retry by user {UserId}", scanId, userId);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrying scan {ScanId}", scanId);
                return false;
            }
        }
    }
}