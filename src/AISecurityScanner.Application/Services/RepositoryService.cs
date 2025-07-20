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
using AISecurityScanner.Domain.Interfaces;

namespace AISecurityScanner.Application.Services
{
    public class RepositoryService : IRepositoryService
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMapper _mapper;
        private readonly ILogger<RepositoryService> _logger;

        public RepositoryService(
            IUnitOfWork unitOfWork,
            IMapper mapper,
            ILogger<RepositoryService> logger)
        {
            _unitOfWork = unitOfWork;
            _mapper = mapper;
            _logger = logger;
        }

        public async Task<PagedResult<RepositoryDto>> GetRepositoriesAsync(Guid organizationId, PaginationRequest pagination, CancellationToken cancellationToken = default)
        {
            var repositories = await _unitOfWork.Repositories.FindAsync(
                r => r.OrganizationId == organizationId,
                cancellationToken);

            if (!string.IsNullOrEmpty(pagination.SearchTerm))
            {
                repositories = repositories.Where(r =>
                    r.Name.Contains(pagination.SearchTerm, StringComparison.OrdinalIgnoreCase) ||
                    r.Language.Contains(pagination.SearchTerm, StringComparison.OrdinalIgnoreCase));
            }

            var totalCount = repositories.Count();
            var pagedRepositories = repositories
                .Skip((pagination.PageNumber - 1) * pagination.PageSize)
                .Take(pagination.PageSize);

            return new PagedResult<RepositoryDto>
            {
                Items = _mapper.Map<IEnumerable<RepositoryDto>>(pagedRepositories),
                TotalCount = totalCount,
                PageNumber = pagination.PageNumber,
                PageSize = pagination.PageSize
            };
        }

        public async Task<RepositoryDto?> GetRepositoryAsync(Guid repositoryId, CancellationToken cancellationToken = default)
        {
            var repository = await _unitOfWork.Repositories.GetByIdAsync(repositoryId, cancellationToken);
            return repository != null ? _mapper.Map<RepositoryDto>(repository) : null;
        }

        public async Task<RepositoryDto> CreateRepositoryAsync(CreateRepositoryRequest request, CancellationToken cancellationToken = default)
        {
            try
            {
                // Check if organization can add more repositories
                var canAdd = await _unitOfWork.Organizations.CanAddRepositoryAsync(request.OrganizationId, cancellationToken);
                if (!canAdd)
                {
                    throw new InvalidOperationException("Repository limit exceeded for organization");
                }

                var repository = new Repository
                {
                    Id = Guid.NewGuid(),
                    Name = request.Name,
                    GitUrl = request.GitUrl,
                    OrganizationId = request.OrganizationId,
                    Language = request.Language,
                    DefaultBranch = request.DefaultBranch ?? "main",
                    IsPrivate = request.IsPrivate,
                    AutoScanEnabled = request.AutoScanEnabled,
                    GitHubInstallationId = request.GitHubInstallationId,
                    TotalScans = 0,
                    AICodePercentage = 0,
                    TotalLinesOfCode = 0,
                    AIGeneratedLines = 0,
                    CreatedAt = DateTime.UtcNow,
                    ModifiedAt = DateTime.UtcNow
                };

                await _unitOfWork.Repositories.AddAsync(repository, cancellationToken);
                await _unitOfWork.SaveChangesAsync(cancellationToken);

                _logger.LogInformation("Repository {RepositoryName} created with ID {RepositoryId}", request.Name, repository.Id);

                return _mapper.Map<RepositoryDto>(repository);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating repository {RepositoryName}", request.Name);
                throw;
            }
        }

        public async Task<RepositoryDto> UpdateRepositoryAsync(Guid repositoryId, UpdateRepositoryRequest request, CancellationToken cancellationToken = default)
        {
            try
            {
                var repository = await _unitOfWork.Repositories.GetByIdAsync(repositoryId, cancellationToken);
                if (repository == null)
                {
                    throw new ArgumentException("Repository not found");
                }

                if (!string.IsNullOrEmpty(request.Name))
                    repository.Name = request.Name;

                if (!string.IsNullOrEmpty(request.Language))
                    repository.Language = request.Language;

                if (!string.IsNullOrEmpty(request.DefaultBranch))
                    repository.DefaultBranch = request.DefaultBranch;

                if (request.AutoScanEnabled.HasValue)
                    repository.AutoScanEnabled = request.AutoScanEnabled.Value;

                repository.ModifiedAt = DateTime.UtcNow;

                await _unitOfWork.Repositories.UpdateAsync(repository, cancellationToken);
                await _unitOfWork.SaveChangesAsync(cancellationToken);

                _logger.LogInformation("Repository {RepositoryId} updated", repositoryId);

                return _mapper.Map<RepositoryDto>(repository);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating repository {RepositoryId}", repositoryId);
                throw;
            }
        }

        public async Task<bool> DeleteRepositoryAsync(Guid repositoryId, CancellationToken cancellationToken = default)
        {
            try
            {
                var repository = await _unitOfWork.Repositories.GetByIdAsync(repositoryId, cancellationToken);
                if (repository == null)
                {
                    return false;
                }

                await _unitOfWork.Repositories.DeleteAsync(repository, cancellationToken);
                await _unitOfWork.SaveChangesAsync(cancellationToken);

                _logger.LogInformation("Repository {RepositoryId} deleted", repositoryId);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting repository {RepositoryId}", repositoryId);
                return false;
            }
        }

        public async Task<bool> SetupWebhookAsync(Guid repositoryId, CancellationToken cancellationToken = default)
        {
            try
            {
                var repository = await _unitOfWork.Repositories.GetByIdAsync(repositoryId, cancellationToken);
                if (repository == null)
                {
                    return false;
                }

                // Generate webhook URL and secret
                var webhookUrl = $"https://api.aisecurityscanner.com/webhooks/github/{repositoryId}";
                var webhookSecret = Guid.NewGuid().ToString("N");

                repository.WebhookUrl = webhookUrl;
                repository.WebhookSecret = webhookSecret;
                repository.ModifiedAt = DateTime.UtcNow;

                await _unitOfWork.Repositories.UpdateAsync(repository, cancellationToken);
                await _unitOfWork.SaveChangesAsync(cancellationToken);

                _logger.LogInformation("Webhook setup for repository {RepositoryId}", repositoryId);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error setting up webhook for repository {RepositoryId}", repositoryId);
                return false;
            }
        }

        public async Task<bool> TestRepositoryConnectionAsync(Guid repositoryId, CancellationToken cancellationToken = default)
        {
            try
            {
                var repository = await _unitOfWork.Repositories.GetByIdAsync(repositoryId, cancellationToken);
                if (repository == null)
                {
                    return false;
                }

                // TODO: Implement actual Git connection test
                // This would involve cloning or fetching from the repository
                
                _logger.LogInformation("Repository connection test for {RepositoryId} completed", repositoryId);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error testing repository connection {RepositoryId}", repositoryId);
                return false;
            }
        }

        public async Task<RepositoryMetrics> GetRepositoryMetricsAsync(Guid repositoryId, CancellationToken cancellationToken = default)
        {
            var repository = await _unitOfWork.Repositories.GetByIdAsync(repositoryId, cancellationToken);
            if (repository == null)
            {
                throw new ArgumentException("Repository not found");
            }

            var scans = await _unitOfWork.SecurityScans.FindAsync(
                s => s.RepositoryId == repositoryId,
                cancellationToken);

            var vulnerabilities = await _unitOfWork.Vulnerabilities.FindAsync(
                v => scans.Select(s => s.Id).Contains(v.SecurityScanId),
                cancellationToken);

            var scanHistory = scans
                .OrderBy(s => s.StartedAt)
                .Select(s => new ScanTrend
                {
                    Date = s.StartedAt,
                    VulnerabilityCount = s.VulnerabilitiesFound,
                    LinesScanned = s.TotalLinesScanned,
                    ScanDuration = s.ScanDuration ?? TimeSpan.Zero
                })
                .ToList();

            var totalVulns = vulnerabilities.Count();
            var openVulns = vulnerabilities.Count(v => v.Status == Domain.Enums.VulnerabilityStatus.Open);
            var resolvedVulns = vulnerabilities.Count(v => v.Status == Domain.Enums.VulnerabilityStatus.Resolved);

            return new RepositoryMetrics
            {
                RepositoryId = repositoryId,
                RepositoryName = repository.Name,
                TotalScans = repository.TotalScans,
                LastScanAt = repository.LastScanAt,
                TotalLinesOfCode = repository.TotalLinesOfCode,
                AIGeneratedLines = repository.AIGeneratedLines,
                AICodePercentage = repository.AICodePercentage,
                TotalVulnerabilities = totalVulns,
                OpenVulnerabilities = openVulns,
                ResolvedVulnerabilities = resolvedVulns,
                VulnerabilitiesBySeverity = vulnerabilities
                    .GroupBy(v => v.Severity.ToString())
                    .ToDictionary(g => g.Key, g => g.Count()),
                VulnerabilitiesByType = vulnerabilities
                    .GroupBy(v => v.Type)
                    .ToDictionary(g => g.Key, g => g.Count()),
                ScanHistory = scanHistory
            };
        }

        public async Task<List<RepositoryDto>> GetRecentlyScannedRepositoriesAsync(Guid organizationId, int limit = 10, CancellationToken cancellationToken = default)
        {
            var repositories = await _unitOfWork.Repositories.FindAsync(
                r => r.OrganizationId == organizationId && r.LastScanAt.HasValue,
                cancellationToken);

            var recentRepositories = repositories
                .OrderByDescending(r => r.LastScanAt)
                .Take(limit);

            return _mapper.Map<List<RepositoryDto>>(recentRepositories);
        }

        public async Task<bool> UpdateRepositoryStatsAsync(Guid repositoryId, long totalLines, long aiLines, CancellationToken cancellationToken = default)
        {
            try
            {
                var repository = await _unitOfWork.Repositories.GetByIdAsync(repositoryId, cancellationToken);
                if (repository == null)
                {
                    return false;
                }

                repository.TotalLinesOfCode = totalLines;
                repository.AIGeneratedLines = aiLines;
                repository.AICodePercentage = totalLines > 0 ? (decimal)aiLines / totalLines * 100 : 0;
                repository.ModifiedAt = DateTime.UtcNow;

                await _unitOfWork.Repositories.UpdateAsync(repository, cancellationToken);
                await _unitOfWork.SaveChangesAsync(cancellationToken);

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating repository stats for {RepositoryId}", repositoryId);
                return false;
            }
        }
    }
}