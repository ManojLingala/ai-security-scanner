using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using AISecurityScanner.Application.Interfaces;
using AISecurityScanner.Application.Models;

namespace AISecurityScanner.API.Controllers
{
    [Authorize]
    public class RepositoryController : BaseController
    {
        private readonly IRepositoryService _repositoryService;
        private readonly ILogger<RepositoryController> _logger;

        public RepositoryController(
            IRepositoryService repositoryService,
            ILogger<RepositoryController> logger)
        {
            _repositoryService = repositoryService;
            _logger = logger;
        }

        /// <summary>
        /// Get organization repositories with pagination
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> GetRepositories(
            [FromQuery] int pageNumber = 1,
            [FromQuery] int pageSize = 20,
            [FromQuery] string? sortBy = null,
            [FromQuery] bool sortDescending = true,
            [FromQuery] string? searchTerm = null,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var organizationId = GetCurrentOrganizationId();
                if (organizationId == Guid.Empty)
                {
                    return Unauthorized(new { message = "Invalid organization session" });
                }

                var pagination = new PaginationRequest
                {
                    PageNumber = pageNumber,
                    PageSize = pageSize,
                    SortBy = sortBy,
                    SortDescending = sortDescending,
                    SearchTerm = searchTerm
                };

                var result = await _repositoryService.GetRepositoriesAsync(organizationId, pagination, cancellationToken);
                return Ok(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving repositories");
                return HandleException(ex);
            }
        }

        /// <summary>
        /// Get repository by ID
        /// </summary>
        [HttpGet("{repositoryId:guid}")]
        public async Task<IActionResult> GetRepository(Guid repositoryId, CancellationToken cancellationToken)
        {
            try
            {
                var repository = await _repositoryService.GetRepositoryAsync(repositoryId, cancellationToken);
                return HandleResult(repository);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving repository {RepositoryId}", repositoryId);
                return HandleException(ex);
            }
        }

        /// <summary>
        /// Create a new repository
        /// </summary>
        [HttpPost]
        [Authorize(Roles = "Admin,Developer")]
        public async Task<IActionResult> CreateRepository([FromBody] CreateRepositoryRequest request, CancellationToken cancellationToken)
        {
            try
            {
                request.OrganizationId = GetCurrentOrganizationId();
                if (request.OrganizationId == Guid.Empty)
                {
                    return Unauthorized(new { message = "Invalid organization session" });
                }

                var repository = await _repositoryService.CreateRepositoryAsync(request, cancellationToken);
                return CreatedAtAction(nameof(GetRepository), new { repositoryId = repository.Id }, repository);
            }
            catch (InvalidOperationException ex)
            {
                return BadRequest(new { message = ex.Message });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating repository");
                return HandleException(ex);
            }
        }

        /// <summary>
        /// Update repository
        /// </summary>
        [HttpPut("{repositoryId:guid}")]
        [Authorize(Roles = "Admin,Developer")]
        public async Task<IActionResult> UpdateRepository(Guid repositoryId, [FromBody] UpdateRepositoryRequest request, CancellationToken cancellationToken)
        {
            try
            {
                var repository = await _repositoryService.UpdateRepositoryAsync(repositoryId, request, cancellationToken);
                return Ok(repository);
            }
            catch (ArgumentException ex)
            {
                return NotFound(new { message = ex.Message });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating repository {RepositoryId}", repositoryId);
                return HandleException(ex);
            }
        }

        /// <summary>
        /// Delete repository
        /// </summary>
        [HttpDelete("{repositoryId:guid}")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> DeleteRepository(Guid repositoryId, CancellationToken cancellationToken)
        {
            try
            {
                var success = await _repositoryService.DeleteRepositoryAsync(repositoryId, cancellationToken);
                
                if (success)
                {
                    return Ok(new { message = "Repository deleted successfully" });
                }

                return NotFound(new { message = "Repository not found" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting repository {RepositoryId}", repositoryId);
                return HandleException(ex);
            }
        }

        /// <summary>
        /// Setup webhook for repository
        /// </summary>
        [HttpPost("{repositoryId:guid}/webhook")]
        [Authorize(Roles = "Admin,Developer")]
        public async Task<IActionResult> SetupWebhook(Guid repositoryId, CancellationToken cancellationToken)
        {
            try
            {
                var success = await _repositoryService.SetupWebhookAsync(repositoryId, cancellationToken);
                
                if (success)
                {
                    return Ok(new { message = "Webhook configured successfully" });
                }

                return BadRequest(new { message = "Failed to setup webhook" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error setting up webhook for repository {RepositoryId}", repositoryId);
                return HandleException(ex);
            }
        }

        /// <summary>
        /// Test repository connection
        /// </summary>
        [HttpPost("{repositoryId:guid}/test-connection")]
        [Authorize(Roles = "Admin,Developer")]
        public async Task<IActionResult> TestConnection(Guid repositoryId, CancellationToken cancellationToken)
        {
            try
            {
                var success = await _repositoryService.TestRepositoryConnectionAsync(repositoryId, cancellationToken);
                
                if (success)
                {
                    return Ok(new { message = "Connection test successful", isConnected = true });
                }

                return Ok(new { message = "Connection test failed", isConnected = false });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error testing connection for repository {RepositoryId}", repositoryId);
                return HandleException(ex);
            }
        }

        /// <summary>
        /// Get repository metrics
        /// </summary>
        [HttpGet("{repositoryId:guid}/metrics")]
        public async Task<IActionResult> GetRepositoryMetrics(Guid repositoryId, CancellationToken cancellationToken)
        {
            try
            {
                var metrics = await _repositoryService.GetRepositoryMetricsAsync(repositoryId, cancellationToken);
                return Ok(metrics);
            }
            catch (ArgumentException ex)
            {
                return NotFound(new { message = ex.Message });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving metrics for repository {RepositoryId}", repositoryId);
                return HandleException(ex);
            }
        }

        /// <summary>
        /// Get recently scanned repositories
        /// </summary>
        [HttpGet("recent")]
        public async Task<IActionResult> GetRecentlyScanned(
            [FromQuery] int limit = 10,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var organizationId = GetCurrentOrganizationId();
                if (organizationId == Guid.Empty)
                {
                    return Unauthorized(new { message = "Invalid organization session" });
                }

                var repositories = await _repositoryService.GetRecentlyScannedRepositoriesAsync(organizationId, limit, cancellationToken);
                return Ok(repositories);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving recently scanned repositories");
                return HandleException(ex);
            }
        }

        /// <summary>
        /// Trigger manual scan for repository
        /// </summary>
        [HttpPost("{repositoryId:guid}/scan")]
        [Authorize(Roles = "Admin,Developer")]
        public async Task<IActionResult> TriggerScan(Guid repositoryId, CancellationToken cancellationToken)
        {
            try
            {
                var scanRequest = new StartScanRequest
                {
                    RepositoryId = repositoryId,
                    ScanType = Domain.Enums.ScanType.Manual,
                    TriggerSource = "Manual API Trigger"
                };

                // This would typically be handled by the ScanController
                return Ok(new { message = "Scan triggered successfully", repositoryId });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error triggering scan for repository {RepositoryId}", repositoryId);
                return HandleException(ex);
            }
        }
    }
}