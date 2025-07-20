using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.SignalR;
using AISecurityScanner.Application.Interfaces;
using AISecurityScanner.Application.Models;
using AISecurityScanner.API.Hubs;

namespace AISecurityScanner.API.Controllers
{
    [Authorize]
    public class ScanController : BaseController
    {
        private readonly ISecurityScannerService _scannerService;
        private readonly IHubContext<ScanProgressHub> _hubContext;
        private readonly ILogger<ScanController> _logger;

        public ScanController(
            ISecurityScannerService scannerService,
            IHubContext<ScanProgressHub> hubContext,
            ILogger<ScanController> logger)
        {
            _scannerService = scannerService;
            _hubContext = hubContext;
            _logger = logger;
        }

        /// <summary>
        /// Start a new security scan
        /// </summary>
        [HttpPost("start")]
        public async Task<IActionResult> StartScan([FromBody] StartScanRequest request, CancellationToken cancellationToken)
        {
            try
            {
                var userId = GetCurrentUserId();
                if (userId == Guid.Empty)
                {
                    return Unauthorized(new { message = "Invalid user session" });
                }

                var result = await _scannerService.StartScanAsync(request, userId, cancellationToken);
                
                if (result.IsSuccess)
                {
                    // Notify clients about scan start
                    await _hubContext.Clients.Group($"org_{GetCurrentOrganizationId()}")
                        .SendAsync("ScanStarted", new { 
                            ScanId = result.ScanId, 
                            RepositoryId = request.RepositoryId,
                            UserId = userId
                        }, cancellationToken);

                    return Ok(result);
                }

                return BadRequest(new { message = result.ErrorMessage });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error starting scan");
                return HandleException(ex);
            }
        }

        /// <summary>
        /// Get scan details by ID
        /// </summary>
        [HttpGet("{scanId:guid}")]
        public async Task<IActionResult> GetScan(Guid scanId, CancellationToken cancellationToken)
        {
            try
            {
                var scan = await _scannerService.GetScanAsync(scanId, cancellationToken);
                return HandleResult(scan);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving scan {ScanId}", scanId);
                return HandleException(ex);
            }
        }

        /// <summary>
        /// Get scan results with vulnerabilities
        /// </summary>
        [HttpGet("{scanId:guid}/results")]
        public async Task<IActionResult> GetScanResults(Guid scanId, CancellationToken cancellationToken)
        {
            try
            {
                var result = await _scannerService.GetScanResultAsync(scanId, cancellationToken);
                
                if (result.IsSuccess)
                {
                    return Ok(result);
                }

                return BadRequest(new { message = result.ErrorMessage });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving scan results for {ScanId}", scanId);
                return HandleException(ex);
            }
        }

        /// <summary>
        /// Get scan vulnerabilities
        /// </summary>
        [HttpGet("{scanId:guid}/vulnerabilities")]
        public async Task<IActionResult> GetScanVulnerabilities(Guid scanId, CancellationToken cancellationToken)
        {
            try
            {
                var vulnerabilities = await _scannerService.GetScanVulnerabilitiesAsync(scanId, cancellationToken);
                return Ok(vulnerabilities);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving vulnerabilities for scan {ScanId}", scanId);
                return HandleException(ex);
            }
        }

        /// <summary>
        /// Get scan metrics
        /// </summary>
        [HttpGet("{scanId:guid}/metrics")]
        public async Task<IActionResult> GetScanMetrics(Guid scanId, CancellationToken cancellationToken)
        {
            try
            {
                var metrics = await _scannerService.GetScanMetricsAsync(scanId, cancellationToken);
                return Ok(metrics);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving metrics for scan {ScanId}", scanId);
                return HandleException(ex);
            }
        }

        /// <summary>
        /// Cancel a running scan
        /// </summary>
        [HttpPost("{scanId:guid}/cancel")]
        public async Task<IActionResult> CancelScan(Guid scanId, CancellationToken cancellationToken)
        {
            try
            {
                var userId = GetCurrentUserId();
                var success = await _scannerService.CancelScanAsync(scanId, userId, cancellationToken);
                
                if (success)
                {
                    // Notify clients about scan cancellation
                    await _hubContext.Clients.Group($"org_{GetCurrentOrganizationId()}")
                        .SendAsync("ScanCancelled", new { ScanId = scanId }, cancellationToken);

                    return Ok(new { message = "Scan cancelled successfully" });
                }

                return BadRequest(new { message = "Failed to cancel scan" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error cancelling scan {ScanId}", scanId);
                return HandleException(ex);
            }
        }

        /// <summary>
        /// Retry a failed scan
        /// </summary>
        [HttpPost("{scanId:guid}/retry")]
        public async Task<IActionResult> RetryScan(Guid scanId, CancellationToken cancellationToken)
        {
            try
            {
                var userId = GetCurrentUserId();
                var success = await _scannerService.RetryFailedScanAsync(scanId, userId, cancellationToken);
                
                if (success)
                {
                    return Ok(new { message = "Scan queued for retry" });
                }

                return BadRequest(new { message = "Failed to retry scan" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrying scan {ScanId}", scanId);
                return HandleException(ex);
            }
        }

        /// <summary>
        /// Get organization scans with pagination
        /// </summary>
        [HttpGet("organization")]
        public async Task<IActionResult> GetOrganizationScans(
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

                var result = await _scannerService.GetScansAsync(organizationId, pagination, cancellationToken);
                return Ok(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving organization scans");
                return HandleException(ex);
            }
        }

        /// <summary>
        /// Get repository scans with pagination
        /// </summary>
        [HttpGet("repository/{repositoryId:guid}")]
        public async Task<IActionResult> GetRepositoryScans(
            Guid repositoryId,
            [FromQuery] int pageNumber = 1,
            [FromQuery] int pageSize = 20,
            [FromQuery] string? sortBy = null,
            [FromQuery] bool sortDescending = true,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var pagination = new PaginationRequest
                {
                    PageNumber = pageNumber,
                    PageSize = pageSize,
                    SortBy = sortBy,
                    SortDescending = sortDescending
                };

                var result = await _scannerService.GetRepositoryScansAsync(repositoryId, pagination, cancellationToken);
                return Ok(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving repository scans for {RepositoryId}", repositoryId);
                return HandleException(ex);
            }
        }
    }
}