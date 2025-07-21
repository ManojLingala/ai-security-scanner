using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using AISecurityScanner.Application.DTOs;
using AISecurityScanner.Application.Interfaces;
using AISecurityScanner.Application.Models;
using AISecurityScanner.Domain.Enums;
using AISecurityScanner.API.Controllers;

namespace AISecurityScanner.API.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize]
    public class ComplianceController : BaseController
    {
        private readonly IComplianceService _complianceService;
        private readonly ILogger<ComplianceController> _logger;

        public ComplianceController(
            IComplianceService complianceService,
            ILogger<ComplianceController> logger)
        {
            _complianceService = complianceService;
            _logger = logger;
        }

        /// <summary>
        /// Get all available compliance frameworks
        /// </summary>
        [HttpGet("frameworks")]
        public async Task<ActionResult<List<ComplianceFrameworkDto>>> GetAvailableFrameworks(CancellationToken cancellationToken)
        {
            try
            {
                var frameworks = await _complianceService.GetAvailableFrameworksAsync(cancellationToken);
                return Ok(frameworks);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving available compliance frameworks");
                return StatusCode(500, "An error occurred while retrieving compliance frameworks");
            }
        }

        /// <summary>
        /// Get specific compliance framework details
        /// </summary>
        [HttpGet("frameworks/{framework}")]
        public async Task<ActionResult<ComplianceFrameworkDto>> GetFramework(ComplianceFrameworkType framework, CancellationToken cancellationToken)
        {
            try
            {
                var frameworkDto = await _complianceService.GetFrameworkAsync(framework, cancellationToken);
                if (frameworkDto == null)
                {
                    return NotFound($"Compliance framework {framework} not found");
                }

                return Ok(frameworkDto);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving compliance framework {Framework}", framework);
                return StatusCode(500, "An error occurred while retrieving the compliance framework");
            }
        }

        /// <summary>
        /// Enable a compliance framework for an organization
        /// </summary>
        [HttpPost("organizations/{organizationId}/frameworks/{framework}/enable")]
        public async Task<ActionResult> EnableFramework(Guid organizationId, ComplianceFrameworkType framework, CancellationToken cancellationToken)
        {
            try
            {
                var result = await _complianceService.EnableFrameworkAsync(organizationId, framework, cancellationToken);
                if (result)
                {
                    return Ok(new { message = $"Framework {framework} enabled successfully" });
                }

                return BadRequest("Failed to enable framework");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error enabling framework {Framework} for organization {OrganizationId}", framework, organizationId);
                return StatusCode(500, "An error occurred while enabling the framework");
            }
        }

        /// <summary>
        /// Disable a compliance framework for an organization
        /// </summary>
        [HttpPost("organizations/{organizationId}/frameworks/{framework}/disable")]
        public async Task<ActionResult> DisableFramework(Guid organizationId, ComplianceFrameworkType framework, CancellationToken cancellationToken)
        {
            try
            {
                var result = await _complianceService.DisableFrameworkAsync(organizationId, framework, cancellationToken);
                if (result)
                {
                    return Ok(new { message = $"Framework {framework} disabled successfully" });
                }

                return BadRequest("Failed to disable framework");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error disabling framework {Framework} for organization {OrganizationId}", framework, organizationId);
                return StatusCode(500, "An error occurred while disabling the framework");
            }
        }

        /// <summary>
        /// Start a compliance scan
        /// </summary>
        [HttpPost("scan")]
        public async Task<ActionResult<ComplianceScanResultDto>> StartComplianceScan(ComplianceScanRequest request, CancellationToken cancellationToken)
        {
            try
            {
                var result = await _complianceService.ScanForComplianceAsync(request, cancellationToken);
                return Ok(result);
            }
            catch (ArgumentException ex)
            {
                return BadRequest(ex.Message);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error starting compliance scan for organization {OrganizationId}", request.OrganizationId);
                return StatusCode(500, "An error occurred while starting the compliance scan");
            }
        }

        /// <summary>
        /// Scan a specific repository for compliance
        /// </summary>
        [HttpPost("repositories/{repositoryId}/scan")]
        public async Task<ActionResult<ComplianceScanResultDto>> ScanRepository(
            Guid repositoryId, 
            [FromBody] List<ComplianceFrameworkType> frameworks, 
            CancellationToken cancellationToken)
        {
            try
            {
                var result = await _complianceService.ScanRepositoryAsync(repositoryId, frameworks, cancellationToken);
                return Ok(result);
            }
            catch (ArgumentException ex)
            {
                return BadRequest(ex.Message);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error scanning repository {RepositoryId} for compliance", repositoryId);
                return StatusCode(500, "An error occurred while scanning the repository");
            }
        }

        /// <summary>
        /// Get compliance scan history for an organization
        /// </summary>
        [HttpGet("organizations/{organizationId}/scan-history")]
        public async Task<ActionResult<List<ComplianceScanResultDto>>> GetScanHistory(
            Guid organizationId, 
            [FromQuery] ComplianceFrameworkType? framework = null, 
            CancellationToken cancellationToken = default)
        {
            try
            {
                var history = await _complianceService.GetComplianceScanHistoryAsync(organizationId, framework, cancellationToken);
                return Ok(history);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving scan history for organization {OrganizationId}", organizationId);
                return StatusCode(500, "An error occurred while retrieving scan history");
            }
        }

        /// <summary>
        /// Generate a compliance report
        /// </summary>
        [HttpPost("reports")]
        public async Task<ActionResult<ComplianceReportDto>> GenerateReport(ComplianceReportRequest request, CancellationToken cancellationToken)
        {
            try
            {
                var report = await _complianceService.GenerateComplianceReportAsync(request, cancellationToken);
                return Ok(report);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating compliance report for organization {OrganizationId}", request.OrganizationId);
                return StatusCode(500, "An error occurred while generating the compliance report");
            }
        }

        /// <summary>
        /// Get compliance dashboard for an organization
        /// </summary>
        [HttpGet("organizations/{organizationId}/dashboard")]
        public async Task<ActionResult<ComplianceDashboardDto>> GetDashboard(Guid organizationId, CancellationToken cancellationToken)
        {
            try
            {
                var dashboard = await _complianceService.GetComplianceDashboardAsync(organizationId, cancellationToken);
                return Ok(dashboard);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving compliance dashboard for organization {OrganizationId}", organizationId);
                return StatusCode(500, "An error occurred while retrieving the compliance dashboard");
            }
        }

        /// <summary>
        /// Get compliance trends analysis
        /// </summary>
        [HttpGet("organizations/{organizationId}/trends")]
        public async Task<ActionResult<ComplianceTrendAnalysisDto>> GetTrends(
            Guid organizationId, 
            [FromQuery] DateTime? fromDate = null, 
            [FromQuery] DateTime? toDate = null, 
            CancellationToken cancellationToken = default)
        {
            try
            {
                var from = fromDate ?? DateTime.UtcNow.AddDays(-30);
                var to = toDate ?? DateTime.UtcNow;
                
                var trends = await _complianceService.GetComplianceTrendsAsync(organizationId, from, to, cancellationToken);
                return Ok(trends);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving compliance trends for organization {OrganizationId}", organizationId);
                return StatusCode(500, "An error occurred while retrieving compliance trends");
            }
        }

        /// <summary>
        /// Get compliance violations with filtering and pagination
        /// </summary>
        [HttpGet("organizations/{organizationId}/violations")]
        public async Task<ActionResult<PagedResult<ComplianceViolationDto>>> GetViolations(
            Guid organizationId,
            [FromQuery] ComplianceFrameworkType? framework = null,
            [FromQuery] ComplianceSeverity? severity = null,
            [FromQuery] ComplianceStatus? status = null,
            [FromQuery] string? requirementId = null,
            [FromQuery] string? category = null,
            [FromQuery] Guid? repositoryId = null,
            [FromQuery] DateTime? fromDate = null,
            [FromQuery] DateTime? toDate = null,
            [FromQuery] string? searchTerm = null,
            [FromQuery] int pageNumber = 1,
            [FromQuery] int pageSize = 50,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var filter = new ComplianceViolationFilter
                {
                    Framework = framework,
                    Severity = severity,
                    Status = status,
                    RequirementId = requirementId,
                    Category = category,
                    RepositoryId = repositoryId,
                    FromDate = fromDate,
                    ToDate = toDate,
                    SearchTerm = searchTerm
                };

                var pagination = new PaginationRequest
                {
                    PageNumber = pageNumber,
                    PageSize = Math.Min(pageSize, 100) // Limit maximum page size
                };

                var violations = await _complianceService.GetViolationsAsync(organizationId, filter, pagination, cancellationToken);
                return Ok(violations);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving violations for organization {OrganizationId}", organizationId);
                return StatusCode(500, "An error occurred while retrieving violations");
            }
        }

        /// <summary>
        /// Update the status of a compliance violation
        /// </summary>
        [HttpPut("violations/{violationId}/status")]
        public async Task<ActionResult> UpdateViolationStatus(
            Guid violationId, 
            [FromBody] UpdateViolationStatusRequest request, 
            CancellationToken cancellationToken)
        {
            try
            {
                var result = await _complianceService.UpdateViolationStatusAsync(violationId, request.Status, request.Notes, cancellationToken);
                if (result)
                {
                    return Ok(new { message = "Violation status updated successfully" });
                }

                return BadRequest("Failed to update violation status");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating violation {ViolationId} status", violationId);
                return StatusCode(500, "An error occurred while updating the violation status");
            }
        }

        /// <summary>
        /// Bulk update violation statuses
        /// </summary>
        [HttpPut("violations/bulk-status")]
        public async Task<ActionResult> BulkUpdateViolationStatus(
            [FromBody] BulkUpdateViolationStatusRequest request, 
            CancellationToken cancellationToken)
        {
            try
            {
                var result = await _complianceService.BulkUpdateViolationsAsync(request.ViolationIds, request.Status, request.Notes, cancellationToken);
                if (result)
                {
                    return Ok(new { message = $"Updated {request.ViolationIds.Count} violations successfully" });
                }

                return BadRequest("Failed to update violations");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error bulk updating violations");
                return StatusCode(500, "An error occurred while updating violations");
            }
        }

        /// <summary>
        /// Get remediation guidance for a specific violation
        /// </summary>
        [HttpGet("violations/{violationId}/remediation")]
        public async Task<ActionResult<ComplianceRemediationGuidanceDto>> GetRemediationGuidance(Guid violationId, CancellationToken cancellationToken)
        {
            try
            {
                var guidance = await _complianceService.GetRemediationGuidanceAsync(violationId, cancellationToken);
                return Ok(guidance);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving remediation guidance for violation {ViolationId}", violationId);
                return StatusCode(500, "An error occurred while retrieving remediation guidance");
            }
        }

        /// <summary>
        /// Get remediation templates for a compliance framework
        /// </summary>
        [HttpGet("frameworks/{framework}/remediation-templates")]
        public async Task<ActionResult<List<ComplianceRemediationTemplateDto>>> GetRemediationTemplates(
            ComplianceFrameworkType framework, 
            CancellationToken cancellationToken)
        {
            try
            {
                var templates = await _complianceService.GetRemediationTemplatesAsync(framework, cancellationToken);
                return Ok(templates);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving remediation templates for framework {Framework}", framework);
                return StatusCode(500, "An error occurred while retrieving remediation templates");
            }
        }

        /// <summary>
        /// Collect compliance evidence for a framework
        /// </summary>
        [HttpPost("organizations/{organizationId}/frameworks/{framework}/evidence/collect")]
        public async Task<ActionResult<List<ComplianceEvidenceDto>>> CollectEvidence(
            Guid organizationId, 
            ComplianceFrameworkType framework, 
            CancellationToken cancellationToken)
        {
            try
            {
                var evidence = await _complianceService.CollectComplianceEvidenceAsync(organizationId, framework, cancellationToken);
                return Ok(evidence);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error collecting evidence for organization {OrganizationId} and framework {Framework}", organizationId, framework);
                return StatusCode(500, "An error occurred while collecting compliance evidence");
            }
        }

        /// <summary>
        /// Add manual compliance evidence
        /// </summary>
        [HttpPost("evidence")]
        public async Task<ActionResult> AddManualEvidence([FromBody] ComplianceEvidenceRequest request, CancellationToken cancellationToken)
        {
            try
            {
                var result = await _complianceService.AddManualEvidenceAsync(request, cancellationToken);
                if (result)
                {
                    return Ok(new { message = "Evidence added successfully" });
                }

                return BadRequest("Failed to add evidence");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error adding manual evidence");
                return StatusCode(500, "An error occurred while adding manual evidence");
            }
        }
    }

    // Request/Response models
    public class UpdateViolationStatusRequest
    {
        public ComplianceStatus Status { get; set; }
        public string? Notes { get; set; }
    }

    public class BulkUpdateViolationStatusRequest
    {
        public List<Guid> ViolationIds { get; set; } = new();
        public ComplianceStatus Status { get; set; }
        public string? Notes { get; set; }
    }
}