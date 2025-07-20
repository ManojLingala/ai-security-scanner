using Microsoft.AspNetCore.SignalR;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace AISecurityScanner.API.Hubs
{
    [Authorize]
    public class ScanProgressHub : Hub
    {
        private readonly ILogger<ScanProgressHub> _logger;

        public ScanProgressHub(ILogger<ScanProgressHub> logger)
        {
            _logger = logger;
        }

        public override async Task OnConnectedAsync()
        {
            var organizationId = GetOrganizationId();
            var userId = GetUserId();

            if (organizationId != null && userId != null)
            {
                // Join organization group for receiving organization-wide updates
                await Groups.AddToGroupAsync(Context.ConnectionId, $"org_{organizationId}");
                
                // Join user-specific group for personal notifications
                await Groups.AddToGroupAsync(Context.ConnectionId, $"user_{userId}");

                _logger.LogInformation("User {UserId} from organization {OrganizationId} connected to ScanProgressHub", 
                    userId, organizationId);
            }

            await base.OnConnectedAsync();
        }

        public override async Task OnDisconnectedAsync(Exception? exception)
        {
            var organizationId = GetOrganizationId();
            var userId = GetUserId();

            if (organizationId != null && userId != null)
            {
                await Groups.RemoveFromGroupAsync(Context.ConnectionId, $"org_{organizationId}");
                await Groups.RemoveFromGroupAsync(Context.ConnectionId, $"user_{userId}");

                _logger.LogInformation("User {UserId} from organization {OrganizationId} disconnected from ScanProgressHub", 
                    userId, organizationId);
            }

            await base.OnDisconnectedAsync(exception);
        }

        /// <summary>
        /// Join a specific scan group to receive updates for that scan
        /// </summary>
        public async Task JoinScanGroup(string scanId)
        {
            await Groups.AddToGroupAsync(Context.ConnectionId, $"scan_{scanId}");
            _logger.LogDebug("Connection {ConnectionId} joined scan group {ScanId}", Context.ConnectionId, scanId);
        }

        /// <summary>
        /// Leave a specific scan group
        /// </summary>
        public async Task LeaveScanGroup(string scanId)
        {
            await Groups.RemoveFromGroupAsync(Context.ConnectionId, $"scan_{scanId}");
            _logger.LogDebug("Connection {ConnectionId} left scan group {ScanId}", Context.ConnectionId, scanId);
        }

        /// <summary>
        /// Join repository group to receive repository-specific updates
        /// </summary>
        public async Task JoinRepositoryGroup(string repositoryId)
        {
            await Groups.AddToGroupAsync(Context.ConnectionId, $"repo_{repositoryId}");
            _logger.LogDebug("Connection {ConnectionId} joined repository group {RepositoryId}", Context.ConnectionId, repositoryId);
        }

        /// <summary>
        /// Leave repository group
        /// </summary>
        public async Task LeaveRepositoryGroup(string repositoryId)
        {
            await Groups.RemoveFromGroupAsync(Context.ConnectionId, $"repo_{repositoryId}");
            _logger.LogDebug("Connection {ConnectionId} left repository group {RepositoryId}", Context.ConnectionId, repositoryId);
        }

        /// <summary>
        /// Send a heartbeat to keep connection alive
        /// </summary>
        public async Task Heartbeat()
        {
            await Clients.Caller.SendAsync("HeartbeatResponse", DateTime.UtcNow);
        }

        private string? GetUserId()
        {
            return Context.User?.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        }

        private string? GetOrganizationId()
        {
            return Context.User?.FindFirst("OrganizationId")?.Value;
        }

        private string? GetUserRole()
        {
            return Context.User?.FindFirst(ClaimTypes.Role)?.Value;
        }
    }

    /// <summary>
    /// Extension methods for sending typed messages through SignalR
    /// </summary>
    public static class ScanProgressHubExtensions
    {
        public static async Task NotifyScanStarted(this IHubContext<ScanProgressHub> hubContext, 
            string organizationId, Guid scanId, Guid repositoryId, string repositoryName)
        {
            await hubContext.Clients.Group($"org_{organizationId}")
                .SendAsync("ScanStarted", new
                {
                    ScanId = scanId,
                    RepositoryId = repositoryId,
                    RepositoryName = repositoryName,
                    StartedAt = DateTime.UtcNow
                });
        }

        public static async Task NotifyScanProgress(this IHubContext<ScanProgressHub> hubContext,
            Guid scanId, int progressPercentage, string currentFile, int filesProcessed, int totalFiles)
        {
            await hubContext.Clients.Group($"scan_{scanId}")
                .SendAsync("ScanProgress", new
                {
                    ScanId = scanId,
                    ProgressPercentage = progressPercentage,
                    CurrentFile = currentFile,
                    FilesProcessed = filesProcessed,
                    TotalFiles = totalFiles,
                    UpdatedAt = DateTime.UtcNow
                });
        }

        public static async Task NotifyVulnerabilityFound(this IHubContext<ScanProgressHub> hubContext,
            Guid scanId, string organizationId, object vulnerability)
        {
            await hubContext.Clients.Group($"scan_{scanId}")
                .SendAsync("VulnerabilityFound", new
                {
                    ScanId = scanId,
                    Vulnerability = vulnerability,
                    FoundAt = DateTime.UtcNow
                });

            // Also notify organization group for alerts
            await hubContext.Clients.Group($"org_{organizationId}")
                .SendAsync("VulnerabilityAlert", new
                {
                    ScanId = scanId,
                    Vulnerability = vulnerability,
                    FoundAt = DateTime.UtcNow
                });
        }

        public static async Task NotifyScanCompleted(this IHubContext<ScanProgressHub> hubContext,
            Guid scanId, string organizationId, object scanResult)
        {
            await hubContext.Clients.Group($"scan_{scanId}")
                .SendAsync("ScanCompleted", new
                {
                    ScanId = scanId,
                    Result = scanResult,
                    CompletedAt = DateTime.UtcNow
                });

            await hubContext.Clients.Group($"org_{organizationId}")
                .SendAsync("ScanCompleted", new
                {
                    ScanId = scanId,
                    Result = scanResult,
                    CompletedAt = DateTime.UtcNow
                });
        }

        public static async Task NotifyScanFailed(this IHubContext<ScanProgressHub> hubContext,
            Guid scanId, string organizationId, string errorMessage)
        {
            await hubContext.Clients.Group($"scan_{scanId}")
                .SendAsync("ScanFailed", new
                {
                    ScanId = scanId,
                    ErrorMessage = errorMessage,
                    FailedAt = DateTime.UtcNow
                });

            await hubContext.Clients.Group($"org_{organizationId}")
                .SendAsync("ScanFailed", new
                {
                    ScanId = scanId,
                    ErrorMessage = errorMessage,
                    FailedAt = DateTime.UtcNow
                });
        }

        public static async Task NotifySystemAlert(this IHubContext<ScanProgressHub> hubContext,
            string organizationId, string alertType, string message, object? data = null)
        {
            await hubContext.Clients.Group($"org_{organizationId}")
                .SendAsync("SystemAlert", new
                {
                    AlertType = alertType,
                    Message = message,
                    Data = data,
                    Timestamp = DateTime.UtcNow
                });
        }
    }
}