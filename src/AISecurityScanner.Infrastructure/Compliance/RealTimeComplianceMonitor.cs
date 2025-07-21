using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AISecurityScanner.Application.Interfaces;
using AISecurityScanner.Domain.Entities;
using AISecurityScanner.Domain.Enums;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace AISecurityScanner.Infrastructure.Compliance
{
    public interface IRealTimeComplianceMonitor
    {
        Task StartMonitoringAsync(Guid organizationId, string repositoryPath, List<ComplianceFrameworkType> frameworks);
        Task StopMonitoringAsync(Guid organizationId);
        bool IsMonitoring(Guid organizationId);
        event EventHandler<ComplianceViolationDetectedEventArgs> ViolationDetected;
        event EventHandler<ComplianceStatusChangedEventArgs> StatusChanged;
    }

    public class RealTimeComplianceMonitor : BackgroundService, IRealTimeComplianceMonitor
    {
        private readonly ILogger<RealTimeComplianceMonitor> _logger;
        private readonly IComplianceProviderFactory _providerFactory;
        private readonly Dictionary<Guid, MonitoringSession> _activeSessions;
        private readonly FileSystemWatcher _fileWatcher;

        public event EventHandler<ComplianceViolationDetectedEventArgs>? ViolationDetected;
        public event EventHandler<ComplianceStatusChangedEventArgs>? StatusChanged;

        public RealTimeComplianceMonitor(
            ILogger<RealTimeComplianceMonitor> logger,
            IComplianceProviderFactory providerFactory)
        {
            _logger = logger;
            _providerFactory = providerFactory;
            _activeSessions = new Dictionary<Guid, MonitoringSession>();
            _fileWatcher = new FileSystemWatcher();
        }

        public async Task StartMonitoringAsync(Guid organizationId, string repositoryPath, List<ComplianceFrameworkType> frameworks)
        {
            if (_activeSessions.ContainsKey(organizationId))
            {
                _logger.LogWarning("Monitoring already active for organization {OrganizationId}", organizationId);
                return;
            }

            var session = new MonitoringSession
            {
                OrganizationId = organizationId,
                RepositoryPath = repositoryPath,
                Frameworks = frameworks,
                StartTime = DateTime.UtcNow,
                IsActive = true
            };

            _activeSessions[organizationId] = session;

            // Configure file system watcher
            ConfigureFileWatcher(repositoryPath, organizationId);

            _logger.LogInformation("Started real-time compliance monitoring for organization {OrganizationId}", organizationId);
            
            OnStatusChanged(new ComplianceStatusChangedEventArgs
            {
                OrganizationId = organizationId,
                Status = "Monitoring Started",
                Timestamp = DateTime.UtcNow
            });

            await Task.CompletedTask;
        }

        public async Task StopMonitoringAsync(Guid organizationId)
        {
            if (!_activeSessions.ContainsKey(organizationId))
            {
                _logger.LogWarning("No active monitoring session for organization {OrganizationId}", organizationId);
                return;
            }

            _activeSessions[organizationId].IsActive = false;
            _activeSessions.Remove(organizationId);

            _logger.LogInformation("Stopped real-time compliance monitoring for organization {OrganizationId}", organizationId);
            
            OnStatusChanged(new ComplianceStatusChangedEventArgs
            {
                OrganizationId = organizationId,
                Status = "Monitoring Stopped",
                Timestamp = DateTime.UtcNow
            });

            await Task.CompletedTask;
        }

        public bool IsMonitoring(Guid organizationId)
        {
            return _activeSessions.ContainsKey(organizationId) && _activeSessions[organizationId].IsActive;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    // Periodic compliance checks for all active sessions
                    foreach (var session in _activeSessions.Values.Where(s => s.IsActive))
                    {
                        await PerformPeriodicComplianceCheckAsync(session, stoppingToken);
                    }

                    // Wait before next check cycle
                    await Task.Delay(TimeSpan.FromMinutes(5), stoppingToken);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error in real-time compliance monitoring");
                }
            }
        }

        private void ConfigureFileWatcher(string path, Guid organizationId)
        {
            if (!Directory.Exists(path))
            {
                _logger.LogWarning("Repository path does not exist: {Path}", path);
                return;
            }

            _fileWatcher.Path = path;
            _fileWatcher.NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.DirectoryName;
            _fileWatcher.Filter = "*.*";
            _fileWatcher.IncludeSubdirectories = true;

            _fileWatcher.Changed += async (sender, e) => await OnFileChangedAsync(e, organizationId);
            _fileWatcher.Created += async (sender, e) => await OnFileChangedAsync(e, organizationId);
            _fileWatcher.Renamed += async (sender, e) => await OnFileChangedAsync(e, organizationId);

            _fileWatcher.EnableRaisingEvents = true;
        }

        private async Task OnFileChangedAsync(FileSystemEventArgs e, Guid organizationId)
        {
            try
            {
                if (!_activeSessions.TryGetValue(organizationId, out var session))
                    return;

                // Skip non-code files
                var codeExtensions = new[] { ".cs", ".java", ".py", ".js", ".php", ".sql", ".config", ".json", ".xml" };
                var extension = Path.GetExtension(e.FullPath);
                if (!codeExtensions.Contains(extension, StringComparer.OrdinalIgnoreCase))
                    return;

                _logger.LogDebug("File changed: {FilePath}", e.FullPath);

                // Perform quick compliance check on the changed file
                await QuickComplianceCheckAsync(session, e.FullPath);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing file change event");
            }
        }

        private async Task QuickComplianceCheckAsync(MonitoringSession session, string filePath)
        {
            var file = new ComplianceFile
            {
                Path = filePath,
                Extension = Path.GetExtension(filePath),
                Size = new FileInfo(filePath).Length,
                LastModified = File.GetLastWriteTime(filePath)
            };

            var context = new ComplianceScanContext
            {
                ScanId = Guid.NewGuid(),
                OrganizationId = session.OrganizationId,
                Files = new List<ComplianceFile> { file }
            };

            foreach (var framework in session.Frameworks)
            {
                var provider = _providerFactory.GetProvider(framework);
                var result = await provider.ScanAsync(context);

                foreach (var violation in result.Violations)
                {
                    OnViolationDetected(new ComplianceViolationDetectedEventArgs
                    {
                        OrganizationId = session.OrganizationId,
                        Violation = violation,
                        Framework = framework,
                        FilePath = filePath,
                        DetectedAt = DateTime.UtcNow,
                        IsRealTime = true
                    });
                }
            }
        }

        private async Task PerformPeriodicComplianceCheckAsync(MonitoringSession session, CancellationToken cancellationToken)
        {
            try
            {
                _logger.LogDebug("Performing periodic compliance check for organization {OrganizationId}", session.OrganizationId);

                var recentlyModifiedFiles = GetRecentlyModifiedFiles(session.RepositoryPath, TimeSpan.FromMinutes(10));
                if (!recentlyModifiedFiles.Any())
                    return;

                var context = new ComplianceScanContext
                {
                    ScanId = Guid.NewGuid(),
                    OrganizationId = session.OrganizationId,
                    Files = recentlyModifiedFiles
                };

                var totalViolations = 0;
                foreach (var framework in session.Frameworks)
                {
                    var provider = _providerFactory.GetProvider(framework);
                    var result = await provider.ScanAsync(context, cancellationToken);
                    totalViolations += result.Violations.Count;
                }

                if (totalViolations > 0)
                {
                    OnStatusChanged(new ComplianceStatusChangedEventArgs
                    {
                        OrganizationId = session.OrganizationId,
                        Status = $"Detected {totalViolations} compliance violations in recent changes",
                        Timestamp = DateTime.UtcNow
                    });
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in periodic compliance check");
            }
        }

        private List<ComplianceFile> GetRecentlyModifiedFiles(string path, TimeSpan timeSpan)
        {
            var files = new List<ComplianceFile>();
            var cutoffTime = DateTime.UtcNow.Subtract(timeSpan);

            try
            {
                var directory = new DirectoryInfo(path);
                var codeExtensions = new[] { ".cs", ".java", ".py", ".js", ".php", ".sql", ".config", ".json", ".xml" };

                var recentFiles = directory.GetFiles("*.*", SearchOption.AllDirectories)
                    .Where(f => codeExtensions.Contains(f.Extension, StringComparer.OrdinalIgnoreCase))
                    .Where(f => f.LastWriteTimeUtc > cutoffTime)
                    .Select(f => new ComplianceFile
                    {
                        Path = f.FullName,
                        Extension = f.Extension,
                        Size = f.Length,
                        LastModified = f.LastWriteTimeUtc
                    })
                    .ToList();

                files.AddRange(recentFiles);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting recently modified files");
            }

            return files;
        }

        protected virtual void OnViolationDetected(ComplianceViolationDetectedEventArgs e)
        {
            ViolationDetected?.Invoke(this, e);
        }

        protected virtual void OnStatusChanged(ComplianceStatusChangedEventArgs e)
        {
            StatusChanged?.Invoke(this, e);
        }

        private class MonitoringSession
        {
            public Guid OrganizationId { get; set; }
            public string RepositoryPath { get; set; } = string.Empty;
            public List<ComplianceFrameworkType> Frameworks { get; set; } = new();
            public DateTime StartTime { get; set; }
            public bool IsActive { get; set; }
        }
    }

    public class ComplianceViolationDetectedEventArgs : EventArgs
    {
        public Guid OrganizationId { get; set; }
        public ComplianceViolation Violation { get; set; } = null!;
        public ComplianceFrameworkType Framework { get; set; }
        public string FilePath { get; set; } = string.Empty;
        public DateTime DetectedAt { get; set; }
        public bool IsRealTime { get; set; }
    }

    public class ComplianceStatusChangedEventArgs : EventArgs
    {
        public Guid OrganizationId { get; set; }
        public string Status { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; }
    }
}