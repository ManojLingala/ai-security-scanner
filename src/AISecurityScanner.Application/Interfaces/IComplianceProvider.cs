using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AISecurityScanner.Domain.Entities;
using AISecurityScanner.Domain.Enums;

namespace AISecurityScanner.Application.Interfaces
{
    public interface IComplianceProvider
    {
        ComplianceFrameworkType Framework { get; }
        string Version { get; }
        string Name { get; }
        Task<ComplianceScanResult> ScanAsync(ComplianceScanContext context, CancellationToken cancellationToken = default);
    }

    public interface IComplianceProviderFactory
    {
        IComplianceProvider GetProvider(ComplianceFrameworkType framework);
        IEnumerable<IComplianceProvider> GetAllProviders();
        bool IsFrameworkSupported(ComplianceFrameworkType framework);
    }

    public class ComplianceScanContext
    {
        public Guid ScanId { get; set; }
        public Guid OrganizationId { get; set; }
        public List<ComplianceFile> Files { get; set; } = new();
        public Dictionary<string, object> Options { get; set; } = new();
    }

    public class ComplianceFile
    {
        public string Path { get; set; } = string.Empty;
        public string Extension { get; set; } = string.Empty;
        public long Size { get; set; }
        public DateTime LastModified { get; set; }
        
        public async Task<string> ReadContentAsync()
        {
            // Implementation will be provided by Infrastructure layer
            return await Task.FromResult(string.Empty);
        }
    }
}