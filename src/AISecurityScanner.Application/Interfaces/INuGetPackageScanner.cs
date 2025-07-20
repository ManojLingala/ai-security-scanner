using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AISecurityScanner.Domain.Entities;

namespace AISecurityScanner.Application.Interfaces
{
    public interface INuGetPackageScanner
    {
        Task<List<PackageVulnerability>> ScanProjectAsync(
            string projectFilePath, 
            Guid scanId, 
            CancellationToken cancellationToken = default);
    }
}