using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AISecurityScanner.Domain.Entities;

namespace AISecurityScanner.Application.Interfaces
{
    public interface INpmPackageScanner
    {
        Task<List<PackageVulnerability>> ScanPackageJsonAsync(
            string packageJsonPath, 
            Guid scanId, 
            CancellationToken cancellationToken = default);
    }
}