using System.Threading;
using System.Threading.Tasks;
using AISecurityScanner.Application.Models;

namespace AISecurityScanner.Application.Interfaces
{
    public interface IHallucinationDetectionService
    {
        Task<HallucinationDetectionResult> CheckForHallucinationAsync(
            string packageName,
            string packageManager,
            string? version = null,
            CancellationToken cancellationToken = default);
    }
}