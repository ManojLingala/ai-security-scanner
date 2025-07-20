using System;
using System.Threading;
using System.Threading.Tasks;
using AISecurityScanner.Domain.Entities;

namespace AISecurityScanner.Domain.Interfaces
{
    public interface IOrganizationRepository : IRepository<Organization>
    {
        Task<Organization?> GetByStripeCustomerIdAsync(string stripeCustomerId, CancellationToken cancellationToken = default);
        Task<bool> CanAddUserAsync(Guid organizationId, CancellationToken cancellationToken = default);
        Task<bool> CanAddRepositoryAsync(Guid organizationId, CancellationToken cancellationToken = default);
        Task<bool> CanPerformScanAsync(Guid organizationId, CancellationToken cancellationToken = default);
        Task IncrementMonthlyScansAsync(Guid organizationId, CancellationToken cancellationToken = default);
        Task ResetMonthlyScansIfNeededAsync(Guid organizationId, CancellationToken cancellationToken = default);
    }
}