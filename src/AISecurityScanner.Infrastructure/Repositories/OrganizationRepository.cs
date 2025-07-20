using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AISecurityScanner.Domain.Entities;
using AISecurityScanner.Domain.Interfaces;
using AISecurityScanner.Infrastructure.Data;
using Raven.Client.Documents;

namespace AISecurityScanner.Infrastructure.Repositories
{
    public class OrganizationRepository : RavenRepository<Organization>, IOrganizationRepository
    {
        private readonly IRavenDbContext _context;

        public OrganizationRepository(IRavenDbContext context) : base(context)
        {
            _context = context;
        }

        public async Task<Organization?> GetByStripeCustomerIdAsync(string stripeCustomerId, CancellationToken cancellationToken = default)
        {
            using var session = _context.OpenAsyncSession();
            return await session.Query<Organization>()
                .Where(x => x.StripeCustomerId == stripeCustomerId && !x.IsDeleted)
                .FirstOrDefaultAsync(cancellationToken);
        }

        public async Task<bool> CanAddUserAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            using var session = _context.OpenAsyncSession();
            var org = await session.LoadAsync<Organization>(organizationId.ToString(), cancellationToken);
            if (org == null || org.IsDeleted || !org.IsActive)
                return false;

            var currentUserCount = await session.Query<User>()
                .Where(x => x.OrganizationId == organizationId && !x.IsDeleted && x.IsActive)
                .CountAsync(cancellationToken);

            return currentUserCount < org.TeamSizeLimit;
        }

        public async Task<bool> CanAddRepositoryAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            using var session = _context.OpenAsyncSession();
            var org = await session.LoadAsync<Organization>(organizationId.ToString(), cancellationToken);
            if (org == null || org.IsDeleted || !org.IsActive)
                return false;

            var currentRepoCount = await session.Query<Repository>()
                .Where(x => x.OrganizationId == organizationId && !x.IsDeleted)
                .CountAsync(cancellationToken);

            return currentRepoCount < org.RepositoriesLimit;
        }

        public async Task<bool> CanPerformScanAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            using var session = _context.OpenAsyncSession();
            var org = await session.LoadAsync<Organization>(organizationId.ToString(), cancellationToken);
            if (org == null || org.IsDeleted || !org.IsActive)
                return false;

            await ResetMonthlyScansIfNeededAsync(organizationId, cancellationToken);
            
            return org.CurrentMonthScans < org.MonthlyScansLimit;
        }

        public async Task IncrementMonthlyScansAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            using var session = _context.OpenAsyncSession();
            var org = await session.LoadAsync<Organization>(organizationId.ToString(), cancellationToken);
            if (org != null)
            {
                org.CurrentMonthScans++;
                await session.SaveChangesAsync(cancellationToken);
            }
        }

        public async Task ResetMonthlyScansIfNeededAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            using var session = _context.OpenAsyncSession();
            var org = await session.LoadAsync<Organization>(organizationId.ToString(), cancellationToken);
            
            if (org != null && org.LastScanResetDate.HasValue)
            {
                var now = DateTime.UtcNow;
                if (org.LastScanResetDate.Value.Month != now.Month || 
                    org.LastScanResetDate.Value.Year != now.Year)
                {
                    org.CurrentMonthScans = 0;
                    org.LastScanResetDate = now;
                    await session.SaveChangesAsync(cancellationToken);
                }
            }
            else if (org != null)
            {
                org.LastScanResetDate = DateTime.UtcNow;
                await session.SaveChangesAsync(cancellationToken);
            }
        }
    }
}