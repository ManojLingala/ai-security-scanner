using System;
using System.Threading;
using System.Threading.Tasks;
using AISecurityScanner.Domain.Entities;
using AISecurityScanner.Domain.Interfaces;

namespace AISecurityScanner.CLI.Services
{
    public class MockUnitOfWork : IUnitOfWork
    {
        public IOrganizationRepository Organizations => new MockOrganizationRepository();
        public IRepository<User> Users => new MockRepository<User>();
        public IRepository<Repository> Repositories => new MockRepository<Repository>();
        public IRepository<SecurityScan> SecurityScans => new MockRepository<SecurityScan>();
        public IRepository<Vulnerability> Vulnerabilities => new MockRepository<Vulnerability>();
        public IRepository<AIProvider> AIProviders => new MockRepository<AIProvider>();
        public IRepository<ApiKey> ApiKeys => new MockRepository<ApiKey>();
        public IRepository<ActivityLog> ActivityLogs => new MockRepository<ActivityLog>();

        public IRepository<T> GetRepository<T>() where T : BaseEntity
        {
            return new MockRepository<T>();
        }

        public Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
        {
            return Task.FromResult(0);
        }

        public Task BeginTransactionAsync(CancellationToken cancellationToken = default)
        {
            return Task.CompletedTask;
        }

        public Task CommitTransactionAsync(CancellationToken cancellationToken = default)
        {
            return Task.CompletedTask;
        }

        public Task RollbackTransactionAsync(CancellationToken cancellationToken = default)
        {
            return Task.CompletedTask;
        }

        public void Dispose()
        {
            // Nothing to dispose in mock
        }
    }

    public class MockRepository<T> : IRepository<T> where T : BaseEntity
    {
        public Task<T?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<T?>(null);
        }

        public Task<T?> GetByIdAsync(string id, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<T?>(null);
        }

        public Task<IEnumerable<T>> GetAllAsync(CancellationToken cancellationToken = default)
        {
            return Task.FromResult<IEnumerable<T>>(new List<T>());
        }

        public Task<IEnumerable<T>> FindAsync(System.Linq.Expressions.Expression<Func<T, bool>> predicate, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<IEnumerable<T>>(new List<T>());
        }

        public Task<T?> FirstOrDefaultAsync(System.Linq.Expressions.Expression<Func<T, bool>> predicate, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<T?>(null);
        }

        public Task<T> AddAsync(T entity, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(entity);
        }

        public Task UpdateAsync(T entity, CancellationToken cancellationToken = default)
        {
            return Task.CompletedTask;
        }

        public Task DeleteAsync(T entity, CancellationToken cancellationToken = default)
        {
            return Task.CompletedTask;
        }

        public Task DeleteAsync(Guid id, CancellationToken cancellationToken = default)
        {
            return Task.CompletedTask;
        }

        public Task<int> CountAsync(System.Linq.Expressions.Expression<Func<T, bool>>? predicate = null, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(0);
        }

        public Task<bool> ExistsAsync(System.Linq.Expressions.Expression<Func<T, bool>> predicate, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(false);
        }

        public Task SaveChangesAsync(CancellationToken cancellationToken = default)
        {
            return Task.CompletedTask;
        }
    }

    public class MockOrganizationRepository : IOrganizationRepository
    {
        public Task<Organization?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<Organization?>(null);
        }

        public Task<Organization?> GetByIdAsync(string id, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<Organization?>(null);
        }

        public Task<IEnumerable<Organization>> GetAllAsync(CancellationToken cancellationToken = default)
        {
            return Task.FromResult<IEnumerable<Organization>>(new List<Organization>());
        }

        public Task<IEnumerable<Organization>> FindAsync(System.Linq.Expressions.Expression<Func<Organization, bool>> predicate, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<IEnumerable<Organization>>(new List<Organization>());
        }

        public Task<Organization?> FirstOrDefaultAsync(System.Linq.Expressions.Expression<Func<Organization, bool>> predicate, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<Organization?>(null);
        }

        public Task<Organization> AddAsync(Organization entity, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(entity);
        }

        public Task UpdateAsync(Organization entity, CancellationToken cancellationToken = default)
        {
            return Task.CompletedTask;
        }

        public Task DeleteAsync(Organization entity, CancellationToken cancellationToken = default)
        {
            return Task.CompletedTask;
        }

        public Task DeleteAsync(Guid id, CancellationToken cancellationToken = default)
        {
            return Task.CompletedTask;
        }

        public Task<int> CountAsync(System.Linq.Expressions.Expression<Func<Organization, bool>>? predicate = null, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(0);
        }

        public Task<bool> ExistsAsync(System.Linq.Expressions.Expression<Func<Organization, bool>> predicate, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(false);
        }

        public Task SaveChangesAsync(CancellationToken cancellationToken = default)
        {
            return Task.CompletedTask;
        }

        // IOrganizationRepository specific methods
        public Task<Organization?> GetByStripeCustomerIdAsync(string stripeCustomerId, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<Organization?>(null);
        }

        public Task<bool> CanAddUserAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(true);
        }

        public Task<bool> CanAddRepositoryAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(true);
        }

        public Task<bool> CanPerformScanAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(true);
        }

        public Task IncrementMonthlyScansAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            return Task.CompletedTask;
        }

        public Task ResetMonthlyScansIfNeededAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            return Task.CompletedTask;
        }
    }
}