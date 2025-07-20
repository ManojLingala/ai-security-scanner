using System;
using System.Threading;
using System.Threading.Tasks;
using AISecurityScanner.Domain.Entities;

namespace AISecurityScanner.Domain.Interfaces
{
    public interface IUnitOfWork : IDisposable
    {
        IOrganizationRepository Organizations { get; }
        IRepository<User> Users { get; }
        IRepository<Repository> Repositories { get; }
        IRepository<SecurityScan> SecurityScans { get; }
        IRepository<Vulnerability> Vulnerabilities { get; }
        IRepository<AIProvider> AIProviders { get; }
        IRepository<ApiKey> ApiKeys { get; }
        IRepository<ActivityLog> ActivityLogs { get; }
        
        IRepository<T> GetRepository<T>() where T : BaseEntity;
        Task<int> SaveChangesAsync(CancellationToken cancellationToken = default);
        Task BeginTransactionAsync(CancellationToken cancellationToken = default);
        Task CommitTransactionAsync(CancellationToken cancellationToken = default);
        Task RollbackTransactionAsync(CancellationToken cancellationToken = default);
    }
}