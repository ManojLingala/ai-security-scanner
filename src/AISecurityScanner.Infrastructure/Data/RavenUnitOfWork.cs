using System;
using System.Threading;
using System.Threading.Tasks;
using AISecurityScanner.Domain.Entities;
using AISecurityScanner.Domain.Interfaces;
using AISecurityScanner.Infrastructure.Repositories;
using Raven.Client.Documents.Session;

namespace AISecurityScanner.Infrastructure.Data
{
    public class RavenUnitOfWork : IUnitOfWork
    {
        private readonly IRavenDbContext _context;
        private readonly IAsyncDocumentSession _session;
        private bool _disposed;

        private IOrganizationRepository? _organizations;
        private IRepository<User>? _users;
        private IRepository<Repository>? _repositories;
        private IRepository<SecurityScan>? _securityScans;
        private IRepository<Vulnerability>? _vulnerabilities;
        private IRepository<AIProvider>? _aiProviders;
        private IRepository<ApiKey>? _apiKeys;
        private IRepository<ActivityLog>? _activityLogs;

        public RavenUnitOfWork(IRavenDbContext context)
        {
            _context = context;
            _session = context.OpenAsyncSession();
        }

        public IOrganizationRepository Organizations =>
            _organizations ??= new OrganizationRepository(_context);

        public IRepository<User> Users =>
            _users ??= new RavenRepository<User>(_context);

        public IRepository<Repository> Repositories =>
            _repositories ??= new RavenRepository<Repository>(_context);

        public IRepository<SecurityScan> SecurityScans =>
            _securityScans ??= new RavenRepository<SecurityScan>(_context);

        public IRepository<Vulnerability> Vulnerabilities =>
            _vulnerabilities ??= new RavenRepository<Vulnerability>(_context);

        public IRepository<AIProvider> AIProviders =>
            _aiProviders ??= new RavenRepository<AIProvider>(_context);

        public IRepository<ApiKey> ApiKeys =>
            _apiKeys ??= new RavenRepository<ApiKey>(_context);

        public IRepository<ActivityLog> ActivityLogs =>
            _activityLogs ??= new RavenRepository<ActivityLog>(_context);

        public IRepository<T> GetRepository<T>() where T : BaseEntity
        {
            return new RavenRepository<T>(_context);
        }

        public async Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
        {
            await _session.SaveChangesAsync(cancellationToken);
            return _session.Advanced.NumberOfRequests;
        }

        public Task BeginTransactionAsync(CancellationToken cancellationToken = default)
        {
            // RavenDB handles transactions automatically within a session
            return Task.CompletedTask;
        }

        public async Task CommitTransactionAsync(CancellationToken cancellationToken = default)
        {
            await _session.SaveChangesAsync(cancellationToken);
        }

        public Task RollbackTransactionAsync(CancellationToken cancellationToken = default)
        {
            // RavenDB automatically rolls back if SaveChanges is not called
            return Task.CompletedTask;
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    _session?.Dispose();
                }
                _disposed = true;
            }
        }

        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }
}