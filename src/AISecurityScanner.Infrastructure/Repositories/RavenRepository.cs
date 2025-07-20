using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Threading;
using System.Threading.Tasks;
using AISecurityScanner.Domain.Entities;
using AISecurityScanner.Domain.Interfaces;
using AISecurityScanner.Infrastructure.Data;
using Raven.Client.Documents;
using Raven.Client.Documents.Session;

namespace AISecurityScanner.Infrastructure.Repositories
{
    public class RavenRepository<T> : IRepository<T> where T : BaseEntity
    {
        private readonly IRavenDbContext _context;
        private readonly IAsyncDocumentSession _session;

        public RavenRepository(IRavenDbContext context)
        {
            _context = context;
            _session = context.OpenAsyncSession();
        }

        public async Task<T?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default)
        {
            return await GetByIdAsync(id.ToString(), cancellationToken);
        }

        public async Task<T?> GetByIdAsync(string id, CancellationToken cancellationToken = default)
        {
            var entity = await _session.LoadAsync<T>(id, cancellationToken);
            return entity != null && !entity.IsDeleted ? entity : null;
        }

        public async Task<IEnumerable<T>> GetAllAsync(CancellationToken cancellationToken = default)
        {
            return await _session.Query<T>()
                .Where(x => !x.IsDeleted)
                .ToListAsync(cancellationToken);
        }

        public async Task<IEnumerable<T>> FindAsync(Expression<Func<T, bool>> predicate, CancellationToken cancellationToken = default)
        {
            return await _session.Query<T>()
                .Where(x => !x.IsDeleted)
                .Where(predicate)
                .ToListAsync(cancellationToken);
        }

        public async Task<T?> FirstOrDefaultAsync(Expression<Func<T, bool>> predicate, CancellationToken cancellationToken = default)
        {
            return await _session.Query<T>()
                .Where(x => !x.IsDeleted)
                .Where(predicate)
                .FirstOrDefaultAsync(cancellationToken);
        }

        public async Task<T> AddAsync(T entity, CancellationToken cancellationToken = default)
        {
            entity.Id = Guid.NewGuid();
            entity.CreatedAt = DateTime.UtcNow;
            entity.ModifiedAt = DateTime.UtcNow;
            
            await _session.StoreAsync(entity, cancellationToken);
            await _session.SaveChangesAsync(cancellationToken);
            
            return entity;
        }

        public async Task UpdateAsync(T entity, CancellationToken cancellationToken = default)
        {
            entity.ModifiedAt = DateTime.UtcNow;
            await _session.SaveChangesAsync(cancellationToken);
        }

        public async Task DeleteAsync(T entity, CancellationToken cancellationToken = default)
        {
            entity.IsDeleted = true;
            entity.DeletedAt = DateTime.UtcNow;
            entity.ModifiedAt = DateTime.UtcNow;
            await _session.SaveChangesAsync(cancellationToken);
        }

        public async Task DeleteAsync(Guid id, CancellationToken cancellationToken = default)
        {
            var entity = await GetByIdAsync(id, cancellationToken);
            if (entity != null)
            {
                await DeleteAsync(entity, cancellationToken);
            }
        }

        public async Task<int> CountAsync(Expression<Func<T, bool>>? predicate = null, CancellationToken cancellationToken = default)
        {
            var query = _session.Query<T>().Where(x => !x.IsDeleted);
            
            if (predicate != null)
            {
                query = query.Where(predicate);
            }

            return await query.CountAsync(cancellationToken);
        }

        public async Task<bool> ExistsAsync(Expression<Func<T, bool>> predicate, CancellationToken cancellationToken = default)
        {
            return await _session.Query<T>()
                .Where(x => !x.IsDeleted)
                .Where(predicate)
                .AnyAsync(cancellationToken);
        }

        public async Task SaveChangesAsync(CancellationToken cancellationToken = default)
        {
            await _session.SaveChangesAsync(cancellationToken);
        }

        public void Dispose()
        {
            _session?.Dispose();
        }
    }
}