using Raven.Client.Documents;
using Raven.Client.Documents.Session;
using Raven.Client.Documents.Conventions;
using System.Security.Cryptography.X509Certificates;
using AISecurityScanner.Infrastructure.Configuration;
using AISecurityScanner.Domain.Entities;
using Raven.Client.Documents.Indexes;
using Raven.Client.ServerWide;
using Raven.Client.ServerWide.Operations;
using Raven.Client.Exceptions;
using System.Reflection;

namespace AISecurityScanner.Infrastructure.Data
{
    public interface IRavenDbContext
    {
        IDocumentStore Store { get; }
        IAsyncDocumentSession OpenAsyncSession();
        IDocumentSession OpenSession();
        Task EnsureIndexesCreatedAsync();
    }

    public class RavenDbContext : IRavenDbContext
    {
        private readonly IDocumentStore _store;
        private readonly RavenDbConfiguration _configuration;

        public IDocumentStore Store => _store;

        public RavenDbContext(RavenDbConfiguration configuration)
        {
            _configuration = configuration;
            _store = CreateDocumentStore(configuration);
            _store.Initialize();
        }

        private IDocumentStore CreateDocumentStore(RavenDbConfiguration configuration)
        {
            var conventions = new DocumentConventions
            {
                IdentityPartsSeparator = '-',
                UseOptimisticConcurrency = true,
                MaxNumberOfRequestsPerSession = 100,
                ReadBalanceBehavior = Raven.Client.Http.ReadBalanceBehavior.RoundRobin
            };

            var store = new DocumentStore
            {
                Urls = configuration.Urls,
                Database = configuration.Database,
                Conventions = conventions
            };

            if (!string.IsNullOrEmpty(configuration.CertificatePath))
            {
                store.Certificate = new X509Certificate2(
                    configuration.CertificatePath, 
                    configuration.CertificatePassword);
            }

            RegisterIdConventions(store.Conventions);

            return store;
        }

        private void RegisterIdConventions(DocumentConventions conventions)
        {
            conventions.RegisterAsyncIdConvention<Organization>((dbName, entity) => 
                Task.FromResult($"organizations/{entity.Id}"));
            
            conventions.RegisterAsyncIdConvention<User>((dbName, entity) => 
                Task.FromResult($"users/{entity.Id}"));
            
            conventions.RegisterAsyncIdConvention<Repository>((dbName, entity) => 
                Task.FromResult($"repositories/{entity.Id}"));
            
            conventions.RegisterAsyncIdConvention<SecurityScan>((dbName, entity) => 
                Task.FromResult($"scans/{entity.Id}"));
            
            conventions.RegisterAsyncIdConvention<Vulnerability>((dbName, entity) => 
                Task.FromResult($"vulnerabilities/{entity.Id}"));
            
            conventions.RegisterAsyncIdConvention<AIProvider>((dbName, entity) => 
                Task.FromResult($"ai-providers/{entity.Id}"));
        }

        public IAsyncDocumentSession OpenAsyncSession()
        {
            var session = _store.OpenAsyncSession();
            session.Advanced.MaxNumberOfRequestsPerSession = 100;
            return session;
        }

        public IDocumentSession OpenSession()
        {
            var session = _store.OpenSession();
            session.Advanced.MaxNumberOfRequestsPerSession = 100;
            return session;
        }

        public async Task EnsureIndexesCreatedAsync()
        {
            // First ensure the database exists
            await EnsureDatabaseExistsAsync();
            
            await IndexCreation.CreateIndexesAsync(
                Assembly.GetExecutingAssembly(), 
                _store);
        }

        private async Task EnsureDatabaseExistsAsync()
        {
            try
            {
                var databaseRecord = new Raven.Client.ServerWide.DatabaseRecord(_configuration.Database);
                await _store.Maintenance.Server.SendAsync(new Raven.Client.ServerWide.Operations.CreateDatabaseOperation(databaseRecord));
            }
            catch (Raven.Client.Exceptions.ConcurrencyException)
            {
                // Database already exists, which is fine
            }
        }
    }
}