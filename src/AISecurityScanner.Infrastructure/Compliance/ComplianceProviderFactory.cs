using System;
using System.Collections.Generic;
using AISecurityScanner.Application.Interfaces;
using AISecurityScanner.Domain.Enums;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace AISecurityScanner.Infrastructure.Compliance
{
    public class ComplianceProviderFactory : IComplianceProviderFactory
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly ILogger<ComplianceProviderFactory> _logger;
        private readonly Dictionary<ComplianceFrameworkType, Type> _providerTypes;

        public ComplianceProviderFactory(IServiceProvider serviceProvider, ILogger<ComplianceProviderFactory> logger)
        {
            _serviceProvider = serviceProvider;
            _logger = logger;
            _providerTypes = new Dictionary<ComplianceFrameworkType, Type>
            {
                { ComplianceFrameworkType.PCI_DSS, typeof(PCIDSSComplianceProvider) },
                { ComplianceFrameworkType.HIPAA, typeof(HIPAAComplianceProvider) },
                { ComplianceFrameworkType.SOX, typeof(SOXComplianceProvider) },
                { ComplianceFrameworkType.GDPR, typeof(GDPRComplianceProvider) }
            };
        }

        public IComplianceProvider GetProvider(ComplianceFrameworkType framework)
        {
            if (!_providerTypes.ContainsKey(framework))
            {
                throw new NotSupportedException($"Compliance framework {framework} is not supported");
            }

            var providerType = _providerTypes[framework];
            var provider = (IComplianceProvider)_serviceProvider.GetRequiredService(providerType);
            
            _logger.LogInformation("Created compliance provider for framework: {Framework}", framework);
            return provider;
        }

        public IEnumerable<IComplianceProvider> GetAllProviders()
        {
            foreach (var framework in _providerTypes.Keys)
            {
                yield return GetProvider(framework);
            }
        }

        public bool IsFrameworkSupported(ComplianceFrameworkType framework)
        {
            return _providerTypes.ContainsKey(framework);
        }
    }
}