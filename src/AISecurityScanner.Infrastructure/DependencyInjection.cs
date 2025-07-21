using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using AISecurityScanner.Application.Interfaces;
using AISecurityScanner.Infrastructure.Compliance;

namespace AISecurityScanner.Infrastructure
{
    public static class DependencyInjection
    {
        public static IServiceCollection AddComplianceInfrastructure(this IServiceCollection services)
        {
            // Register compliance providers
            services.AddScoped<PCIDSSComplianceProvider>();
            services.AddScoped<HIPAAComplianceProvider>();
            services.AddScoped<SOXComplianceProvider>();
            services.AddScoped<GDPRComplianceProvider>();
            
            // Register as IComplianceProvider for factory pattern
            services.AddScoped<IComplianceProvider, PCIDSSComplianceProvider>(provider => 
                provider.GetRequiredService<PCIDSSComplianceProvider>());
            services.AddScoped<IComplianceProvider, HIPAAComplianceProvider>(provider => 
                provider.GetRequiredService<HIPAAComplianceProvider>());
            services.AddScoped<IComplianceProvider, SOXComplianceProvider>(provider => 
                provider.GetRequiredService<SOXComplianceProvider>());
            services.AddScoped<IComplianceProvider, GDPRComplianceProvider>(provider => 
                provider.GetRequiredService<GDPRComplianceProvider>());

            // Register factory
            services.AddSingleton<IComplianceProviderFactory, ComplianceProviderFactory>();

            // Register real-time monitoring
            services.AddSingleton<RealTimeComplianceMonitor>();
            services.AddSingleton<IRealTimeComplianceMonitor>(provider => 
                provider.GetRequiredService<RealTimeComplianceMonitor>());
            services.AddSingleton<IHostedService>(provider => 
                provider.GetRequiredService<RealTimeComplianceMonitor>());

            return services;
        }
    }
}