using System.CommandLine;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using AISecurityScanner.CLI.Services;
using AISecurityScanner.Application.Services;
using AISecurityScanner.Application.Interfaces;
using AISecurityScanner.Infrastructure.AIProviders;
using AISecurityScanner.Infrastructure;

namespace AISecurityScanner.CLI
{
    class Program
    {
        private static ServiceProvider? _serviceProvider;

        static async Task<int> Main(string[] args)
        {
            // Setup dependency injection
            var services = ConfigureServices();
            _serviceProvider = services.BuildServiceProvider();

            // Create root command
            var rootCommand = new RootCommand("AI Security Scanner CLI - AI-powered security vulnerability scanning and compliance checking");

            // Auth commands
            var authCommand = CreateAuthCommand();
            rootCommand.AddCommand(authCommand);

            // Scan commands
            var scanCommand = CreateScanCommand();
            rootCommand.AddCommand(scanCommand);

            // Compliance commands
            var complianceCommand = CreateComplianceCommand();
            rootCommand.AddCommand(complianceCommand);

            // Config commands
            var configCommand = CreateConfigCommand();
            rootCommand.AddCommand(configCommand);
            
            // Version command
            var versionCommand = new Command("version", "Show version information");
            versionCommand.SetHandler(() =>
            {
                Console.WriteLine("AI Security Scanner CLI v1.0.0");
                Console.WriteLine("AI-powered security vulnerability scanning and compliance checking");
                Console.WriteLine();
                Console.WriteLine("🤖 Powered by Claude AI");
                Console.WriteLine("🛡️ Supporting PCI DSS, HIPAA, SOX, and GDPR compliance frameworks");
            });
            rootCommand.AddCommand(versionCommand);

            try
            {
                return await rootCommand.InvokeAsync(args);
            }
            finally
            {
                _serviceProvider?.Dispose();
            }
        }

        private static Command CreateAuthCommand()
        {
            var authCommand = new Command("auth", "Authentication commands");

            // Login command
            var loginCommand = new Command("login", "Authenticate with Claude Code token");
            loginCommand.SetHandler(async () =>
            {
                var authService = _serviceProvider!.GetRequiredService<AuthService>();
                var success = await authService.LoginAsync();
                Environment.Exit(success ? 0 : 1);
            });

            // Status command
            var statusCommand = new Command("status", "Show authentication status");
            statusCommand.SetHandler(async () =>
            {
                var authService = _serviceProvider!.GetRequiredService<AuthService>();
                await authService.ShowStatusAsync();
            });

            // Logout command
            var logoutCommand = new Command("logout", "Clear stored credentials");
            logoutCommand.SetHandler(async () =>
            {
                var authService = _serviceProvider!.GetRequiredService<AuthService>();
                await authService.LogoutAsync();
            });

            authCommand.AddCommand(loginCommand);
            authCommand.AddCommand(statusCommand);
            authCommand.AddCommand(logoutCommand);

            return authCommand;
        }

        private static Command CreateScanCommand()
        {
            var scanCommand = new Command("scan", "Security scanning commands");

            // Common options
            var formatOption = new Option<string>(
                "--format",
                description: "Output format (table, json, csv)",
                getDefaultValue: () => "table"
            );

            // File scan command
            var fileCommand = new Command("file", "Scan a single file");
            var filePathArgument = new Argument<string>("path", "Path to the file to scan");
            fileCommand.AddArgument(filePathArgument);
            fileCommand.AddOption(formatOption);
            
            fileCommand.SetHandler(async (string path, string format) =>
            {
                if (!await CheckAuthenticationAsync())
                    return;

                var scanService = _serviceProvider!.GetRequiredService<ScanService>();
                var success = await scanService.ScanFileAsync(path, format);
                Environment.Exit(success ? 0 : 1);
            }, filePathArgument, formatOption);

            // Directory scan command
            var directoryCommand = new Command("directory", "Scan all files in a directory");
            var dirPathArgument = new Argument<string>("path", "Path to the directory to scan");
            var recursiveOption = new Option<bool>("--recursive", description: "Scan subdirectories", getDefaultValue: () => true);
            
            directoryCommand.AddArgument(dirPathArgument);
            directoryCommand.AddOption(formatOption);
            directoryCommand.AddOption(recursiveOption);
            
            directoryCommand.SetHandler(async (string path, string format, bool recursive) =>
            {
                if (!await CheckAuthenticationAsync())
                    return;

                var scanService = _serviceProvider!.GetRequiredService<ScanService>();
                var success = await scanService.ScanDirectoryAsync(path, format, recursive);
                Environment.Exit(success ? 0 : 1);
            }, dirPathArgument, formatOption, recursiveOption);

            // Project scan command
            var projectCommand = new Command("project", "Scan the current project/repository");
            projectCommand.AddOption(formatOption);
            
            projectCommand.SetHandler(async (string format) =>
            {
                if (!await CheckAuthenticationAsync())
                    return;

                var scanService = _serviceProvider!.GetRequiredService<ScanService>();
                var success = await scanService.ScanProjectAsync(format);
                Environment.Exit(success ? 0 : 1);
            }, formatOption);

            scanCommand.AddCommand(fileCommand);
            scanCommand.AddCommand(directoryCommand);
            scanCommand.AddCommand(projectCommand);

            return scanCommand;
        }

        private static Command CreateComplianceCommand()
        {
            var complianceCommand = new Command("compliance", "Compliance scanning and reporting");

            // List frameworks command
            var listCommand = new Command("list", "List supported compliance frameworks");
            listCommand.SetHandler(() =>
            {
                var complianceService = _serviceProvider!.GetRequiredService<ComplianceCliService>();
                complianceService.ListFrameworks();
            });

            // Scan command
            var scanCommand = new Command("scan", "Run compliance scan");
            var frameworkOption = new Option<string>(
                "--framework",
                "Compliance framework (pci-dss, hipaa, sox, gdpr)"
            ) { IsRequired = true };
            
            var pathOption = new Option<string>(
                "--path",
                description: "Path to scan",
                getDefaultValue: () => Directory.GetCurrentDirectory()
            );
            
            var formatOption = new Option<string>(
                "--format",
                description: "Output format (table, json, csv)",
                getDefaultValue: () => "table"
            );

            scanCommand.AddOption(frameworkOption);
            scanCommand.AddOption(pathOption);
            scanCommand.AddOption(formatOption);
            
            scanCommand.SetHandler(async (string framework, string path, string format) =>
            {
                if (!await CheckAuthenticationAsync())
                    return;

                var complianceService = _serviceProvider!.GetRequiredService<ComplianceCliService>();
                var success = await complianceService.ScanComplianceAsync(framework, path, format);
                Environment.Exit(success ? 0 : 1);
            }, frameworkOption, pathOption, formatOption);

            complianceCommand.AddCommand(listCommand);
            complianceCommand.AddCommand(scanCommand);

            return complianceCommand;
        }

        private static Command CreateConfigCommand()
        {
            var configCommand = new Command("config", "Configuration management");

            // List config command
            var listCommand = new Command("list", "List all configuration settings");
            listCommand.SetHandler(async () =>
            {
                var configService = _serviceProvider!.GetRequiredService<ConfigService>();
                var config = await configService.GetConfigAsync();
                
                Console.WriteLine("⚙️ Configuration Settings");
                Console.WriteLine("━━━━━━━━━━━━━━━━━━━━━━━━");
                Console.WriteLine($"Output Format: {config.OutputFormat}");
                Console.WriteLine($"Scan Timeout: {config.ScanTimeoutSeconds}s");
                Console.WriteLine($"Max Concurrent Scans: {config.MaxConcurrentScans}");
                Console.WriteLine($"Enabled Frameworks: {string.Join(", ", config.EnabledComplianceFrameworks)}");
            });

            // Get config command
            var getCommand = new Command("get", "Get a configuration value");
            var getKeyArgument = new Argument<string>("key", "Configuration key");
            getCommand.AddArgument(getKeyArgument);
            
            getCommand.SetHandler(async (string key) =>
            {
                var configService = _serviceProvider!.GetRequiredService<ConfigService>();
                var value = await configService.GetSettingAsync(key, "Not set");
                Console.WriteLine(value);
            }, getKeyArgument);

            // Set config command
            var setCommand = new Command("set", "Set a configuration value");
            var setKeyArgument = new Argument<string>("key", "Configuration key");
            var setValueArgument = new Argument<string>("value", "Configuration value");
            
            setCommand.AddArgument(setKeyArgument);
            setCommand.AddArgument(setValueArgument);
            
            setCommand.SetHandler(async (string key, string value) =>
            {
                var configService = _serviceProvider!.GetRequiredService<ConfigService>();
                await configService.SetSettingAsync(key, value);
                Console.WriteLine($"✅ Set {key} = {value}");
            }, setKeyArgument, setValueArgument);

            configCommand.AddCommand(listCommand);
            configCommand.AddCommand(getCommand);
            configCommand.AddCommand(setCommand);

            return configCommand;
        }

        private static async Task<bool> CheckAuthenticationAsync()
        {
            var authService = _serviceProvider!.GetRequiredService<AuthService>();
            
            if (!await authService.IsAuthenticatedAsync())
            {
                Console.WriteLine("❌ You are not authenticated.");
                Console.WriteLine("Run 'aiscan auth login' to authenticate first.");
                return false;
            }
            
            return true;
        }

        private static IServiceCollection ConfigureServices()
        {
            var services = new ServiceCollection();

            // Configuration
            var configuration = new ConfigurationBuilder()
                .AddJsonFile("appsettings.json", optional: true)
                .AddEnvironmentVariables()
                .Build();

            services.AddSingleton<IConfiguration>(configuration);

            // Logging
            services.AddLogging(builder =>
            {
                builder.AddConsole();
                builder.SetMinimumLevel(LogLevel.Warning); // Reduce noise in CLI
            });

            // CLI Services
            services.AddScoped<ConfigService>();
            services.AddScoped<AuthService>();
            services.AddScoped<ScanService>();
            services.AddScoped<ComplianceCliService>();

            // Infrastructure Services (minimal for CLI)
            // Note: Only register what's needed for CLI operation
            
            // AI Providers (will use token from config)
            services.AddScoped<ClaudeProvider>();
            services.AddScoped<IAIProvider>(provider => provider.GetRequiredService<ClaudeProvider>());

            return services;
        }
    }
}
