using System.CommandLine;
using System.CommandLine.Builder;
using System.CommandLine.Parsing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using AISecurityScanner.CLI.Services;
using AISecurityScanner.CLI.Commands;
using AISecurityScanner.CLI.Architecture;
using AISecurityScanner.Application.Services;
using AISecurityScanner.Application.Interfaces;
using AISecurityScanner.Infrastructure.AIProviders;
using AISecurityScanner.Infrastructure;
using Spectre.Console;

namespace AISecurityScanner.CLI
{
    class Program
    {
        private static ServiceProvider? _serviceProvider;
        private static bool _useSlashCommands = false;

        static async Task<int> Main(string[] args)
        {
            // Check if slash commands are being used
            _useSlashCommands = args.Any(arg => arg.StartsWith("/"));

            // Setup dependency injection
            var services = ConfigureServices();
            _serviceProvider = services.BuildServiceProvider();

            // Initialize default profiles on first run
            var profileService = _serviceProvider.GetRequiredService<ConfigurationProfileService>();
            await profileService.InitializeDefaultProfilesAsync();

            // Create root command
            var rootCommand = new RootCommand("🤖 AI Security Scanner - Intelligent vulnerability detection powered by Claude AI");
            
            // Configure root command
            ConfigureRootCommand(rootCommand);

            // Build command line with enhanced features
            var commandLine = new CommandLineBuilder(rootCommand)
                .UseDefaults()
                .UseExceptionHandler((exception, context) =>
                {
                    AnsiConsole.WriteException(exception, ExceptionFormats.ShortenEverything);
                })
                .Build();

            try
            {
                // Handle special cases
                if (args.Length == 0)
                {
                    await ShowInteractiveMenuAsync();
                    return 0;
                }

                if (args.Length == 1 && args[0] == "--interactive")
                {
                    await ShowInteractiveMenuAsync();
                    return 0;
                }

                return await commandLine.InvokeAsync(args);
            }
            finally
            {
                _serviceProvider?.Dispose();
            }
        }

        private static void ConfigureRootCommand(RootCommand rootCommand)
        {
            // Enhanced commands (primary)
            var scanV2 = _serviceProvider!.GetRequiredService<ScanCommandV2>();
            rootCommand.AddCommand(scanV2.BuildCommand());

            // Legacy commands (for backward compatibility)
            var authCommand = CreateAuthCommand();
            rootCommand.AddCommand(authCommand);

            var complianceCommand = CreateComplianceCommand();
            rootCommand.AddCommand(complianceCommand);

            var configCommand = CreateConfigCommand();
            rootCommand.AddCommand(configCommand);

            // Profile command
            var profileCommand = CreateProfileCommand();
            rootCommand.AddCommand(profileCommand);

            // Quick action commands
            var quickCommand = CreateQuickCommand();
            rootCommand.AddCommand(quickCommand);

            // Version command
            var versionCommand = new Command("version", "Show version information");
            versionCommand.SetHandler(() =>
            {
                var version = new FigletText("v1.0.0")
                    .Centered()
                    .Color(Color.Cyan1);
                
                AnsiConsole.Write(version);
                AnsiConsole.WriteLine();
                AnsiConsole.MarkupLine("[bold]AI Security Scanner CLI[/]");
                AnsiConsole.MarkupLine("[grey]AI-powered security vulnerability scanning and compliance checking[/]");
                AnsiConsole.WriteLine();
                AnsiConsole.MarkupLine("🤖 Powered by [cyan]Claude AI[/]");
                AnsiConsole.MarkupLine("🛡️  Supporting [yellow]PCI DSS[/], [blue]HIPAA[/], [red]SOX[/], and [green]GDPR[/] compliance");
                AnsiConsole.WriteLine();
                AnsiConsole.MarkupLine("[grey]Run 'aiscan --help' for usage information[/]");
            });
            rootCommand.AddCommand(versionCommand);

            // Global options
            var verboseOption = new Option<bool>(
                new[] { "--verbose", "-V" },
                "Enable verbose output");
            rootCommand.AddGlobalOption(verboseOption);

            var quietOption = new Option<bool>(
                new[] { "--quiet", "-q" },
                "Suppress non-essential output");
            rootCommand.AddGlobalOption(quietOption);

            var noColorOption = new Option<bool>(
                "--no-color",
                "Disable colored output");
            rootCommand.AddGlobalOption(noColorOption);
        }

        private static async Task ShowInteractiveMenuAsync()
        {
            AnsiConsole.Clear();
            
            var banner = new FigletText("AI Security Scanner")
                .Centered()
                .Color(Color.Cyan1);
            AnsiConsole.Write(banner);
            
            AnsiConsole.WriteLine();

            while (true)
            {
                var choice = AnsiConsole.Prompt(
                    new SelectionPrompt<string>()
                        .Title("What would you like to do?")
                        .AddChoices(new[]
                        {
                            "🔍 Quick Scan (current directory)",
                            "📋 Configure & Run Scan",
                            "🏃 Use Scan Preset",
                            "🔐 Manage Authentication",
                            "⚙️  Configure Settings",
                            "👤 Manage Profiles",
                            "📊 View Recent Results",
                            "❓ Help & Documentation",
                            "🚪 Exit"
                        })
                        .HighlightStyle(new Style(Color.Cyan1)));

                switch (choice)
                {
                    case "🔍 Quick Scan (current directory)":
                        await RunQuickScanAsync();
                        break;
                    
                    case "📋 Configure & Run Scan":
                        await RunInteractiveScanAsync();
                        break;
                    
                    case "🏃 Use Scan Preset":
                        await RunPresetScanAsync();
                        break;
                    
                    case "🔐 Manage Authentication":
                        await ManageAuthenticationAsync();
                        break;
                    
                    case "⚙️  Configure Settings":
                        await ConfigureSettingsAsync();
                        break;
                    
                    case "👤 Manage Profiles":
                        await ManageProfilesAsync();
                        break;
                    
                    case "📊 View Recent Results":
                        AnsiConsole.MarkupLine("[yellow]Feature coming soon![/]");
                        break;
                    
                    case "❓ Help & Documentation":
                        ShowHelp();
                        break;
                    
                    case "🚪 Exit":
                        return;
                }

                AnsiConsole.WriteLine();
                if (!AnsiConsole.Confirm("Return to main menu?"))
                    return;
                
                AnsiConsole.Clear();
                AnsiConsole.Write(banner);
                AnsiConsole.WriteLine();
            }
        }

        private static async Task RunQuickScanAsync()
        {
            var scanService = _serviceProvider!.GetRequiredService<ScanService>();
            await scanService.ScanDirectoryAsync(".", "table", true);
        }

        private static async Task RunInteractiveScanAsync()
        {
            var interactiveService = _serviceProvider!.GetRequiredService<InteractiveModeService>();
            var config = await interactiveService.ConfigureScanAsync(".");
            
            if (config != null)
            {
                var scanService = _serviceProvider!.GetRequiredService<ScanService>();
                
                if (config.Target.StartsWith("@"))
                {
                    await scanService.ScanDirectoryAsync(config.Target[1..], config.Format, true);
                }
                else
                {
                    await scanService.ScanFileAsync(config.Target, config.Format);
                }
            }
        }

        private static async Task RunPresetScanAsync()
        {
            var interactiveService = _serviceProvider!.GetRequiredService<InteractiveModeService>();
            var preset = await interactiveService.SelectPresetAsync();
            
            if (preset != null)
            {
                AnsiConsole.MarkupLine($"[cyan]Running preset scan with options: {preset}[/]");
                // Parse and execute preset
            }
        }

        private static async Task ManageAuthenticationAsync()
        {
            var authService = _serviceProvider!.GetRequiredService<AuthService>();
            
            var choice = AnsiConsole.Prompt(
                new SelectionPrompt<string>()
                    .Title("Authentication Management")
                    .AddChoices(new[]
                    {
                        "Login",
                        "Check Status",
                        "Logout",
                        "Back"
                    }));

            switch (choice)
            {
                case "Login":
                    await authService.LoginAsync();
                    break;
                case "Check Status":
                    await authService.ShowStatusAsync();
                    break;
                case "Logout":
                    await authService.LogoutAsync();
                    break;
            }
        }

        private static async Task ConfigureSettingsAsync()
        {
            var configService = _serviceProvider!.GetRequiredService<ConfigService>();
            var config = await configService.GetConfigAsync();
            
            var choice = AnsiConsole.Prompt(
                new SelectionPrompt<string>()
                    .Title("What would you like to configure?")
                    .AddChoices(new[]
                    {
                        $"Output Format (current: {config.OutputFormat})",
                        $"Scan Timeout (current: {config.ScanTimeoutSeconds}s)",
                        $"Max Concurrent Scans (current: {config.MaxConcurrentScans})",
                        "Compliance Frameworks",
                        "Back"
                    }));

            if (choice.StartsWith("Output Format"))
            {
                var format = AnsiConsole.Prompt(
                    new SelectionPrompt<string>()
                        .Title("Select output format:")
                        .AddChoices(new[] { "table", "json", "csv", "sarif", "html" }));
                
                await configService.SetSettingAsync("OutputFormat", format);
                AnsiConsole.MarkupLine($"[green]✅ Output format set to {format}[/]");
            }
            // Handle other configuration options...
        }

        private static async Task ManageProfilesAsync()
        {
            var profileService = _serviceProvider!.GetRequiredService<ConfigurationProfileService>();
            
            var choice = AnsiConsole.Prompt(
                new SelectionPrompt<string>()
                    .Title("Profile Management")
                    .AddChoices(new[]
                    {
                        "List Profiles",
                        "Apply Profile",
                        "Create Profile",
                        "Create from Current Settings",
                        "Delete Profile",
                        "Back"
                    }));

            switch (choice)
            {
                case "List Profiles":
                    var profiles = await profileService.ListProfilesAsync();
                    var table = new Table()
                        .Border(TableBorder.Rounded)
                        .AddColumn("Name")
                        .AddColumn("Description")
                        .AddColumn("Last Used");
                    
                    foreach (var profile in profiles)
                    {
                        table.AddRow(
                            profile.Name,
                            profile.Description,
                            profile.LastUsed == default ? "Never" : profile.LastUsed.ToString("yyyy-MM-dd HH:mm")
                        );
                    }
                    
                    AnsiConsole.Write(table);
                    break;
                
                case "Apply Profile":
                    var profileList = await profileService.ListProfilesAsync();
                    if (profileList.Any())
                    {
                        var profileName = AnsiConsole.Prompt(
                            new SelectionPrompt<string>()
                                .Title("Select profile to apply:")
                                .AddChoices(profileList.Select(p => p.Name)));
                        
                        await profileService.ApplyProfileAsync(profileName);
                    }
                    else
                    {
                        AnsiConsole.MarkupLine("[yellow]No profiles found[/]");
                    }
                    break;
                
                case "Create from Current Settings":
                    var name = AnsiConsole.Ask<string>("Profile name:");
                    var description = AnsiConsole.Ask<string>("Profile description:");
                    await profileService.CreateProfileFromCurrentAsync(name, description);
                    break;
            }
        }

        private static void ShowHelp()
        {
            AnsiConsole.Clear();
            
            var panel = new Panel(
                "[bold]AI Security Scanner Help[/]\n\n" +
                "[cyan]Quick Start:[/]\n" +
                "  aiscan /scan @.              - Scan current directory\n" +
                "  aiscan /scan file.cs         - Scan specific file\n" +
                "  aiscan /scan --interactive   - Interactive configuration\n\n" +
                "[cyan]Common Commands:[/]\n" +
                "  aiscan auth login            - Authenticate with Claude\n" +
                "  aiscan compliance list       - List compliance frameworks\n" +
                "  aiscan config profile apply  - Apply configuration profile\n\n" +
                "[cyan]Advanced Features:[/]\n" +
                "  --watch                      - Watch mode for real-time scanning\n" +
                "  --deep                       - Deep analysis with AI\n" +
                "  --compliance=PCI-DSS,HIPAA   - Check specific compliance\n\n" +
                "[cyan]Performance Profiles:[/]\n" +
                "  --performance=optimization   - Fast scanning\n" +
                "  --performance=complex        - Thorough analysis\n\n" +
                "Press any key to continue...")
                .Header("Help")
                .BorderColor(Color.Cyan1)
                .Padding(2, 1);
            
            AnsiConsole.Write(panel);
            Console.ReadKey();
        }

        private static Command CreateQuickCommand()
        {
            var quickCommand = new Command("quick", "Quick actions for common tasks");
            
            // Quick scan current directory
            var scanCurrentCommand = new Command("scan", "Quick scan current directory");
            scanCurrentCommand.SetHandler(async () =>
            {
                if (!await CheckAuthenticationAsync())
                    return;
                
                var scanService = _serviceProvider!.GetRequiredService<ScanService>();
                await scanService.ScanDirectoryAsync(".", "table", true);
            });
            
            // Quick OWASP check
            var owaspCommand = new Command("owasp", "Quick OWASP Top 10 check");
            owaspCommand.SetHandler(async () =>
            {
                if (!await CheckAuthenticationAsync())
                    return;
                
                AnsiConsole.MarkupLine("[cyan]Running OWASP Top 10 security check...[/]");
                var complianceService = _serviceProvider!.GetRequiredService<ComplianceCliService>();
                await complianceService.ScanComplianceAsync("owasp", ".", "table");
            });
            
            quickCommand.AddCommand(scanCurrentCommand);
            quickCommand.AddCommand(owaspCommand);
            
            return quickCommand;
        }

        private static Command CreateProfileCommand()
        {
            var profileCommand = new Command("profile", "Configuration profile management");
            
            var listCommand = new Command("list", "List all profiles");
            listCommand.SetHandler(async () =>
            {
                var profileService = _serviceProvider!.GetRequiredService<ConfigurationProfileService>();
                var profiles = await profileService.ListProfilesAsync();
                
                if (!profiles.Any())
                {
                    AnsiConsole.MarkupLine("[yellow]No profiles found[/]");
                    return;
                }
                
                var table = new Table()
                    .Border(TableBorder.Rounded)
                    .AddColumn("Name")
                    .AddColumn("Description")
                    .AddColumn("Created")
                    .AddColumn("Last Used");
                
                foreach (var profile in profiles)
                {
                    table.AddRow(
                        profile.Name,
                        profile.Description,
                        profile.CreatedAt.ToString("yyyy-MM-dd"),
                        profile.LastUsed == default ? "Never" : profile.LastUsed.ToString("yyyy-MM-dd HH:mm")
                    );
                }
                
                AnsiConsole.Write(table);
            });
            
            var applyCommand = new Command("apply", "Apply a profile");
            var profileNameArg = new Argument<string>("name", "Profile name");
            applyCommand.AddArgument(profileNameArg);
            applyCommand.SetHandler(async (string name) =>
            {
                var profileService = _serviceProvider!.GetRequiredService<ConfigurationProfileService>();
                await profileService.ApplyProfileAsync(name);
            }, profileNameArg);
            
            var createCommand = new Command("create", "Create a new profile");
            var createNameArg = new Argument<string>("name", "Profile name");
            var descriptionOption = new Option<string>("--description", "Profile description");
            createCommand.AddArgument(createNameArg);
            createCommand.AddOption(descriptionOption);
            createCommand.SetHandler(async (string name, string description) =>
            {
                var profileService = _serviceProvider!.GetRequiredService<ConfigurationProfileService>();
                await profileService.CreateProfileFromCurrentAsync(name, description ?? "Custom profile");
            }, createNameArg, descriptionOption);
            
            profileCommand.AddCommand(listCommand);
            profileCommand.AddCommand(applyCommand);
            profileCommand.AddCommand(createCommand);
            
            return profileCommand;
        }

        // Keep existing command creation methods for backward compatibility
        private static Command CreateAuthCommand()
        {
            // Same as in original Program.cs
            var authCommand = new Command("auth", "Authentication commands");

            var loginCommand = new Command("login", "Authenticate with Claude Code token");
            loginCommand.SetHandler(async () =>
            {
                var authService = _serviceProvider!.GetRequiredService<AuthService>();
                var success = await authService.LoginAsync();
                Environment.Exit(success ? 0 : 1);
            });

            var statusCommand = new Command("status", "Show authentication status");
            statusCommand.SetHandler(async () =>
            {
                var authService = _serviceProvider!.GetRequiredService<AuthService>();
                await authService.ShowStatusAsync();
            });

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
            // Keep existing scan command for backward compatibility
            var scanCommand = new Command("scan", "Security scanning commands");

            var fileCommand = new Command("file", "Scan a single file");
            var filePathArgument = new Argument<string>("path", "Path to the file to scan");
            fileCommand.AddArgument(filePathArgument);
            
            var formatOption = new Option<string>(
                "--format",
                description: "Output format (table, json, csv)",
                getDefaultValue: () => "table"
            );
            fileCommand.AddOption(formatOption);
            
            fileCommand.SetHandler(async (string path, string format) =>
            {
                if (!await CheckAuthenticationAsync())
                    return;

                var scanService = _serviceProvider!.GetRequiredService<ScanService>();
                var success = await scanService.ScanFileAsync(path, format);
                Environment.Exit(success ? 0 : 1);
            }, filePathArgument, formatOption);

            scanCommand.AddCommand(fileCommand);
            
            return scanCommand;
        }

        private static Command CreateComplianceCommand()
        {
            // Keep existing compliance command
            var complianceCommand = new Command("compliance", "Compliance scanning and reporting");

            var listCommand = new Command("list", "List supported compliance frameworks");
            listCommand.SetHandler(() =>
            {
                var complianceService = _serviceProvider!.GetRequiredService<ComplianceCliService>();
                complianceService.ListFrameworks();
            });

            complianceCommand.AddCommand(listCommand);
            
            return complianceCommand;
        }

        private static Command CreateConfigCommand()
        {
            // Keep existing config command
            var configCommand = new Command("config", "Configuration management");

            var listCommand = new Command("list", "List all configuration settings");
            listCommand.SetHandler(async () =>
            {
                var configService = _serviceProvider!.GetRequiredService<ConfigService>();
                var config = await configService.GetConfigAsync();
                
                AnsiConsole.MarkupLine("[bold]⚙️  Configuration Settings[/]");
                AnsiConsole.Write(new Rule().RuleStyle("grey"));
                
                var table = new Table()
                    .Border(TableBorder.None)
                    .AddColumn("Setting")
                    .AddColumn("Value");
                
                table.AddRow("Output Format", config.OutputFormat);
                table.AddRow("Scan Timeout", $"{config.ScanTimeoutSeconds}s");
                table.AddRow("Max Concurrent Scans", config.MaxConcurrentScans.ToString());
                table.AddRow("Enabled Frameworks", string.Join(", ", config.EnabledComplianceFrameworks));
                
                AnsiConsole.Write(table);
            });

            configCommand.AddCommand(listCommand);
            
            return configCommand;
        }

        private static async Task<bool> CheckAuthenticationAsync()
        {
            var authService = _serviceProvider!.GetRequiredService<AuthService>();
            
            if (!await authService.IsAuthenticatedAsync())
            {
                AnsiConsole.MarkupLine("[red]❌ You are not authenticated.[/]");
                AnsiConsole.MarkupLine("Run '[cyan]aiscan auth login[/]' to authenticate first.");
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
                builder.SetMinimumLevel(LogLevel.Warning);
            });

            // CLI Services
            services.AddScoped<ConfigService>();
            services.AddScoped<AuthService>();
            services.AddScoped<ScanService>();
            services.AddScoped<ComplianceCliService>();
            services.AddScoped<InteractiveModeService>();
            services.AddScoped<ConfigurationProfileService>();

            // Enhanced Commands
            services.AddScoped<ScanCommandV2>();

            // Infrastructure Services
            services.AddScoped<ClaudeProvider>();
            services.AddScoped<IAIProvider>(provider => provider.GetRequiredService<ClaudeProvider>());

            return services;
        }
    }
}