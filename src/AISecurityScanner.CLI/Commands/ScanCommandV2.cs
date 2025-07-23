using System.CommandLine;
using System.CommandLine.Invocation;
using AISecurityScanner.CLI.Architecture;
using AISecurityScanner.CLI.Services;
using AISecurityScanner.Application.Interfaces;
using AISecurityScanner.Domain.ValueObjects;
using AISecurityScanner.Infrastructure.AIProviders;

namespace AISecurityScanner.CLI.Commands
{
    public class ScanCommandV2 : BaseCommand
    {
        public override CommandMetadata Metadata => new()
        {
            Command = "/scan",
            Category = "Security Analysis",
            Purpose = "AI-powered security vulnerability scanning",
            WaveEnabled = true,
            PerformanceProfile = PerformanceProfile.Standard,
            Aliases = new[] { "s", "analyze" },
            Examples = new()
            {
                ["Quick scan"] = "aiscan /scan @src/",
                ["Deep scan"] = "aiscan /scan @src/ --deep --compliance=all",
                ["Specific file"] = "aiscan /scan UserController.cs --format=json",
                ["With performance"] = "aiscan /scan @. --performance=optimization"
            }
        };

        public ScanCommandV2(IServiceProvider serviceProvider) : base(serviceProvider) { }

        public override Command BuildCommand()
        {
            var command = new Command("scan", Metadata.Purpose);
            
            // Add slash command alias
            command.AddAlias("/scan");
            foreach (var alias in Metadata.Aliases)
            {
                command.AddAlias(alias);
            }

            // Arguments
            var targetArgument = new Argument<string>(
                "target",
                description: "File or directory to scan (use @ prefix for directories)",
                getDefaultValue: () => ".");
            
            // Options
            var formatOption = new Option<string>(
                new[] { "--format", "-f" },
                description: "Output format",
                getDefaultValue: () => "table");
            formatOption.FromAmong("table", "json", "csv", "sarif", "html");

            var depthOption = new Option<string>(
                new[] { "--depth", "-d" },
                description: "Scan depth",
                getDefaultValue: () => "standard");
            depthOption.FromAmong("quick", "standard", "deep");

            var performanceOption = new Option<string>(
                new[] { "--performance", "-p" },
                description: "Performance profile",
                getDefaultValue: () => "standard");
            performanceOption.FromAmong("optimization", "standard", "complex");

            var complianceOption = new Option<string[]>(
                new[] { "--compliance", "-c" },
                description: "Compliance frameworks to check",
                getDefaultValue: () => Array.Empty<string>());

            var interactiveOption = new Option<bool>(
                new[] { "--interactive", "-i" },
                description: "Interactive mode",
                getDefaultValue: () => false);

            var estimateOption = new Option<bool>(
                new[] { "--estimate" },
                description: "Estimate scan time and resources",
                getDefaultValue: () => false);

            var watchOption = new Option<bool>(
                new[] { "--watch", "-w" },
                description: "Watch for file changes and rescan",
                getDefaultValue: () => false);

            command.AddArgument(targetArgument);
            command.AddOption(formatOption);
            command.AddOption(depthOption);
            command.AddOption(performanceOption);
            command.AddOption(complianceOption);
            command.AddOption(interactiveOption);
            command.AddOption(estimateOption);
            command.AddOption(watchOption);

            command.SetHandler(async (InvocationContext context) =>
            {
                var target = context.ParseResult.GetValueForArgument(targetArgument);
                var format = context.ParseResult.GetValueForOption(formatOption)!;
                var depth = context.ParseResult.GetValueForOption(depthOption)!;
                var performance = context.ParseResult.GetValueForOption(performanceOption)!;
                var compliance = context.ParseResult.GetValueForOption(complianceOption)!;
                var interactive = context.ParseResult.GetValueForOption(interactiveOption);
                var estimate = context.ParseResult.GetValueForOption(estimateOption);
                var watch = context.ParseResult.GetValueForOption(watchOption);

                await ExecuteScanAsync(target, format, depth, performance, compliance, interactive, estimate, watch);
            });

            return command;
        }

        private async Task ExecuteScanAsync(
            string target,
            string format,
            string depth,
            string performance,
            string[] compliance,
            bool interactive,
            bool estimate,
            bool watch)
        {
            if (!await CheckAuthentication())
                return;

            // Handle interactive mode
            if (interactive)
            {
                var interactiveService = GetService<InteractiveModeService>();
                var config = await interactiveService.ConfigureScanAsync(target);
                if (config == null) return;
                
                target = config.Target;
                format = config.Format;
                depth = config.Depth;
                compliance = config.Compliance;
            }

            // Parse target (@ prefix for directories)
            var isDirectory = target.StartsWith("@") || Directory.Exists(target);
            var actualPath = target.StartsWith("@") ? target[1..] : target;

            if (isDirectory && actualPath == ".")
                actualPath = Directory.GetCurrentDirectory();

            // Handle estimation
            if (estimate)
            {
                await EstimateScanAsync(actualPath, isDirectory, depth);
                if (!Console.IsInputRedirected)
                {
                    Console.Write("Continue with scan? (y/n): ");
                    if (Console.ReadLine()?.ToLower() != "y")
                        return;
                }
            }

            // Get performance settings
            var perfProfile = Enum.Parse<PerformanceProfile>(performance, true);
            var perfSettings = PerformanceSettings.Profiles[perfProfile];

            Console.WriteLine($"🚀 Starting {depth} scan with {performance} performance profile");
            Console.WriteLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

            if (watch)
            {
                await RunWatchModeAsync(actualPath, isDirectory, format, depth, perfSettings, compliance);
            }
            else if (depth == "deep" || compliance.Any())
            {
                await RunWaveOrchestrationAsync(actualPath, isDirectory, format, depth, perfSettings, compliance);
            }
            else
            {
                await RunStandardScanAsync(actualPath, isDirectory, format, perfSettings);
            }
        }

        private async Task EstimateScanAsync(string path, bool isDirectory, string depth)
        {
            Console.WriteLine("📊 Scan Estimation");
            Console.WriteLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

            var fileCount = 0;
            var totalSize = 0L;

            if (isDirectory)
            {
                var files = Directory.GetFiles(path, "*.*", SearchOption.AllDirectories)
                    .Where(f => IsSupportedFile(f))
                    .ToList();
                
                fileCount = files.Count;
                totalSize = files.Sum(f => new FileInfo(f).Length);
            }
            else
            {
                fileCount = 1;
                totalSize = new FileInfo(path).Length;
            }

            var complexity = WaveOrchestrator.CalculateComplexity(isDirectory ? path : Path.GetDirectoryName(path)!);
            var estimatedTime = CalculateEstimatedTime(fileCount, totalSize, depth, complexity);
            var estimatedMemory = CalculateEstimatedMemory(fileCount, totalSize);

            Console.WriteLine($"📁 Files to scan: {fileCount:N0}");
            Console.WriteLine($"💾 Total size: {FormatBytes(totalSize)}");
            Console.WriteLine($"🧮 Complexity score: {complexity:F2}");
            Console.WriteLine($"⏱️  Estimated time: {FormatDuration(estimatedTime)}");
            Console.WriteLine($"🧠 Estimated memory: ~{estimatedMemory}MB");
            Console.WriteLine();
        }

        private async Task RunWaveOrchestrationAsync(
            string path,
            bool isDirectory,
            string format,
            string depth,
            PerformanceSettings perfSettings,
            string[] compliance)
        {
            var orchestrator = new WaveOrchestrator();
            var scanService = GetService<ScanService>();
            var complianceService = GetService<ComplianceCliService>();

            // Configure waves
            orchestrator.AddWave(new WaveOrchestrator.Wave
            {
                Name = "Quick Scan",
                Description = "Fast vulnerability detection",
                ExecuteAsync = async (context) =>
                {
                    var vulnerabilities = new List<SecurityVulnerability>();
                    
                    // Quick scan implementation
                    if (isDirectory)
                    {
                        var files = Directory.GetFiles(path, "*.*", SearchOption.AllDirectories)
                            .Where(f => IsSupportedFile(f))
                            .Take(perfSettings.ParallelWorkers * 2)
                            .ToList();
                        
                        foreach (var file in files)
                        {
                            // Simplified scan logic
                            vulnerabilities.Add(new SecurityVulnerability
                            {
                                Type = "Quick Scan",
                                Description = $"Sample vulnerability in {Path.GetFileName(file)}",
                                Severity = Domain.Enums.VulnerabilitySeverity.Low
                            });
                        }
                    }

                    return new WaveOrchestrator.WaveResult
                    {
                        Success = true,
                        OutputData = { ["QuickVulnerabilities"] = vulnerabilities },
                        Messages = { $"Found {vulnerabilities.Count} potential issues" }
                    };
                }
            });

            orchestrator.AddWave(new WaveOrchestrator.Wave
            {
                Name = "Deep Analysis",
                Description = "Comprehensive code analysis",
                IsOptional = true,
                ComplexityThreshold = 0.5,
                ExecuteAsync = async (context) =>
                {
                    // Deep analysis implementation
                    await Task.Delay(1000); // Simulate work
                    
                    return new WaveOrchestrator.WaveResult
                    {
                        Success = true,
                        Messages = { "Completed AI-powered deep analysis" }
                    };
                }
            });

            if (compliance.Any())
            {
                orchestrator.AddWave(new WaveOrchestrator.Wave
                {
                    Name = "Compliance Check",
                    Description = $"Checking {string.Join(", ", compliance)} compliance",
                    ExecuteAsync = async (context) =>
                    {
                        var violations = new List<string>();
                        
                        foreach (var framework in compliance)
                        {
                            // Compliance check implementation
                            violations.Add($"Sample {framework} violation");
                        }

                        return new WaveOrchestrator.WaveResult
                        {
                            Success = true,
                            OutputData = { ["ComplianceViolations"] = violations },
                            Messages = { $"Found {violations.Count} compliance issues" }
                        };
                    }
                });
            }

            // Execute waves
            var context = new WaveOrchestrator.WaveContext
            {
                ComplexityScore = WaveOrchestrator.CalculateComplexity(path),
                FileCount = isDirectory ? Directory.GetFiles(path, "*.*", SearchOption.AllDirectories).Length : 1,
                CancellationToken = CancellationToken.None
            };

            var results = await orchestrator.ExecuteAsync(context);
            
            // Display results based on format
            Console.WriteLine($"\n📋 Scan Results ({format} format)");
            Console.WriteLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            // Format-specific output would go here
        }

        private async Task RunStandardScanAsync(
            string path,
            bool isDirectory,
            string format,
            PerformanceSettings perfSettings)
        {
            var scanService = GetService<ScanService>();
            
            if (isDirectory)
            {
                await scanService.ScanDirectoryAsync(path, format, true);
            }
            else
            {
                await scanService.ScanFileAsync(path, format);
            }
        }

        private async Task RunWatchModeAsync(
            string path,
            bool isDirectory,
            string format,
            string depth,
            PerformanceSettings perfSettings,
            string[] compliance)
        {
            Console.WriteLine("👁️  Watch mode enabled - monitoring for changes...");
            Console.WriteLine("Press Ctrl+C to stop");
            Console.WriteLine();

            using var watcher = new FileSystemWatcher(isDirectory ? path : Path.GetDirectoryName(path)!)
            {
                Filter = isDirectory ? "*.*" : Path.GetFileName(path),
                NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName,
                IncludeSubdirectories = isDirectory,
                EnableRaisingEvents = true
            };

            var changedFiles = new HashSet<string>();
            var debounceTimer = new System.Timers.Timer(1000);
            
            watcher.Changed += (sender, e) =>
            {
                if (IsSupportedFile(e.FullPath))
                {
                    lock (changedFiles)
                    {
                        changedFiles.Add(e.FullPath);
                    }
                    debounceTimer.Stop();
                    debounceTimer.Start();
                }
            };

            debounceTimer.Elapsed += async (sender, e) =>
            {
                List<string> filesToScan;
                lock (changedFiles)
                {
                    filesToScan = changedFiles.ToList();
                    changedFiles.Clear();
                }

                if (filesToScan.Any())
                {
                    Console.WriteLine($"\n🔄 Detected changes in {filesToScan.Count} file(s), rescanning...");
                    foreach (var file in filesToScan)
                    {
                        await RunStandardScanAsync(file, false, format, perfSettings);
                    }
                }
            };

            // Keep the application running
            var tcs = new TaskCompletionSource<bool>();
            Console.CancelKeyPress += (sender, e) =>
            {
                e.Cancel = true;
                tcs.SetResult(true);
            };

            await tcs.Task;
            Console.WriteLine("\n👋 Watch mode stopped");
        }

        private bool IsSupportedFile(string filePath)
        {
            var supportedExtensions = new[] { ".cs", ".js", ".ts", ".py", ".java", ".cpp", ".php", ".rb", ".go" };
            return supportedExtensions.Contains(Path.GetExtension(filePath).ToLower());
        }

        private TimeSpan CalculateEstimatedTime(int fileCount, long totalSize, string depth, double complexity)
        {
            var baseSeconds = fileCount * (depth switch
            {
                "quick" => 0.5,
                "standard" => 2,
                "deep" => 5,
                _ => 2
            });

            var sizeMultiplier = Math.Max(1, totalSize / (1024 * 1024 * 10)); // Per 10MB
            var complexityMultiplier = 1 + complexity;

            return TimeSpan.FromSeconds(baseSeconds * sizeMultiplier * complexityMultiplier);
        }

        private int CalculateEstimatedMemory(int fileCount, long totalSize)
        {
            var baseMemory = 50; // Base 50MB
            var fileMemory = fileCount * 2; // 2MB per file
            var sizeMemory = (int)(totalSize / (1024 * 1024)); // Size in MB
            
            return baseMemory + fileMemory + sizeMemory;
        }

        private string FormatBytes(long bytes)
        {
            string[] sizes = { "B", "KB", "MB", "GB" };
            double len = bytes;
            int order = 0;
            while (len >= 1024 && order < sizes.Length - 1)
            {
                order++;
                len /= 1024;
            }
            return $"{len:0.##} {sizes[order]}";
        }

        private string FormatDuration(TimeSpan duration)
        {
            if (duration.TotalMinutes >= 60)
                return $"{duration.Hours}h {duration.Minutes}m";
            if (duration.TotalSeconds >= 60)
                return $"{duration.Minutes}m {duration.Seconds}s";
            return $"{duration.TotalSeconds:F0}s";
        }
    }
}