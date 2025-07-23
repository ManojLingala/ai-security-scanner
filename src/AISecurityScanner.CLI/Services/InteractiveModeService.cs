using Spectre.Console;
using AISecurityScanner.Domain.ValueObjects;

namespace AISecurityScanner.CLI.Services
{
    public class InteractiveModeService
    {
        public class ScanConfiguration
        {
            public string Target { get; set; } = ".";
            public string Format { get; set; } = "table";
            public string Depth { get; set; } = "standard";
            public string[] Compliance { get; set; } = Array.Empty<string>();
        }

        public async Task<ScanConfiguration?> ConfigureScanAsync(string initialTarget)
        {
            AnsiConsole.Clear();
            
            // Show banner
            var banner = new FigletText("AI Security Scanner")
                .Centered()
                .Color(Color.Cyan1);
            AnsiConsole.Write(banner);
            
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[bold cyan]Interactive Scan Configuration[/]");
            AnsiConsole.WriteLine();

            var config = new ScanConfiguration { Target = initialTarget };

            // Target selection
            var targetChoice = AnsiConsole.Prompt(
                new SelectionPrompt<string>()
                    .Title("What would you like to scan?")
                    .AddChoices(new[]
                    {
                        "Current directory",
                        "Specific file",
                        "Custom directory",
                        "Git repository (uncommitted changes)"
                    }));

            switch (targetChoice)
            {
                case "Current directory":
                    config.Target = ".";
                    break;
                case "Specific file":
                    config.Target = AnsiConsole.Ask<string>("Enter file path:");
                    break;
                case "Custom directory":
                    config.Target = "@" + AnsiConsole.Ask<string>("Enter directory path:");
                    break;
                case "Git repository (uncommitted changes)":
                    config.Target = "@git:unstaged";
                    break;
            }

            // Scan depth
            config.Depth = AnsiConsole.Prompt(
                new SelectionPrompt<string>()
                    .Title("Select scan depth:")
                    .AddChoices(new[]
                    {
                        "quick",
                        "standard",
                        "deep"
                    })
                    .HighlightStyle(new Style(Color.Cyan1)));

            // Compliance frameworks
            var complianceChoices = AnsiConsole.Prompt(
                new MultiSelectionPrompt<string>()
                    .Title("Select compliance frameworks to check (optional):")
                    .NotRequired()
                    .AddChoices(new[]
                    {
                        "PCI-DSS",
                        "HIPAA",
                        "SOX",
                        "GDPR",
                        "OWASP"
                    })
                    .InstructionsText("[grey](Press [blue]<space>[/] to toggle, [green]<enter>[/] to accept)[/]"));
            
            config.Compliance = complianceChoices.ToArray();

            // Output format
            config.Format = AnsiConsole.Prompt(
                new SelectionPrompt<string>()
                    .Title("Select output format:")
                    .AddChoices(new[]
                    {
                        "table",
                        "json",
                        "csv",
                        "sarif",
                        "html"
                    }));

            // Show summary
            AnsiConsole.WriteLine();
            var summaryTable = new Table()
                .Border(TableBorder.Rounded)
                .AddColumn("Setting")
                .AddColumn("Value");

            summaryTable.AddRow("Target", config.Target);
            summaryTable.AddRow("Depth", config.Depth);
            summaryTable.AddRow("Compliance", config.Compliance.Any() ? string.Join(", ", config.Compliance) : "None");
            summaryTable.AddRow("Format", config.Format);

            AnsiConsole.Write(summaryTable);
            AnsiConsole.WriteLine();

            if (!AnsiConsole.Confirm("Proceed with scan?"))
                return null;

            return config;
        }

        public async Task<string?> SelectPresetAsync()
        {
            var presets = new Dictionary<string, string>
            {
                ["Quick Security Check"] = "--depth=quick --format=table",
                ["OWASP Top 10"] = "--depth=standard --compliance=OWASP",
                ["Full Compliance Audit"] = "--depth=deep --compliance=PCI-DSS,HIPAA,SOX,GDPR",
                ["CI/CD Pipeline"] = "--depth=standard --format=sarif --performance=optimization",
                ["Development Mode"] = "--depth=quick --watch --format=table"
            };

            var choice = AnsiConsole.Prompt(
                new SelectionPrompt<string>()
                    .Title("Select a scan preset:")
                    .AddChoices(presets.Keys.Append("Custom"))
                    .HighlightStyle(new Style(Color.Cyan1)));

            return choice == "Custom" ? null : presets[choice];
        }

        public void ShowScanProgress(string scanName, int current, int total)
        {
            AnsiConsole.Progress()
                .AutoRefresh(true)
                .AutoClear(false)
                .HideCompleted(false)
                .Columns(new ProgressColumn[]
                {
                    new TaskDescriptionColumn(),
                    new ProgressBarColumn(),
                    new PercentageColumn(),
                    new RemainingTimeColumn(),
                    new SpinnerColumn(),
                })
                .Start(ctx =>
                {
                    var task = ctx.AddTask($"[cyan]{scanName}[/]", maxValue: total);
                    task.Value = current;
                });
        }

        public void DisplayInteractiveResults(List<SecurityVulnerability> vulnerabilities)
        {
            if (!vulnerabilities.Any())
            {
                AnsiConsole.MarkupLine("[green]✅ No vulnerabilities found![/]");
                return;
            }

            var groupedBySeverity = vulnerabilities
                .GroupBy(v => v.Severity)
                .OrderByDescending(g => g.Key);

            foreach (var group in groupedBySeverity)
            {
                var color = group.Key switch
                {
                    Domain.Enums.VulnerabilitySeverity.Critical => "red",
                    Domain.Enums.VulnerabilitySeverity.High => "orange1",
                    Domain.Enums.VulnerabilitySeverity.Medium => "yellow",
                    Domain.Enums.VulnerabilitySeverity.Low => "blue",
                    _ => "grey"
                };

                AnsiConsole.WriteLine();
                AnsiConsole.MarkupLine($"[bold {color}]{group.Key} Severity ({group.Count()} issues)[/]");

                var table = new Table()
                    .Border(TableBorder.Rounded)
                    .AddColumn("Line")
                    .AddColumn("Type")
                    .AddColumn("Description")
                    .AddColumn("Confidence");

                foreach (var vuln in group.Take(5))
                {
                    table.AddRow(
                        vuln.LineNumber.ToString(),
                        vuln.Type,
                        Markup.Escape(vuln.Description.Length > 50 
                            ? vuln.Description.Substring(0, 47) + "..." 
                            : vuln.Description),
                        $"{vuln.Confidence:F1}%"
                    );
                }

                AnsiConsole.Write(table);

                if (group.Count() > 5)
                {
                    AnsiConsole.MarkupLine($"[grey]... and {group.Count() - 5} more[/]");
                }
            }

            AnsiConsole.WriteLine();
            if (AnsiConsole.Confirm("Would you like to see detailed recommendations?"))
            {
                ShowDetailedRecommendations(vulnerabilities);
            }
        }

        private void ShowDetailedRecommendations(List<SecurityVulnerability> vulnerabilities)
        {
            var uniqueTypes = vulnerabilities.Select(v => v.Type).Distinct();
            
            foreach (var type in uniqueTypes)
            {
                var vulnsOfType = vulnerabilities.Where(v => v.Type == type).ToList();
                
                AnsiConsole.WriteLine();
                AnsiConsole.MarkupLine($"[bold cyan]{type}[/]");
                AnsiConsole.MarkupLine($"[grey]Found in {vulnsOfType.Count} location(s)[/]");
                
                var recommendation = vulnsOfType.First().Recommendation;
                if (!string.IsNullOrEmpty(recommendation))
                {
                    var panel = new Panel(Markup.Escape(recommendation))
                        .Header("Recommendation")
                        .BorderColor(Color.Cyan1)
                        .Padding(1, 1);
                    
                    AnsiConsole.Write(panel);
                }
            }
        }
    }
}