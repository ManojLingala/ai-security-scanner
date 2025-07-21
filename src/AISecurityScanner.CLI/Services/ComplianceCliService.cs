using AISecurityScanner.Application.Interfaces;
using AISecurityScanner.Domain.Enums;
using AISecurityScanner.Domain.Entities;
using AISecurityScanner.Infrastructure.Compliance;
using ConsoleTables;
using System.Text.Json;

namespace AISecurityScanner.CLI.Services
{
    public class ComplianceCliService
    {
        private readonly ConfigService _configService;

        public ComplianceCliService(ConfigService configService)
        {
            _configService = configService;
        }

        public void ListFrameworks()
        {
            Console.WriteLine("🛡️ Supported Compliance Frameworks");
            Console.WriteLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            Console.WriteLine();

            var frameworks = new[]
            {
                new { Code = "pci-dss", Name = "PCI DSS v4.0", Description = "Payment Card Industry Data Security Standard", Rules = 22 },
                new { Code = "hipaa", Name = "HIPAA Security Rule", Description = "Health Insurance Portability and Accountability Act", Rules = 18 },
                new { Code = "sox", Name = "SOX", Description = "Sarbanes-Oxley Act Financial Controls", Rules = 15 },
                new { Code = "gdpr", Name = "GDPR", Description = "General Data Protection Regulation", Rules = 21 }
            };

            var table = new ConsoleTable("Code", "Framework", "Description", "Rules");
            
            foreach (var framework in frameworks)
            {
                table.AddRow(framework.Code, framework.Name, framework.Description, framework.Rules);
            }

            table.Write();
            Console.WriteLine();
            Console.WriteLine("💡 Usage: aiscan compliance scan --framework <code>");
        }

        public async Task<bool> ScanComplianceAsync(string framework, string directoryPath, string outputFormat = "table")
        {
            if (!Directory.Exists(directoryPath))
            {
                Console.WriteLine($"❌ Directory not found: {directoryPath}");
                return false;
            }

            var frameworkType = ParseFramework(framework);
            if (frameworkType == null)
            {
                Console.WriteLine($"❌ Unsupported framework: {framework}");
                Console.WriteLine("Run 'aiscan compliance list' to see supported frameworks.");
                return false;
            }

            Console.WriteLine($"🛡️ Running {GetFrameworkDisplayName(frameworkType.Value)} compliance scan");
            Console.WriteLine($"📁 Directory: {directoryPath}");
            Console.WriteLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            Console.WriteLine();

            try
            {
                var files = GetComplianceFiles(directoryPath);
                if (!files.Any())
                {
                    Console.WriteLine("❓ No supported files found for compliance scanning.");
                    Console.WriteLine("Supported file types: .cs, .js, .ts, .py, .java, .config, .json, .xml, .sql");
                    return false;
                }

                Console.WriteLine($"📄 Found {files.Count} files to scan");

                var scanContext = new Application.Interfaces.ComplianceScanContext
                {
                    ScanId = Guid.NewGuid(),
                    OrganizationId = Guid.NewGuid(), // CLI mode uses temp org
                    Files = files
                };

                var provider = CreateComplianceProvider(frameworkType.Value);
                var result = await provider.ScanAsync(scanContext);

                Console.WriteLine($"✅ Compliance scan completed in {result.ScanDuration.TotalSeconds:F2}s");
                Console.WriteLine($"📋 {result.RulesEvaluated} rules evaluated");
                Console.WriteLine();

                await DisplayComplianceResults(result, outputFormat);
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Error during compliance scan: {ex.Message}");
                return false;
            }
        }

        private List<Application.Interfaces.ComplianceFile> GetComplianceFiles(string directoryPath)
        {
            var supportedExtensions = new[] { ".cs", ".js", ".ts", ".py", ".java", ".config", ".json", ".xml", ".sql", ".txt", ".log" };
            
            var files = Directory.GetFiles(directoryPath, "*.*", SearchOption.AllDirectories)
                .Where(f => supportedExtensions.Contains(Path.GetExtension(f).ToLower()))
                .Select(f => new Application.Interfaces.ComplianceFile 
                { 
                    Path = f, 
                    Extension = Path.GetExtension(f).ToLower() 
                })
                .ToList();

            return files;
        }

        private IComplianceProvider CreateComplianceProvider(ComplianceFrameworkType framework)
        {
            return framework switch
            {
                ComplianceFrameworkType.PCI_DSS => new PCIDSSComplianceProvider(null!),
                ComplianceFrameworkType.HIPAA => new HIPAAComplianceProvider(null!),
                ComplianceFrameworkType.SOX => new SOXComplianceProvider(null!),
                ComplianceFrameworkType.GDPR => new GDPRComplianceProvider(null!),
                _ => throw new NotSupportedException($"Framework {framework} not supported")
            };
        }

        private async Task DisplayComplianceResults(ComplianceScanResult result, string outputFormat)
        {
            switch (outputFormat.ToLower())
            {
                case "json":
                    await DisplayComplianceAsJsonAsync(result);
                    break;
                case "csv":
                    await DisplayComplianceAsCsvAsync(result);
                    break;
                case "table":
                default:
                    DisplayComplianceAsTable(result);
                    break;
            }
        }

        private void DisplayComplianceAsTable(ComplianceScanResult result)
        {
            // Display overall score
            Console.WriteLine($"🎯 Overall Compliance Score: {result.OverallScore.OverallScore:F1}%");
            Console.WriteLine();

            // Display violations by severity
            if (result.Violations.Any())
            {
                var violationsBySeverity = result.Violations.GroupBy(v => v.Severity)
                    .OrderByDescending(g => (int)g.Key);

                Console.WriteLine("🚨 Compliance Violations:");
                Console.WriteLine();

                foreach (var group in violationsBySeverity)
                {
                    Console.WriteLine($"{GetSeverityIcon(group.Key)} {group.Key} ({group.Count()} violations):");
                    
                    var table = new ConsoleTable("Rule ID", "Title", "File", "Line", "Guidance");
                    
                    foreach (var violation in group.Take(10)) // Limit display
                    {
                        table.AddRow(
                            violation.RuleId,
                            TruncateString(violation.Title, 25),
                            TruncateString(Path.GetFileName(violation.FilePath), 20),
                            violation.LineNumber,
                            TruncateString(violation.RemediationGuidance, 30)
                        );
                    }

                    table.Write();
                    
                    if (group.Count() > 10)
                    {
                        Console.WriteLine($"... and {group.Count() - 10} more {group.Key.ToString().ToLower()} violations");
                    }
                    
                    Console.WriteLine();
                }
            }
            else
            {
                Console.WriteLine("🎉 No compliance violations found!");
                Console.WriteLine();
            }

            // Display category scores
            if (result.OverallScore.CategoryScores.Any())
            {
                Console.WriteLine("📊 Category Scores:");
                var categoryTable = new ConsoleTable("Category", "Score", "Status");
                
                foreach (var category in result.OverallScore.CategoryScores)
                {
                    var status = category.Value >= 90 ? "✅ Pass" : category.Value >= 70 ? "⚠️ Warning" : "❌ Fail";
                    categoryTable.AddRow(
                        category.Key.Replace("_", " ").ToTitleCase(),
                        $"{category.Value:F1}%",
                        status
                    );
                }
                
                categoryTable.Write();
                Console.WriteLine();
            }

            // Display recommendations
            if (result.Recommendations.HighPriorityActions.Any())
            {
                Console.WriteLine("🔧 High Priority Actions:");
                foreach (var action in result.Recommendations.HighPriorityActions)
                {
                    Console.WriteLine($"  • {action}");
                }
                Console.WriteLine();
            }

            // Display summary
            Console.WriteLine("📋 Executive Summary:");
            Console.WriteLine($"   {result.Recommendations.Summary}");
        }

        private async Task DisplayComplianceAsJsonAsync(ComplianceScanResult result)
        {
            var json = JsonSerializer.Serialize(result, new JsonSerializerOptions 
            { 
                WriteIndented = true 
            });
            
            Console.WriteLine(json);
        }

        private async Task DisplayComplianceAsCsvAsync(ComplianceScanResult result)
        {
            Console.WriteLine("RuleId,Title,Severity,File,Line,Description,Guidance,References");
            
            foreach (var violation in result.Violations)
            {
                var references = string.Join(";", violation.References);
                Console.WriteLine($"\"{violation.RuleId}\",\"{violation.Title}\",\"{violation.Severity}\",\"{Path.GetFileName(violation.FilePath)}\",{violation.LineNumber},\"{EscapeCsv(violation.Description)}\",\"{EscapeCsv(violation.RemediationGuidance)}\",\"{references}\"");
            }
        }

        private ComplianceFrameworkType? ParseFramework(string framework)
        {
            return framework.ToLower() switch
            {
                "pci-dss" or "pci" or "pcidss" => ComplianceFrameworkType.PCI_DSS,
                "hipaa" => ComplianceFrameworkType.HIPAA,
                "sox" => ComplianceFrameworkType.SOX,
                "gdpr" => ComplianceFrameworkType.GDPR,
                _ => null
            };
        }

        private string GetFrameworkDisplayName(ComplianceFrameworkType framework)
        {
            return framework switch
            {
                ComplianceFrameworkType.PCI_DSS => "PCI DSS v4.0",
                ComplianceFrameworkType.HIPAA => "HIPAA Security Rule",
                ComplianceFrameworkType.SOX => "SOX",
                ComplianceFrameworkType.GDPR => "GDPR",
                _ => framework.ToString()
            };
        }

        private string GetSeverityIcon(ComplianceSeverity severity)
        {
            return severity switch
            {
                ComplianceSeverity.Critical => "🔴",
                ComplianceSeverity.High => "🟠",
                ComplianceSeverity.Medium => "🟡",
                ComplianceSeverity.Low => "🔵",
                ComplianceSeverity.Info => "ℹ️",
                _ => "❓"
            };
        }

        private string TruncateString(string input, int maxLength)
        {
            if (string.IsNullOrEmpty(input))
                return "";
                
            return input.Length <= maxLength ? input : input.Substring(0, maxLength - 3) + "...";
        }

        private string EscapeCsv(string? input)
        {
            if (string.IsNullOrEmpty(input))
                return "";
                
            return input.Replace("\"", "\"\"").Replace("\n", " ").Replace("\r", "");
        }
    }

    public static class StringExtensions
    {
        public static string ToTitleCase(this string input)
        {
            if (string.IsNullOrEmpty(input))
                return input;

            return string.Join(" ", input.Split(' ')
                .Select(word => char.ToUpper(word[0]) + word.Substring(1).ToLower()));
        }
    }

}