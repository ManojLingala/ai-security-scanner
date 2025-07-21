using AISecurityScanner.Application.Interfaces;
using AISecurityScanner.Infrastructure.AIProviders;
using AISecurityScanner.Domain.ValueObjects;
using AISecurityScanner.Domain.Enums;
using ConsoleTables;
using System.Text.Json;

namespace AISecurityScanner.CLI.Services
{
    public class ScanService
    {
        private readonly IAIProvider _aiProvider;
        private readonly IComplianceService _complianceService;
        private readonly ConfigService _configService;

        public ScanService(
            IAIProvider aiProvider,
            IComplianceService complianceService,
            ConfigService configService)
        {
            _aiProvider = aiProvider;
            _complianceService = complianceService;
            _configService = configService;
        }

        public async Task<bool> ScanFileAsync(string filePath, string outputFormat = "table")
        {
            if (!File.Exists(filePath))
            {
                Console.WriteLine($"❌ File not found: {filePath}");
                return false;
            }

            Console.WriteLine($"🔍 Scanning file: {filePath}");
            Console.WriteLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            
            try
            {
                var fileContent = await File.ReadAllTextAsync(filePath);
                var fileExtension = Path.GetExtension(filePath);
                var language = DetectLanguage(fileExtension);

                var context = new AIAnalysisContext
                {
                    Language = language,
                    OrganizationId = Guid.NewGuid(), // CLI mode uses temp org
                    IncludeAIDetection = true,
                    IncludePackageValidation = false
                };

                var result = await _aiProvider.AnalyzeCodeAsync(fileContent, context);
                
                Console.WriteLine($"✅ Scan completed in {result.ResponseTime.TotalSeconds:F2}s");
                Console.WriteLine();

                if (result.DetectedVulnerabilities.Any())
                {
                    await DisplayVulnerabilities(result.DetectedVulnerabilities, outputFormat);
                }
                else
                {
                    Console.WriteLine("🎉 No security vulnerabilities detected!");
                }

                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Error scanning file: {ex.Message}");
                return false;
            }
        }

        public async Task<bool> ScanDirectoryAsync(string directoryPath, string outputFormat = "table", bool recursive = true)
        {
            if (!Directory.Exists(directoryPath))
            {
                Console.WriteLine($"❌ Directory not found: {directoryPath}");
                return false;
            }

            Console.WriteLine($"🔍 Scanning directory: {directoryPath}");
            Console.WriteLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

            var searchOption = recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
            var supportedExtensions = new[] { ".cs", ".js", ".ts", ".py", ".java", ".cpp", ".php" };
            
            var files = Directory.GetFiles(directoryPath, "*.*", searchOption)
                .Where(f => supportedExtensions.Contains(Path.GetExtension(f).ToLower()))
                .ToList();

            if (!files.Any())
            {
                Console.WriteLine("❓ No supported source files found in directory.");
                Console.WriteLine($"Supported extensions: {string.Join(", ", supportedExtensions)}");
                return false;
            }

            Console.WriteLine($"📁 Found {files.Count} files to scan");
            Console.WriteLine();

            var allVulnerabilities = new List<SecurityVulnerability>();
            var scannedFiles = 0;

            foreach (var file in files)
            {
                try
                {
                    var relativePath = Path.GetRelativePath(directoryPath, file);
                    Console.Write($"  📄 {relativePath}... ");

                    var fileContent = await File.ReadAllTextAsync(file);
                    var fileExtension = Path.GetExtension(file);
                    var language = DetectLanguage(fileExtension);

                    var context = new AIAnalysisContext
                    {
                        Language = language,
                        OrganizationId = Guid.NewGuid(),
                        IncludeAIDetection = true,
                        IncludePackageValidation = false
                    };

                    var result = await _aiProvider.AnalyzeCodeAsync(fileContent, context);
                    
                    // Add file path to vulnerabilities for tracking
                    foreach (var vuln in result.DetectedVulnerabilities)
                    {
                        vuln.Metadata["FilePath"] = relativePath;
                    }
                    
                    allVulnerabilities.AddRange(result.DetectedVulnerabilities);
                    scannedFiles++;

                    Console.WriteLine($"✅ {result.DetectedVulnerabilities.Count} issues");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"❌ Error: {ex.Message}");
                }
            }

            Console.WriteLine();
            Console.WriteLine($"📊 Scan Summary: {scannedFiles}/{files.Count} files scanned");
            
            if (allVulnerabilities.Any())
            {
                Console.WriteLine($"🚨 Found {allVulnerabilities.Count} total vulnerabilities");
                Console.WriteLine();
                await DisplayVulnerabilities(allVulnerabilities, outputFormat, true);
            }
            else
            {
                Console.WriteLine("🎉 No security vulnerabilities detected!");
            }

            return true;
        }

        public async Task<bool> ScanProjectAsync(string outputFormat = "table")
        {
            var currentDir = Directory.GetCurrentDirectory();
            Console.WriteLine($"🔍 Scanning current project: {currentDir}");
            
            // Check for common project files
            var projectFiles = Directory.GetFiles(currentDir, "*.*", SearchOption.TopDirectoryOnly)
                .Where(f => 
                {
                    var fileName = Path.GetFileName(f).ToLower();
                    return fileName.EndsWith(".csproj") || 
                           fileName.EndsWith(".sln") ||
                           fileName == "package.json" ||
                           fileName == "pom.xml" ||
                           fileName == "requirements.txt" ||
                           fileName == "package-lock.json";
                }).ToList();

            if (projectFiles.Any())
            {
                Console.WriteLine($"📋 Detected project files: {string.Join(", ", projectFiles.Select(Path.GetFileName))}");
            }
            
            return await ScanDirectoryAsync(currentDir, outputFormat, recursive: true);
        }

        private async Task DisplayVulnerabilities(List<SecurityVulnerability> vulnerabilities, string outputFormat, bool includeFilePath = false)
        {
            switch (outputFormat.ToLower())
            {
                case "json":
                    await DisplayAsJsonAsync(vulnerabilities);
                    break;
                case "csv":
                    await DisplayAsCsvAsync(vulnerabilities, includeFilePath);
                    break;
                case "table":
                default:
                    DisplayAsTable(vulnerabilities, includeFilePath);
                    break;
            }
        }

        private void DisplayAsTable(List<SecurityVulnerability> vulnerabilities, bool includeFilePath)
        {
            var grouped = vulnerabilities.GroupBy(v => v.Severity).OrderByDescending(g => (int)g.Key);
            
            foreach (var group in grouped)
            {
                Console.WriteLine($"🚨 {group.Key} Severity ({group.Count()} issues):");
                Console.WriteLine();

                var table = new ConsoleTable();
                
                if (includeFilePath)
                {
                    table.AddColumn(new[] { "File", "Line", "Type", "Description", "Confidence" });
                    
                    foreach (var vuln in group.Take(20)) // Limit to prevent overwhelming output
                    {
                        var filePath = vuln.Metadata.TryGetValue("FilePath", out var fp) ? fp?.ToString() : "Unknown";
                        table.AddRow(
                            TruncateString(filePath ?? "", 30),
                            vuln.LineNumber,
                            TruncateString(vuln.Type, 15),
                            TruncateString(vuln.Description, 40),
                            $"{vuln.Confidence:F1}"
                        );
                    }
                }
                else
                {
                    table.AddColumn(new[] { "Line", "Type", "Description", "Confidence", "CWE" });
                    
                    foreach (var vuln in group)
                    {
                        table.AddRow(
                            vuln.LineNumber,
                            TruncateString(vuln.Type, 20),
                            TruncateString(vuln.Description, 50),
                            $"{vuln.Confidence:F1}",
                            vuln.CweId ?? "N/A"
                        );
                    }
                }

                table.Write();
                Console.WriteLine();
                
                if (includeFilePath && group.Count() > 20)
                {
                    Console.WriteLine($"... and {group.Count() - 20} more {group.Key.ToString().ToLower()} severity issues");
                    Console.WriteLine();
                }
            }
        }

        private async Task DisplayAsJsonAsync(List<SecurityVulnerability> vulnerabilities)
        {
            var json = JsonSerializer.Serialize(vulnerabilities, new JsonSerializerOptions 
            { 
                WriteIndented = true 
            });
            
            Console.WriteLine(json);
        }

        private async Task DisplayAsCsvAsync(List<SecurityVulnerability> vulnerabilities, bool includeFilePath)
        {
            Console.WriteLine(includeFilePath 
                ? "File,Line,Type,Severity,Description,Confidence,CWE,Recommendation"
                : "Line,Type,Severity,Description,Confidence,CWE,Recommendation");
            
            foreach (var vuln in vulnerabilities)
            {
                var filePath = includeFilePath && vuln.Metadata.TryGetValue("FilePath", out var fp) ? fp?.ToString() : "";
                var csvLine = includeFilePath
                    ? $"\"{filePath}\",{vuln.LineNumber},\"{vuln.Type}\",\"{vuln.Severity}\",\"{EscapeCsv(vuln.Description)}\",{vuln.Confidence:F1},\"{vuln.CweId}\",\"{EscapeCsv(vuln.Recommendation)}\""
                    : $"{vuln.LineNumber},\"{vuln.Type}\",\"{vuln.Severity}\",\"{EscapeCsv(vuln.Description)}\",{vuln.Confidence:F1},\"{vuln.CweId}\",\"{EscapeCsv(vuln.Recommendation)}\"";
                
                Console.WriteLine(csvLine);
            }
        }

        private string DetectLanguage(string fileExtension)
        {
            return fileExtension.ToLower() switch
            {
                ".cs" => "C#",
                ".js" => "JavaScript", 
                ".ts" => "TypeScript",
                ".py" => "Python",
                ".java" => "Java",
                ".cpp" or ".cxx" or ".cc" => "C++",
                ".c" => "C",
                ".php" => "PHP",
                ".rb" => "Ruby",
                ".go" => "Go",
                _ => "Unknown"
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
}