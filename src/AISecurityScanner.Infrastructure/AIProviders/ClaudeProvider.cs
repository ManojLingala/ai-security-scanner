using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using AISecurityScanner.Application.DTOs;
using AISecurityScanner.Application.Interfaces;
using AISecurityScanner.Domain.Enums;
using AISecurityScanner.Domain.ValueObjects;

namespace AISecurityScanner.Infrastructure.AIProviders
{
    public class ClaudeProvider : IAIProvider
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger<ClaudeProvider> _logger;
        private readonly ClaudeConfiguration _config;

        public string Name => "Anthropic Claude";
        public decimal CostPerRequest => _config.CostPerRequest;
        public TimeSpan TypicalResponseTime => TimeSpan.FromSeconds(3);
        public bool SupportsCodeAnalysis => true;
        public bool SupportsPackageValidation => true;

        public ClaudeProvider(HttpClient httpClient, ILogger<ClaudeProvider> logger, IOptions<ClaudeConfiguration> config)
        {
            _httpClient = httpClient;
            _logger = logger;
            _config = config.Value;
            
            _httpClient.DefaultRequestHeaders.Add("x-api-key", _config.ApiKey);
            _httpClient.DefaultRequestHeaders.Add("anthropic-version", "2023-06-01");
            _httpClient.DefaultRequestHeaders.Add("User-Agent", "AISecurityScanner/1.0");
        }

        public async Task<SecurityAnalysisResult> AnalyzeCodeAsync(string code, AIAnalysisContext context, CancellationToken cancellationToken = default)
        {
            var startTime = DateTime.UtcNow;
            
            try
            {
                var prompt = BuildSecurityAnalysisPrompt(code, context);
                var response = await SendMessageAsync(prompt, cancellationToken);
                
                var vulnerabilityDtos = ParseVulnerabilities(response, context);
                var vulnerabilities = ConvertToSecurityVulnerabilities(vulnerabilityDtos);
                var responseTime = DateTime.UtcNow - startTime;

                return new SecurityAnalysisResult
                {
                    IsSuccess = true,
                    DetectedVulnerabilities = vulnerabilities,
                    ConfidenceScore = CalculateConfidence(vulnerabilities),
                    ResponseTime = responseTime,
                    TokensUsed = EstimateTokenUsage(prompt + response),
                    Cost = CostPerRequest,
                    ProviderName = Name
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error analyzing code with Claude");
                return new SecurityAnalysisResult
                {
                    IsSuccess = false,
                    ErrorMessage = ex.Message,
                    ResponseTime = DateTime.UtcNow - startTime,
                    ProviderName = Name
                };
            }
        }

        public async Task<PackageValidationResult> ValidatePackagesAsync(List<string> packages, string ecosystem, CancellationToken cancellationToken = default)
        {
            var startTime = DateTime.UtcNow;
            
            try
            {
                var prompt = BuildPackageValidationPrompt(packages, ecosystem);
                var response = await SendMessageAsync(prompt, cancellationToken);
                
                var validatedPackages = ParsePackageValidation(response, packages, ecosystem);
                var vulnerablePackages = ConvertToPackageVulnerabilityInfo(validatedPackages, packages, ecosystem);
                
                return new PackageValidationResult
                {
                    IsSuccess = true,
                    VulnerablePackages = vulnerablePackages,
                    TotalPackagesScanned = packages.Count,
                    VulnerablePackageCount = vulnerablePackages.Count(p => p.HasVulnerabilities),
                    Cost = CostPerRequest * 0.5m,
                    ProviderName = Name
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating packages with Claude");
                return new PackageValidationResult
                {
                    IsSuccess = false,
                    ErrorMessage = ex.Message,
                    ProviderName = Name
                };
            }
        }

        public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                var healthStatus = await GetHealthStatusAsync(cancellationToken);
                return healthStatus.IsHealthy;
            }
            catch
            {
                return false;
            }
        }

        public async Task<ProviderHealthStatus> GetHealthStatusAsync(CancellationToken cancellationToken = default)
        {
            var startTime = DateTime.UtcNow;
            
            try
            {
                var testPrompt = "Please respond with 'HEALTHY' to confirm system status.";
                var response = await SendMessageAsync(testPrompt, cancellationToken);
                
                var responseTime = DateTime.UtcNow - startTime;
                var isHealthy = !string.IsNullOrEmpty(response) && response.Contains("HEALTHY", StringComparison.OrdinalIgnoreCase);

                return new ProviderHealthStatus
                {
                    IsHealthy = isHealthy,
                    ResponseTime = responseTime,
                    CheckedAt = DateTime.UtcNow,
                    SuccessRate = isHealthy ? 1.0m : 0.0m
                };
            }
            catch (Exception ex)
            {
                return new ProviderHealthStatus
                {
                    IsHealthy = false,
                    ErrorMessage = ex.Message,
                    ResponseTime = DateTime.UtcNow - startTime,
                    CheckedAt = DateTime.UtcNow,
                    SuccessRate = 0.0m
                };
            }
        }

        private async Task<string> SendMessageAsync(string prompt, CancellationToken cancellationToken)
        {
            var requestBody = new
            {
                model = _config.Model,
                max_tokens = _config.MaxTokens,
                messages = new[]
                {
                    new { role = "user", content = prompt }
                },
                system = "You are a cybersecurity expert specializing in code vulnerability analysis. Provide detailed, accurate security assessments in JSON format."
            };

            var json = JsonSerializer.Serialize(requestBody);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            var response = await _httpClient.PostAsync(_config.ApiEndpoint, content, cancellationToken);
            response.EnsureSuccessStatusCode();

            var responseJson = await response.Content.ReadAsStringAsync(cancellationToken);
            var responseObj = JsonSerializer.Deserialize<JsonElement>(responseJson);

            if (responseObj.TryGetProperty("content", out var contentArray) && contentArray.GetArrayLength() > 0)
            {
                var firstContent = contentArray[0];
                if (firstContent.TryGetProperty("text", out var text))
                {
                    return text.GetString() ?? "";
                }
            }

            throw new InvalidOperationException("Invalid response format from Claude");
        }

        private string BuildSecurityAnalysisPrompt(string code, AIAnalysisContext context)
        {
            return $@"
I need you to perform a comprehensive security analysis of the following {context.Language} code.

Focus on identifying:
1. SQL Injection vulnerabilities
2. Cross-Site Scripting (XSS) issues
3. Command Injection vulnerabilities
4. Path Traversal attacks
5. Insecure cryptographic implementations
6. Hard-coded credentials or API keys
7. Authentication and authorization flaws
8. Input validation issues
9. Buffer overflow possibilities
10. Race condition vulnerabilities
11. Insecure random number generation
12. Improper error handling that leaks information

Code to analyze:
```{context.Language}
{code}
```

Please respond with a JSON object in this exact format:
{{
  ""vulnerabilities"": [
    {{
      ""type"": ""specific_vulnerability_type"",
      ""severity"": ""Critical|High|Medium|Low|Info"",
      ""line_number"": actual_line_number,
      ""description"": ""detailed explanation of the vulnerability"",
      ""recommendation"": ""specific steps to remediate"",
      ""confidence"": confidence_score_0_to_1,
      ""cwe"": ""CWE-XXX"",
      ""owasp_category"": ""OWASP Top 10 classification""
    }}
  ],
  ""is_ai_generated"": true_or_false,
  ""ai_confidence"": confidence_score_0_to_1,
  ""analysis_notes"": ""additional insights about the code quality and security posture""
}}

Be thorough but precise. Only report actual vulnerabilities, not potential improvements.";
        }

        private string BuildPackageValidationPrompt(List<string> packages, string ecosystem)
        {
            var packageList = string.Join("\n- ", packages);
            
            return $@"
I need you to validate whether the following packages exist in the official {ecosystem} package registry:

- {packageList}

For each package, determine:
1. Does it exist in the official {ecosystem} package registry?
2. Is it a legitimate, real package?
3. Could it be a hallucinated or fabricated package name?

Consider common package naming patterns for {ecosystem} and check against your knowledge of real packages.

Respond with a JSON object in this format:
{{
  ""packages"": [
    {{
      ""name"": ""exact_package_name"",
      ""exists"": true_or_false,
      ""is_hallucinated"": true_or_false,
      ""registry_url"": ""url_if_known"",
      ""confidence"": confidence_score_0_to_1,
      ""notes"": ""any additional information""
    }}
  ],
  ""ecosystem"": ""{ecosystem}"",
  ""validation_notes"": ""overall assessment""
}}";
        }

        private List<VulnerabilityDto> ParseVulnerabilities(string response, AIAnalysisContext context)
        {
            try
            {
                // Claude sometimes wraps JSON in markdown code blocks
                var cleanedResponse = response.Trim();
                if (cleanedResponse.StartsWith("```json"))
                {
                    cleanedResponse = cleanedResponse[7..];
                }
                if (cleanedResponse.EndsWith("```"))
                {
                    cleanedResponse = cleanedResponse[..^3];
                }

                var jsonDoc = JsonSerializer.Deserialize<JsonElement>(cleanedResponse);
                var vulnerabilities = new List<VulnerabilityDto>();

                if (jsonDoc.TryGetProperty("vulnerabilities", out var vulnArray))
                {
                    foreach (var vuln in vulnArray.EnumerateArray())
                    {
                        vulnerabilities.Add(new VulnerabilityDto
                        {
                            Id = Guid.NewGuid(),
                            Type = vuln.GetProperty("type").GetString() ?? "Unknown",
                            Severity = ParseSeverity(vuln.GetProperty("severity").GetString()),
                            LineNumber = vuln.TryGetProperty("line_number", out var lineNum) ? lineNum.GetInt32() : 0,
                            Description = vuln.GetProperty("description").GetString() ?? "",
                            Recommendation = vuln.TryGetProperty("recommendation", out var rec) ? rec.GetString() : null,
                            Confidence = vuln.TryGetProperty("confidence", out var conf) ? conf.GetDecimal() : 0.8m,
                            CWE = vuln.TryGetProperty("cwe", out var cwe) ? cwe.GetString() : null,
                            OWASPCategory = vuln.TryGetProperty("owasp_category", out var owasp) ? owasp.GetString() : null,
                            IsAIGenerated = jsonDoc.TryGetProperty("is_ai_generated", out var aiGen) && aiGen.GetBoolean(),
                            DetectionEngine = Name,
                            Status = VulnerabilityStatus.Open,
                            CreatedAt = DateTime.UtcNow
                        });
                    }
                }

                return vulnerabilities;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to parse Claude vulnerability response: {Response}", response);
                return new List<VulnerabilityDto>();
            }
        }

        private List<PackageInfo> ParsePackageValidation(string response, List<string> originalPackages, string ecosystem)
        {
            try
            {
                var cleanedResponse = response.Trim();
                if (cleanedResponse.StartsWith("```json"))
                {
                    cleanedResponse = cleanedResponse[7..];
                }
                if (cleanedResponse.EndsWith("```"))
                {
                    cleanedResponse = cleanedResponse[..^3];
                }

                var jsonDoc = JsonSerializer.Deserialize<JsonElement>(cleanedResponse);
                var packages = new List<PackageInfo>();

                if (jsonDoc.TryGetProperty("packages", out var packageArray))
                {
                    foreach (var pkg in packageArray.EnumerateArray())
                    {
                        packages.Add(new PackageInfo
                        {
                            Name = pkg.GetProperty("name").GetString() ?? "",
                            Ecosystem = ecosystem,
                            Exists = pkg.TryGetProperty("exists", out var exists) && exists.GetBoolean(),
                            IsHallucinated = pkg.TryGetProperty("is_hallucinated", out var halluc) && halluc.GetBoolean(),
                            RegistryUrl = pkg.TryGetProperty("registry_url", out var url) ? url.GetString() : null,
                            LastChecked = DateTime.UtcNow
                        });
                    }
                }

                return packages;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to parse Claude package validation response");
                return originalPackages.Select(p => new PackageInfo
                {
                    Name = p,
                    Ecosystem = ecosystem,
                    Exists = false,
                    IsHallucinated = true,
                    LastChecked = DateTime.UtcNow
                }).ToList();
            }
        }

        private VulnerabilitySeverity ParseSeverity(string? severity)
        {
            return severity?.ToLowerInvariant() switch
            {
                "critical" => VulnerabilitySeverity.Critical,
                "high" => VulnerabilitySeverity.High,
                "medium" => VulnerabilitySeverity.Medium,
                "low" => VulnerabilitySeverity.Low,
                "info" => VulnerabilitySeverity.Info,
                _ => VulnerabilitySeverity.Medium
            };
        }

        private List<SecurityVulnerability> ConvertToSecurityVulnerabilities(List<VulnerabilityDto> dtos)
        {
            return dtos.Select(dto => new SecurityVulnerability
            {
                Id = dto.Id.ToString(),
                Type = dto.Type,
                Severity = dto.Severity,
                Confidence = dto.Confidence,
                Description = dto.Description,
                LineNumber = dto.LineNumber,
                Code = dto.CodeSnippet ?? "",
                CweId = dto.CWE,
                Recommendation = dto.Recommendation,
                MLDetected = dto.IsAIGenerated,
                DetectedAt = dto.CreatedAt
            }).ToList();
        }

        private List<PackageVulnerabilityInfo> ConvertToPackageVulnerabilityInfo(List<PackageInfo> packages, List<string> originalPackages, string ecosystem)
        {
            return originalPackages.Select(packageName =>
            {
                var packageInfo = packages.FirstOrDefault(p => p.Name.Equals(packageName, StringComparison.OrdinalIgnoreCase));
                var hasVulnerabilities = packageInfo?.Exists == true && !packageInfo.IsHallucinated;
                
                return new PackageVulnerabilityInfo
                {
                    PackageName = packageName,
                    Ecosystem = ecosystem,
                    HasVulnerabilities = hasVulnerabilities,
                    Vulnerabilities = hasVulnerabilities ? new List<PackageVulnerability>
                    {
                        new PackageVulnerability
                        {
                            Id = Guid.NewGuid().ToString(),
                            Description = "Package validation flagged potential security concerns",
                            Severity = VulnerabilitySeverity.Medium,
                            Confidence = 0.7m
                        }
                    } : new List<PackageVulnerability>()
                };
            }).ToList();
        }

        private decimal CalculateConfidence(List<SecurityVulnerability> vulnerabilities)
        {
            if (!vulnerabilities.Any()) return 1.0m;
            return vulnerabilities.Average(v => v.Confidence);
        }

        private int EstimateTokenUsage(string text)
        {
            // Claude token estimation
            return text.Length / 3;
        }
    }

    public class ClaudeConfiguration
    {
        public string ApiKey { get; set; } = string.Empty;
        public string ApiEndpoint { get; set; } = "https://api.anthropic.com/v1/messages";
        public string Model { get; set; } = "claude-3-sonnet-20240229";
        public int MaxTokens { get; set; } = 4096;
        public decimal CostPerRequest { get; set; } = 0.015m;
    }
}