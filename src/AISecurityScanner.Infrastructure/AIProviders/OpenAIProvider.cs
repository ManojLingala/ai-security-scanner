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
    public class OpenAIProvider : IAIProvider
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger<OpenAIProvider> _logger;
        private readonly OpenAIConfiguration _config;

        public string Name => "OpenAI GPT-4";
        public decimal CostPerRequest => _config.CostPerRequest;
        public TimeSpan TypicalResponseTime => TimeSpan.FromSeconds(5);
        public bool SupportsCodeAnalysis => true;
        public bool SupportsPackageValidation => true;

        public OpenAIProvider(HttpClient httpClient, ILogger<OpenAIProvider> logger, IOptions<OpenAIConfiguration> config)
        {
            _httpClient = httpClient;
            _logger = logger;
            _config = config.Value;
            
            _httpClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {_config.ApiKey}");
            _httpClient.DefaultRequestHeaders.Add("User-Agent", "AISecurityScanner/1.0");
        }

        public async Task<SecurityAnalysisResult> AnalyzeCodeAsync(string code, AIAnalysisContext context, CancellationToken cancellationToken = default)
        {
            var startTime = DateTime.UtcNow;
            
            try
            {
                var prompt = BuildSecurityAnalysisPrompt(code, context);
                var response = await SendChatCompletionAsync(prompt, cancellationToken);
                
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
                _logger.LogError(ex, "Error analyzing code with OpenAI");
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
                var response = await SendChatCompletionAsync(prompt, cancellationToken);
                
                var validatedPackages = ParsePackageValidation(response, packages, ecosystem);
                var vulnerablePackages = ConvertToPackageVulnerabilityInfo(validatedPackages, packages, ecosystem);
                
                return new PackageValidationResult
                {
                    IsSuccess = true,
                    VulnerablePackages = vulnerablePackages,
                    TotalPackagesScanned = packages.Count,
                    VulnerablePackageCount = vulnerablePackages.Count(p => p.HasVulnerabilities),
                    Cost = CostPerRequest * 0.5m, // Package validation is simpler
                    ProviderName = Name
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating packages with OpenAI");
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
                var testPrompt = "Respond with 'OK' if you can process this message.";
                var response = await SendChatCompletionAsync(testPrompt, cancellationToken);
                
                var responseTime = DateTime.UtcNow - startTime;
                var isHealthy = !string.IsNullOrEmpty(response) && response.Contains("OK", StringComparison.OrdinalIgnoreCase);

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

        private async Task<string> SendChatCompletionAsync(string prompt, CancellationToken cancellationToken)
        {
            var requestBody = new
            {
                model = _config.Model,
                messages = new[]
                {
                    new { role = "system", content = "You are a security expert analyzing code for vulnerabilities." },
                    new { role = "user", content = prompt }
                },
                max_tokens = _config.MaxTokens,
                temperature = 0.1,
                response_format = new { type = "json_object" }
            };

            var json = JsonSerializer.Serialize(requestBody);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            var response = await _httpClient.PostAsync(_config.ApiEndpoint, content, cancellationToken);
            response.EnsureSuccessStatusCode();

            var responseJson = await response.Content.ReadAsStringAsync(cancellationToken);
            var responseObj = JsonSerializer.Deserialize<JsonElement>(responseJson);

            if (responseObj.TryGetProperty("choices", out var choices) && choices.GetArrayLength() > 0)
            {
                var firstChoice = choices[0];
                if (firstChoice.TryGetProperty("message", out var message) &&
                    message.TryGetProperty("content", out var messageContent))
                {
                    return messageContent.GetString() ?? "";
                }
            }

            throw new InvalidOperationException("Invalid response format from OpenAI");
        }

        private string BuildSecurityAnalysisPrompt(string code, AIAnalysisContext context)
        {
            return $@"
Analyze the following {context.Language} code for security vulnerabilities.

Consider these vulnerability types:
- SQL Injection
- Cross-Site Scripting (XSS)
- Command Injection
- Path Traversal
- Insecure Cryptography
- Hard-coded Secrets
- Authentication/Authorization Issues
- Input Validation Issues
- Buffer Overflows
- Race Conditions

Code to analyze:
```{context.Language}
{code}
```

Respond with a JSON object containing:
{{
  ""vulnerabilities"": [
    {{
      ""type"": ""vulnerability_type"",
      ""severity"": ""Critical|High|Medium|Low|Info"",
      ""line_number"": number,
      ""description"": ""detailed description"",
      ""recommendation"": ""how to fix"",
      ""confidence"": decimal_between_0_and_1,
      ""cwe"": ""CWE-XXX"",
      ""owasp_category"": ""A01:2021-Broken Access Control""
    }}
  ],
  ""is_ai_generated"": boolean,
  ""ai_confidence"": decimal_between_0_and_1
}}";
        }

        private string BuildPackageValidationPrompt(List<string> packages, string ecosystem)
        {
            var packageList = string.Join(", ", packages);
            
            return $@"
Validate if the following {ecosystem} packages exist in the official package registry:
Packages: {packageList}

Check each package and determine:
1. Does it exist in the official {ecosystem} registry?
2. Is it a real, legitimate package?
3. Could it be a hallucinated/made-up package name?

Respond with a JSON object:
{{
  ""packages"": [
    {{
      ""name"": ""package_name"",
      ""exists"": boolean,
      ""is_hallucinated"": boolean,
      ""registry_url"": ""url_if_exists"",
      ""confidence"": decimal_between_0_and_1
    }}
  ]
}}";
        }

        private List<VulnerabilityDto> ParseVulnerabilities(string response, AIAnalysisContext context)
        {
            try
            {
                var jsonDoc = JsonSerializer.Deserialize<JsonElement>(response);
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
                            Confidence = vuln.TryGetProperty("confidence", out var conf) ? conf.GetDecimal() : 0.5m,
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
                _logger.LogWarning(ex, "Failed to parse OpenAI vulnerability response");
                return new List<VulnerabilityDto>();
            }
        }

        private List<PackageInfo> ParsePackageValidation(string response, List<string> originalPackages, string ecosystem)
        {
            try
            {
                var jsonDoc = JsonSerializer.Deserialize<JsonElement>(response);
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
                _logger.LogWarning(ex, "Failed to parse OpenAI package validation response");
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
            // Rough estimation: ~4 characters per token
            return text.Length / 4;
        }
    }

    public class OpenAIConfiguration
    {
        public string ApiKey { get; set; } = string.Empty;
        public string ApiEndpoint { get; set; } = "https://api.openai.com/v1/chat/completions";
        public string Model { get; set; } = "gpt-4-turbo-preview";
        public int MaxTokens { get; set; } = 4096;
        public decimal CostPerRequest { get; set; } = 0.03m;
    }
}