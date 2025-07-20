using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using AISecurityScanner.Application.Interfaces;
using AISecurityScanner.Application.Models;
using AISecurityScanner.Domain.Entities;
using AISecurityScanner.Domain.Enums;
using Microsoft.Extensions.Logging;

namespace AISecurityScanner.Infrastructure.AIProviders
{
    public class HallucinationDetectionService : IHallucinationDetectionService
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger<HallucinationDetectionService> _logger;
        
        // Known package registries
        private readonly Dictionary<string, string> _packageRegistries = new()
        {
            ["NuGet"] = "https://api.nuget.org/v3-flatcontainer/",
            ["npm"] = "https://registry.npmjs.org/",
            ["PyPI"] = "https://pypi.org/simple/",
            ["Maven"] = "https://search.maven.org/solrsearch/select",
            ["RubyGems"] = "https://rubygems.org/api/v1/gems/"
        };

        // Common AI hallucination patterns
        private readonly List<string> _suspiciousPatterns = new()
        {
            @"ai[-_]?generated",
            @"gpt[-_]?package",
            @"claude[-_]?lib",
            @"synthetic[-_]?module",
            @"example[-_]?package",
            @"demo[-_]?lib",
            @"test[-_]?package[-_]?\d+",
            @"placeholder[-_]?module",
            @"dummy[-_]?package"
        };

        // Known legitimate packages that might trigger false positives
        private readonly HashSet<string> _whitelistedPackages = new()
        {
            "openai", "anthropic", "gpt-3-encoder", "gpt-tokenizer", 
            "langchain", "semantic-kernel", "ai-sdk"
        };

        public HallucinationDetectionService(HttpClient httpClient, ILogger<HallucinationDetectionService> logger)
        {
            _httpClient = httpClient;
            _logger = logger;
        }

        public async Task<HallucinationDetectionResult> CheckForHallucinationAsync(
            string packageName,
            string packageManager,
            string? version = null,
            CancellationToken cancellationToken = default)
        {
            var result = new HallucinationDetectionResult
            {
                PackageName = packageName,
                PackageManager = packageManager,
                Version = version,
                CheckedAt = DateTime.UtcNow
            };

            try
            {
                // Step 1: Check if package is whitelisted
                if (IsWhitelisted(packageName))
                {
                    result.IsHallucinated = false;
                    result.Confidence = 1.0m;
                    result.Reason = "Package is in whitelist of known legitimate packages";
                    return result;
                }

                // Step 2: Pattern-based detection
                var patternScore = CheckSuspiciousPatterns(packageName);
                if (patternScore > 0.7m)
                {
                    result.PatternMatchScore = patternScore;
                    result.SuspiciousPatterns.Add($"Package name matches AI-generated patterns (score: {patternScore:F2})");
                }

                // Step 3: Check if package exists in registry
                var exists = await CheckPackageExistsInRegistryAsync(packageName, packageManager, cancellationToken);
                result.ExistsInRegistry = exists;

                if (!exists)
                {
                    result.IsHallucinated = true;
                    result.Confidence = 0.95m;
                    result.Reason = $"Package '{packageName}' not found in {packageManager} registry";
                    result.Severity = VulnerabilitySeverity.Critical;
                    return result;
                }

                // Step 4: Check for typosquatting
                var typosquattingCheck = await CheckTyposquattingAsync(packageName, packageManager, cancellationToken);
                if (typosquattingCheck.IsSuspicious)
                {
                    result.TyposquattingRisk = typosquattingCheck.Score;
                    result.SuspiciousPatterns.Add($"Possible typosquatting of '{typosquattingCheck.SimilarPackage}'");
                }

                // Step 5: Metadata analysis
                var metadata = await GetPackageMetadataAsync(packageName, packageManager, version, cancellationToken);
                if (metadata != null)
                {
                    var metadataScore = AnalyzePackageMetadata(metadata);
                    result.MetadataScore = metadataScore;

                    if (metadataScore < 0.3m)
                    {
                        result.SuspiciousPatterns.Add("Package has suspicious metadata characteristics");
                    }
                }

                // Step 6: Calculate final hallucination score
                result.Confidence = CalculateFinalConfidence(result);
                result.IsHallucinated = result.Confidence > 0.7m;
                
                if (result.IsHallucinated)
                {
                    result.Severity = result.Confidence > 0.9m 
                        ? VulnerabilitySeverity.Critical 
                        : VulnerabilitySeverity.High;
                    result.Reason = GenerateHallucinationReason(result);
                }

                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking hallucination for {Package} ({Manager})", 
                    packageName, packageManager);
                
                result.IsHallucinated = false;
                result.Confidence = 0;
                result.Reason = "Unable to perform hallucination check due to error";
                return result;
            }
        }

        private bool IsWhitelisted(string packageName)
        {
            return _whitelistedPackages.Contains(packageName.ToLowerInvariant());
        }

        private decimal CheckSuspiciousPatterns(string packageName)
        {
            var lowerName = packageName.ToLowerInvariant();
            decimal score = 0;

            foreach (var pattern in _suspiciousPatterns)
            {
                if (Regex.IsMatch(lowerName, pattern, RegexOptions.IgnoreCase))
                {
                    score += 0.3m;
                }
            }

            // Check for random-looking names
            if (HasHighEntropyName(packageName))
            {
                score += 0.4m;
            }

            // Check for version-like suffixes in package name
            if (Regex.IsMatch(packageName, @"\d{1,3}\.\d{1,3}\.\d{1,3}$"))
            {
                score += 0.3m;
            }

            return Math.Min(score, 1.0m);
        }

        private bool HasHighEntropyName(string name)
        {
            // Simple entropy check - ratio of unique characters to total length
            var uniqueChars = name.ToLower().Distinct().Count();
            var entropy = (double)uniqueChars / name.Length;

            // Check for too many numbers or special characters
            var nonAlphaCount = name.Count(c => !char.IsLetter(c));
            var nonAlphaRatio = (double)nonAlphaCount / name.Length;

            return entropy > 0.8 || nonAlphaRatio > 0.5;
        }

        private async Task<bool> CheckPackageExistsInRegistryAsync(
            string packageName, 
            string packageManager,
            CancellationToken cancellationToken)
        {
            if (!_packageRegistries.TryGetValue(packageManager, out var registryUrl))
            {
                _logger.LogWarning("Unknown package manager: {Manager}", packageManager);
                return true; // Assume it exists if we can't check
            }

            try
            {
                string url = packageManager switch
                {
                    "NuGet" => $"{registryUrl}{packageName.ToLowerInvariant()}/index.json",
                    "npm" => $"{registryUrl}{packageName}",
                    "PyPI" => $"{registryUrl}{packageName.ToLowerInvariant()}/",
                    "Maven" => $"{registryUrl}?q=a:{packageName}&rows=1&wt=json",
                    "RubyGems" => $"{registryUrl}{packageName}.json",
                    _ => throw new NotSupportedException($"Package manager {packageManager} not supported")
                };

                var response = await _httpClient.GetAsync(url, cancellationToken);
                return response.IsSuccessStatusCode;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking package existence for {Package} in {Manager}", 
                    packageName, packageManager);
                return true; // Assume exists on error to avoid false positives
            }
        }

        private async Task<TyposquattingResult> CheckTyposquattingAsync(
            string packageName,
            string packageManager,
            CancellationToken cancellationToken)
        {
            var result = new TyposquattingResult();
            var popularPackages = GetPopularPackagesForManager(packageManager);

            foreach (var popular in popularPackages)
            {
                var distance = CalculateLevenshteinDistance(packageName.ToLower(), popular.ToLower());
                
                // If distance is 1 or 2, it might be typosquatting
                if (distance > 0 && distance <= 2)
                {
                    result.IsSuspicious = true;
                    result.Score = 1.0m - (distance / 10.0m); // Higher score for closer matches
                    result.SimilarPackage = popular;
                    break;
                }

                // Check for common typosquatting patterns
                if (IsTyposquattingPattern(packageName, popular))
                {
                    result.IsSuspicious = true;
                    result.Score = 0.8m;
                    result.SimilarPackage = popular;
                    break;
                }
            }

            return await Task.FromResult(result);
        }

        private List<string> GetPopularPackagesForManager(string packageManager)
        {
            return packageManager switch
            {
                "npm" => new List<string> { "react", "vue", "angular", "express", "lodash", "axios", "jquery", "webpack" },
                "NuGet" => new List<string> { "Newtonsoft.Json", "Microsoft.EntityFrameworkCore", "Serilog", "AutoMapper", "Dapper" },
                "PyPI" => new List<string> { "numpy", "pandas", "requests", "django", "flask", "pytest", "tensorflow" },
                _ => new List<string>()
            };
        }

        private bool IsTyposquattingPattern(string packageName, string popularPackage)
        {
            var variations = new[]
            {
                $"{popularPackage}js",
                $"{popularPackage}-js",
                $"{popularPackage}2",
                $"{popularPackage}-lib",
                $"lib{popularPackage}",
                $"{popularPackage}x"
            };

            return variations.Any(v => v.Equals(packageName, StringComparison.OrdinalIgnoreCase));
        }

        private async Task<PackageMetadata?> GetPackageMetadataAsync(
            string packageName,
            string packageManager,
            string? version,
            CancellationToken cancellationToken)
        {
            // In a real implementation, fetch actual metadata from the registry
            // For now, return mock data
            await Task.Delay(10, cancellationToken);

            return new PackageMetadata
            {
                Name = packageName,
                Version = version ?? "latest",
                PublishedDate = DateTime.UtcNow.AddDays(-Random.Shared.Next(1, 365)),
                Downloads = Random.Shared.Next(0, 100000),
                HasRepository = Random.Shared.Next(0, 2) == 1,
                HasDocumentation = Random.Shared.Next(0, 2) == 1,
                MaintainerCount = Random.Shared.Next(0, 5),
                LastUpdateDays = Random.Shared.Next(1, 365)
            };
        }

        private decimal AnalyzePackageMetadata(PackageMetadata metadata)
        {
            decimal score = 1.0m;

            // Penalize packages with no downloads
            if (metadata.Downloads == 0) score -= 0.3m;
            else if (metadata.Downloads < 100) score -= 0.2m;
            else if (metadata.Downloads < 1000) score -= 0.1m;

            // Penalize packages without repository
            if (!metadata.HasRepository) score -= 0.2m;

            // Penalize packages without documentation
            if (!metadata.HasDocumentation) score -= 0.1m;

            // Penalize packages with no maintainers
            if (metadata.MaintainerCount == 0) score -= 0.2m;

            // Penalize very new packages
            if (metadata.PublishedDate > DateTime.UtcNow.AddDays(-7)) score -= 0.2m;

            // Penalize packages not updated recently (abandoned)
            if (metadata.LastUpdateDays > 730) score -= 0.1m; // 2 years

            return Math.Max(0, score);
        }

        private decimal CalculateFinalConfidence(HallucinationDetectionResult result)
        {
            if (!result.ExistsInRegistry) return 0.95m;

            decimal confidence = 0;

            // Weight different factors
            confidence += result.PatternMatchScore * 0.3m;
            confidence += result.TyposquattingRisk * 0.3m;
            confidence += (1.0m - result.MetadataScore) * 0.4m;

            return Math.Min(confidence, 1.0m);
        }

        private string GenerateHallucinationReason(HallucinationDetectionResult result)
        {
            var reasons = new List<string>();

            if (!result.ExistsInRegistry)
            {
                reasons.Add($"Package not found in {result.PackageManager} registry");
            }

            if (result.PatternMatchScore > 0.5m)
            {
                reasons.Add("Package name matches AI-generated patterns");
            }

            if (result.TyposquattingRisk > 0.5m)
            {
                reasons.Add("High risk of typosquatting");
            }

            if (result.MetadataScore < 0.3m)
            {
                reasons.Add("Suspicious package metadata");
            }

            return string.Join("; ", reasons);
        }

        private int CalculateLevenshteinDistance(string s1, string s2)
        {
            var d = new int[s1.Length + 1, s2.Length + 1];

            for (int i = 0; i <= s1.Length; i++)
                d[i, 0] = i;
            for (int j = 0; j <= s2.Length; j++)
                d[0, j] = j;

            for (int i = 1; i <= s1.Length; i++)
            {
                for (int j = 1; j <= s2.Length; j++)
                {
                    var cost = s1[i - 1] == s2[j - 1] ? 0 : 1;
                    d[i, j] = Math.Min(
                        Math.Min(d[i - 1, j] + 1, d[i, j - 1] + 1),
                        d[i - 1, j - 1] + cost);
                }
            }

            return d[s1.Length, s2.Length];
        }
    }


    public class TyposquattingResult
    {
        public bool IsSuspicious { get; set; }
        public decimal Score { get; set; }
        public string? SimilarPackage { get; set; }
    }

    public class PackageMetadata
    {
        public string Name { get; set; } = "";
        public string Version { get; set; } = "";
        public DateTime PublishedDate { get; set; }
        public int Downloads { get; set; }
        public bool HasRepository { get; set; }
        public bool HasDocumentation { get; set; }
        public int MaintainerCount { get; set; }
        public int LastUpdateDays { get; set; }
    }
}