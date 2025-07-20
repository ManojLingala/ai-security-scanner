using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using AISecurityScanner.Application.Interfaces;
using AISecurityScanner.Domain.Entities;
using AISecurityScanner.Domain.Enums;
using Microsoft.Extensions.Logging;

namespace AISecurityScanner.Infrastructure.PackageScanning
{
    public class NpmPackageScanner : INpmPackageScanner
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger<NpmPackageScanner> _logger;
        private const string NpmRegistryUrl = "https://registry.npmjs.org/";
        private const string NpmApiUrl = "https://api.npms.io/v2/";

        public NpmPackageScanner(HttpClient httpClient, ILogger<NpmPackageScanner> logger)
        {
            _httpClient = httpClient;
            _logger = logger;
        }

        public async Task<List<PackageVulnerability>> ScanPackageJsonAsync(
            string packageJsonPath,
            Guid scanId,
            CancellationToken cancellationToken = default)
        {
            var vulnerabilities = new List<PackageVulnerability>();

            try
            {
                if (!File.Exists(packageJsonPath))
                {
                    _logger.LogWarning("package.json not found: {File}", packageJsonPath);
                    return vulnerabilities;
                }

                var packageJson = await File.ReadAllTextAsync(packageJsonPath, cancellationToken);
                var packages = ParsePackageJson(packageJson);

                foreach (var package in packages)
                {
                    var vulnerability = await CheckNpmPackageVulnerabilityAsync(
                        package.Name,
                        package.Version,
                        packageJsonPath,
                        scanId,
                        package.IsDev,
                        cancellationToken);

                    if (vulnerability != null)
                    {
                        vulnerabilities.Add(vulnerability);
                    }
                }

                // Also check package-lock.json for more detailed dependency tree
                var lockFilePath = Path.Combine(Path.GetDirectoryName(packageJsonPath) ?? "", "package-lock.json");
                if (File.Exists(lockFilePath))
                {
                    var transitiveVulnerabilities = await ScanPackageLockAsync(
                        lockFilePath, scanId, cancellationToken);
                    vulnerabilities.AddRange(transitiveVulnerabilities);
                }

                _logger.LogInformation("Scanned {Count} npm packages in {File}",
                    packages.Count, packageJsonPath);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error scanning npm packages in {File}", packageJsonPath);
            }

            return vulnerabilities;
        }

        private List<(string Name, string Version, bool IsDev)> ParsePackageJson(string packageJsonContent)
        {
            var packages = new List<(string Name, string Version, bool IsDev)>();

            try
            {
                using var doc = JsonDocument.Parse(packageJsonContent);
                var root = doc.RootElement;

                // Parse dependencies
                if (root.TryGetProperty("dependencies", out var dependencies))
                {
                    foreach (var dep in dependencies.EnumerateObject())
                    {
                        packages.Add((dep.Name, CleanVersion(dep.Value.GetString() ?? ""), false));
                    }
                }

                // Parse devDependencies
                if (root.TryGetProperty("devDependencies", out var devDependencies))
                {
                    foreach (var dep in devDependencies.EnumerateObject())
                    {
                        packages.Add((dep.Name, CleanVersion(dep.Value.GetString() ?? ""), true));
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error parsing package.json");
            }

            return packages;
        }

        private string CleanVersion(string version)
        {
            // Remove npm version range prefixes
            return version.TrimStart('^', '~', '>', '<', '=', ' ');
        }

        private async Task<PackageVulnerability?> CheckNpmPackageVulnerabilityAsync(
            string packageName,
            string version,
            string filePath,
            Guid scanId,
            bool isDevDependency,
            CancellationToken cancellationToken)
        {
            try
            {
                // Check if package exists
                var packageInfo = await GetPackageInfoAsync(packageName, cancellationToken);
                var packageExists = packageInfo != null;

                // Get security info
                var securityInfo = await GetSecurityInfoAsync(packageName, version, cancellationToken);

                var vulnerability = new PackageVulnerability
                {
                    Id = Guid.NewGuid(),
                    SecurityScanId = scanId,
                    PackageName = packageName,
                    Version = version,
                    PackageManager = "npm",
                    FilePath = filePath,
                    IsDirectDependency = true,
                    PackageExists = packageExists,
                    CreatedAt = DateTime.UtcNow,
                    LastCheckedAt = DateTime.UtcNow
                };

                if (packageInfo != null)
                {
                    vulnerability.LatestVersion = packageInfo.LatestVersion;
                    vulnerability.License = packageInfo.License;
                    vulnerability.IsOutdated = IsVersionOutdated(version, packageInfo.LatestVersion);
                }

                // Check for security vulnerabilities
                if (securityInfo != null && securityInfo.Vulnerabilities.Any())
                {
                    vulnerability.HasKnownVulnerabilities = true;
                    var highestSeverity = securityInfo.Vulnerabilities.Max(v => v.Severity);
                    vulnerability.Severity = MapNpmSeverity(highestSeverity ?? "low");
                    vulnerability.CVE = securityInfo.Vulnerabilities.FirstOrDefault()?.Id;
                    vulnerability.Description = string.Join("; ", 
                        securityInfo.Vulnerabilities.Select(v => v.Title));
                    vulnerability.AdvisoryUrl = securityInfo.Vulnerabilities.FirstOrDefault()?.Url;
                }

                // AI Hallucination check
                if (!packageExists)
                {
                    vulnerability.IsPotentiallyHallucinated = true;
                    vulnerability.HallucinationConfidence = 0.98m;
                    vulnerability.HallucinationReason = $"Package '{packageName}' not found in npm registry";
                    vulnerability.Severity = VulnerabilitySeverity.Critical;
                    vulnerability.Description = $"Potentially hallucinated package: {packageName} - This package does not exist in the npm registry";
                }
                else if (IsSuspiciousPackageName(packageName))
                {
                    vulnerability.IsPotentiallyHallucinated = true;
                    vulnerability.HallucinationConfidence = 0.75m;
                    vulnerability.HallucinationReason = "Package name follows suspicious patterns (typosquatting risk)";
                    vulnerability.Severity = VulnerabilitySeverity.High;
                }

                return vulnerability;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking npm package {Package} v{Version}",
                    packageName, version);
                return null;
            }
        }

        private async Task<List<PackageVulnerability>> ScanPackageLockAsync(
            string lockFilePath,
            Guid scanId,
            CancellationToken cancellationToken)
        {
            var vulnerabilities = new List<PackageVulnerability>();

            try
            {
                var lockContent = await File.ReadAllTextAsync(lockFilePath, cancellationToken);
                using var doc = JsonDocument.Parse(lockContent);
                
                if (doc.RootElement.TryGetProperty("dependencies", out var dependencies))
                {
                    await ScanDependenciesRecursive(
                        dependencies, 
                        scanId, 
                        lockFilePath,
                        "", 
                        vulnerabilities, 
                        cancellationToken);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error scanning package-lock.json");
            }

            return vulnerabilities;
        }

        private async Task ScanDependenciesRecursive(
            JsonElement dependencies,
            Guid scanId,
            string filePath,
            string parentPath,
            List<PackageVulnerability> vulnerabilities,
            CancellationToken cancellationToken)
        {
            foreach (var dep in dependencies.EnumerateObject())
            {
                var packageName = dep.Name;
                var depInfo = dep.Value;

                if (depInfo.TryGetProperty("version", out var versionElement))
                {
                    var version = versionElement.GetString() ?? "";
                    var dependencyPath = string.IsNullOrEmpty(parentPath) 
                        ? packageName 
                        : $"{parentPath} > {packageName}";

                    var vulnerability = await CheckNpmPackageVulnerabilityAsync(
                        packageName,
                        version,
                        filePath,
                        scanId,
                        false,
                        cancellationToken);

                    if (vulnerability != null)
                    {
                        vulnerability.IsDirectDependency = string.IsNullOrEmpty(parentPath);
                        vulnerability.DependencyPath = dependencyPath;
                        vulnerabilities.Add(vulnerability);
                    }

                    // Recursively check nested dependencies
                    if (depInfo.TryGetProperty("dependencies", out var nestedDeps))
                    {
                        await ScanDependenciesRecursive(
                            nestedDeps,
                            scanId,
                            filePath,
                            dependencyPath,
                            vulnerabilities,
                            cancellationToken);
                    }
                }
            }
        }

        private async Task<PackageInfo?> GetPackageInfoAsync(string packageName, CancellationToken cancellationToken)
        {
            try
            {
                var url = $"{NpmRegistryUrl}{packageName}";
                var response = await _httpClient.GetStringAsync(url, cancellationToken);
                
                using var doc = JsonDocument.Parse(response);
                var root = doc.RootElement;

                if (root.TryGetProperty("dist-tags", out var distTags) &&
                    distTags.TryGetProperty("latest", out var latest))
                {
                    var latestVersion = latest.GetString();
                    string? license = null;

                    if (root.TryGetProperty("license", out var licenseElement))
                    {
                        license = licenseElement.ValueKind == JsonValueKind.String 
                            ? licenseElement.GetString() 
                            : licenseElement.GetProperty("type").GetString();
                    }

                    return new PackageInfo
                    {
                        Name = packageName,
                        LatestVersion = latestVersion ?? "",
                        License = license
                    };
                }
            }
            catch (HttpRequestException ex) when (ex.Message.Contains("404"))
            {
                // Package doesn't exist
                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting npm package info for {Package}", packageName);
            }

            return null;
        }

        private async Task<SecurityInfo?> GetSecurityInfoAsync(
            string packageName, 
            string version,
            CancellationToken cancellationToken)
        {
            // In a real implementation, this would check:
            // - npm audit API
            // - Snyk vulnerability database
            // - GitHub Advisory Database
            // - OSV database

            // For now, return mock data for demonstration
            await Task.Delay(10, cancellationToken);

            // Simulate known vulnerable packages
            var knownVulnerablePackages = new Dictionary<string, string[]>
            {
                ["lodash"] = new[] { "4.17.0", "4.17.1", "4.17.2", "4.17.3", "4.17.4" },
                ["minimist"] = new[] { "0.0.8", "1.0.0", "1.1.0", "1.1.1", "1.1.2", "1.1.3" },
                ["express"] = new[] { "3.0.0", "3.0.1", "3.0.2", "3.0.3", "3.0.4", "3.0.5" }
            };

            if (knownVulnerablePackages.TryGetValue(packageName, out var vulnerableVersions) &&
                vulnerableVersions.Contains(version))
            {
                return new SecurityInfo
                {
                    Vulnerabilities = new List<VulnerabilityInfo>
                    {
                        new VulnerabilityInfo
                        {
                            Id = "CVE-2021-MOCK",
                            Title = $"Known vulnerability in {packageName} {version}",
                            Severity = "high",
                            Url = $"https://nvd.nist.gov/vuln/detail/CVE-2021-MOCK"
                        }
                    }
                };
            }

            return null;
        }

        private bool IsSuspiciousPackageName(string packageName)
        {
            // Check for common typosquatting patterns
            var popularPackages = new[] { "react", "vue", "angular", "express", "lodash", "jquery", "axios" };
            
            foreach (var popular in popularPackages)
            {
                // Check for single character differences
                if (LevenshteinDistance(packageName.ToLower(), popular) == 1)
                {
                    return true;
                }

                // Check for common typosquatting patterns
                if (packageName.Equals($"{popular}js", StringComparison.OrdinalIgnoreCase) ||
                    packageName.Equals($"{popular}-js", StringComparison.OrdinalIgnoreCase) ||
                    packageName.Equals($"{popular}2", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        private int LevenshteinDistance(string s1, string s2)
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
                    d[i, j] = Math.Min(Math.Min(d[i - 1, j] + 1, d[i, j - 1] + 1), d[i - 1, j - 1] + cost);
                }
            }

            return d[s1.Length, s2.Length];
        }

        private VulnerabilitySeverity MapNpmSeverity(string npmSeverity)
        {
            return npmSeverity?.ToLower() switch
            {
                "critical" => VulnerabilitySeverity.Critical,
                "high" => VulnerabilitySeverity.High,
                "moderate" => VulnerabilitySeverity.Medium,
                "low" => VulnerabilitySeverity.Low,
                _ => VulnerabilitySeverity.Info
            };
        }

        private bool IsVersionOutdated(string current, string latest)
        {
            try
            {
                var currentParts = current.Split('.').Select(int.Parse).ToArray();
                var latestParts = latest.Split('.').Select(int.Parse).ToArray();

                for (int i = 0; i < Math.Min(currentParts.Length, latestParts.Length); i++)
                {
                    if (currentParts[i] < latestParts[i]) return true;
                    if (currentParts[i] > latestParts[i]) return false;
                }

                return currentParts.Length < latestParts.Length;
            }
            catch
            {
                return false;
            }
        }

        private class PackageInfo
        {
            public string Name { get; set; } = "";
            public string LatestVersion { get; set; } = "";
            public string? License { get; set; }
        }

        private class SecurityInfo
        {
            public List<VulnerabilityInfo> Vulnerabilities { get; set; } = new();
        }

        private class VulnerabilityInfo
        {
            public string Id { get; set; } = "";
            public string Title { get; set; } = "";
            public string Severity { get; set; } = "";
            public string Url { get; set; } = "";
        }
    }
}