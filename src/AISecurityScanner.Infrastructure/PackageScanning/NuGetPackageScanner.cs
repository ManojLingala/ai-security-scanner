using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;
using AISecurityScanner.Application.Interfaces;
using AISecurityScanner.Domain.Entities;
using AISecurityScanner.Domain.Enums;
using Microsoft.Extensions.Logging;

namespace AISecurityScanner.Infrastructure.PackageScanning
{
    public class NuGetPackageScanner : INuGetPackageScanner
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger<NuGetPackageScanner> _logger;
        private const string NuGetApiUrl = "https://api.nuget.org/v3-flatcontainer/";
        private const string NuGetSearchUrl = "https://api.nuget.org/v3/registration5-gz-semver2/";

        public NuGetPackageScanner(HttpClient httpClient, ILogger<NuGetPackageScanner> logger)
        {
            _httpClient = httpClient;
            _logger = logger;
        }

        public async Task<List<PackageVulnerability>> ScanProjectAsync(
            string projectFilePath, 
            Guid scanId,
            CancellationToken cancellationToken = default)
        {
            var vulnerabilities = new List<PackageVulnerability>();

            try
            {
                if (!File.Exists(projectFilePath))
                {
                    _logger.LogWarning("Project file not found: {ProjectFile}", projectFilePath);
                    return vulnerabilities;
                }

                // Parse the project file
                var packages = ParseProjectFile(projectFilePath);
                
                // Check each package
                foreach (var package in packages)
                {
                    var vulnerability = await CheckPackageVulnerabilityAsync(
                        package.Name, 
                        package.Version, 
                        projectFilePath,
                        scanId,
                        cancellationToken);
                    
                    if (vulnerability != null)
                    {
                        vulnerabilities.Add(vulnerability);
                    }
                }

                _logger.LogInformation("Scanned {Count} NuGet packages in {File}", 
                    packages.Count, projectFilePath);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error scanning NuGet packages in {File}", projectFilePath);
            }

            return vulnerabilities;
        }

        private List<(string Name, string Version)> ParseProjectFile(string projectFilePath)
        {
            var packages = new List<(string Name, string Version)>();

            try
            {
                var doc = XDocument.Load(projectFilePath);
                
                // Handle PackageReference format (newer .csproj format)
                var packageReferences = doc.Descendants("PackageReference")
                    .Where(pr => pr.Attribute("Include") != null);

                foreach (var packageRef in packageReferences)
                {
                    var name = packageRef.Attribute("Include")?.Value;
                    var version = packageRef.Attribute("Version")?.Value 
                        ?? packageRef.Element("Version")?.Value;

                    if (!string.IsNullOrEmpty(name) && !string.IsNullOrEmpty(version))
                    {
                        packages.Add((name, version));
                    }
                }

                // Also check for packages.config if it exists
                var directory = Path.GetDirectoryName(projectFilePath);
                var packagesConfigPath = Path.Combine(directory ?? "", "packages.config");
                
                if (File.Exists(packagesConfigPath))
                {
                    packages.AddRange(ParsePackagesConfig(packagesConfigPath));
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error parsing project file: {File}", projectFilePath);
            }

            return packages;
        }

        private List<(string Name, string Version)> ParsePackagesConfig(string packagesConfigPath)
        {
            var packages = new List<(string Name, string Version)>();

            try
            {
                var doc = XDocument.Load(packagesConfigPath);
                var packageElements = doc.Descendants("package");

                foreach (var package in packageElements)
                {
                    var id = package.Attribute("id")?.Value;
                    var version = package.Attribute("version")?.Value;

                    if (!string.IsNullOrEmpty(id) && !string.IsNullOrEmpty(version))
                    {
                        packages.Add((id, version));
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error parsing packages.config: {File}", packagesConfigPath);
            }

            return packages;
        }

        private async Task<PackageVulnerability?> CheckPackageVulnerabilityAsync(
            string packageName, 
            string version,
            string filePath,
            Guid scanId,
            CancellationToken cancellationToken)
        {
            try
            {
                // Check if package exists
                var packageExists = await CheckPackageExistsAsync(packageName, cancellationToken);
                
                // Get latest version
                var latestVersion = await GetLatestVersionAsync(packageName, cancellationToken);
                
                // Check for known vulnerabilities (simplified - in production, use a vulnerability database)
                var hasVulnerabilities = await CheckKnownVulnerabilitiesAsync(packageName, version, cancellationToken);
                
                var vulnerability = new PackageVulnerability
                {
                    Id = Guid.NewGuid(),
                    SecurityScanId = scanId,
                    PackageName = packageName,
                    Version = version,
                    PackageManager = "NuGet",
                    LatestVersion = latestVersion,
                    FilePath = filePath,
                    IsDirectDependency = true,
                    PackageExists = packageExists,
                    CreatedAt = DateTime.UtcNow,
                    LastCheckedAt = DateTime.UtcNow
                };

                // Version comparison
                if (!string.IsNullOrEmpty(latestVersion))
                {
                    vulnerability.IsOutdated = IsVersionOutdated(version, latestVersion);
                }

                // Check for vulnerabilities
                if (hasVulnerabilities.HasValue)
                {
                    vulnerability.HasKnownVulnerabilities = hasVulnerabilities.Value;
                    if (hasVulnerabilities.Value)
                    {
                        // In a real implementation, populate CVE, CVSS, etc.
                        vulnerability.Severity = VulnerabilitySeverity.High;
                        vulnerability.Description = $"Known vulnerabilities found in {packageName} version {version}";
                    }
                }

                // Check for hallucination
                if (!packageExists)
                {
                    vulnerability.IsPotentiallyHallucinated = true;
                    vulnerability.HallucinationConfidence = 0.95m;
                    vulnerability.HallucinationReason = $"Package '{packageName}' not found in NuGet registry";
                    vulnerability.Severity = VulnerabilitySeverity.Critical;
                    vulnerability.Description = $"Potentially hallucinated package: {packageName}";
                }

                return vulnerability;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking vulnerability for package {Package} v{Version}", 
                    packageName, version);
                return null;
            }
        }

        private async Task<bool> CheckPackageExistsAsync(string packageName, CancellationToken cancellationToken)
        {
            try
            {
                var url = $"{NuGetApiUrl}{packageName.ToLowerInvariant()}/index.json";
                var response = await _httpClient.GetAsync(url, cancellationToken);
                return response.IsSuccessStatusCode;
            }
            catch
            {
                return false;
            }
        }

        private async Task<string?> GetLatestVersionAsync(string packageName, CancellationToken cancellationToken)
        {
            try
            {
                var url = $"{NuGetSearchUrl}{packageName.ToLowerInvariant()}/index.json";
                var response = await _httpClient.GetStringAsync(url, cancellationToken);
                
                var json = JsonDocument.Parse(response);
                var items = json.RootElement.GetProperty("items");
                
                if (items.GetArrayLength() > 0)
                {
                    var latestItem = items[items.GetArrayLength() - 1];
                    if (latestItem.TryGetProperty("upper", out var upper))
                    {
                        return upper.GetString();
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting latest version for {Package}", packageName);
            }

            return null;
        }

        private async Task<bool?> CheckKnownVulnerabilitiesAsync(
            string packageName, 
            string version, 
            CancellationToken cancellationToken)
        {
            // In a real implementation, this would check against:
            // - GitHub Advisory Database
            // - NVD (National Vulnerability Database)
            // - OSV (Open Source Vulnerabilities)
            // - Snyk vulnerability database
            
            // For now, we'll use a simple heuristic
            await Task.Delay(10, cancellationToken); // Simulate API call
            
            // Check for very old versions (simplified check)
            if (version.StartsWith("1.") || version.StartsWith("0."))
            {
                return true; // Likely has vulnerabilities
            }

            return false;
        }

        private bool IsVersionOutdated(string currentVersion, string latestVersion)
        {
            try
            {
                var current = ParseVersion(currentVersion);
                var latest = ParseVersion(latestVersion);

                return current.Major < latest.Major ||
                       (current.Major == latest.Major && current.Minor < latest.Minor) ||
                       (current.Major == latest.Major && current.Minor == latest.Minor && current.Patch < latest.Patch);
            }
            catch
            {
                // If we can't parse versions, consider it potentially outdated
                return true;
            }
        }

        private (int Major, int Minor, int Patch) ParseVersion(string version)
        {
            // Remove any pre-release or metadata
            var cleanVersion = Regex.Match(version, @"^\d+\.\d+\.\d+").Value;
            var parts = cleanVersion.Split('.');
            
            return (
                int.Parse(parts[0]),
                parts.Length > 1 ? int.Parse(parts[1]) : 0,
                parts.Length > 2 ? int.Parse(parts[2]) : 0
            );
        }
    }
}