using System.Text.Json;
using AISecurityScanner.CLI.Models;

namespace AISecurityScanner.CLI.Services
{
    public class ConfigurationProfileService
    {
        private readonly string _profilesDirectory;
        private readonly ConfigService _configService;

        public ConfigurationProfileService(ConfigService configService)
        {
            _configService = configService;
            _profilesDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".aiscan", "profiles");
            Directory.CreateDirectory(_profilesDirectory);
        }

        public class ScanProfile
        {
            public string Name { get; set; } = string.Empty;
            public string Description { get; set; } = string.Empty;
            public Dictionary<string, object> Settings { get; set; } = new();
            public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
            public DateTime LastUsed { get; set; }
        }

        public async Task<ScanProfile> CreateProfileAsync(string name, string description, Dictionary<string, object> settings)
        {
            var profile = new ScanProfile
            {
                Name = name,
                Description = description,
                Settings = settings,
                CreatedAt = DateTime.UtcNow
            };

            var profilePath = Path.Combine(_profilesDirectory, $"{name}.json");
            var json = JsonSerializer.Serialize(profile, new JsonSerializerOptions { WriteIndented = true });
            await File.WriteAllTextAsync(profilePath, json);

            Console.WriteLine($"✅ Profile '{name}' created successfully");
            return profile;
        }

        public async Task<ScanProfile?> LoadProfileAsync(string name)
        {
            var profilePath = Path.Combine(_profilesDirectory, $"{name}.json");
            
            if (!File.Exists(profilePath))
            {
                Console.WriteLine($"❌ Profile '{name}' not found");
                return null;
            }

            var json = await File.ReadAllTextAsync(profilePath);
            var profile = JsonSerializer.Deserialize<ScanProfile>(json);
            
            if (profile != null)
            {
                profile.LastUsed = DateTime.UtcNow;
                await SaveProfileAsync(profile);
            }

            return profile;
        }

        public async Task SaveProfileAsync(ScanProfile profile)
        {
            var profilePath = Path.Combine(_profilesDirectory, $"{profile.Name}.json");
            var json = JsonSerializer.Serialize(profile, new JsonSerializerOptions { WriteIndented = true });
            await File.WriteAllTextAsync(profilePath, json);
        }

        public async Task<List<ScanProfile>> ListProfilesAsync()
        {
            var profiles = new List<ScanProfile>();
            
            foreach (var file in Directory.GetFiles(_profilesDirectory, "*.json"))
            {
                try
                {
                    var json = await File.ReadAllTextAsync(file);
                    var profile = JsonSerializer.Deserialize<ScanProfile>(json);
                    if (profile != null)
                        profiles.Add(profile);
                }
                catch
                {
                    // Skip invalid profile files
                }
            }

            return profiles.OrderByDescending(p => p.LastUsed).ToList();
        }

        public async Task<bool> DeleteProfileAsync(string name)
        {
            var profilePath = Path.Combine(_profilesDirectory, $"{name}.json");
            
            if (!File.Exists(profilePath))
            {
                Console.WriteLine($"❌ Profile '{name}' not found");
                return false;
            }

            File.Delete(profilePath);
            Console.WriteLine($"✅ Profile '{name}' deleted");
            return true;
        }

        public async Task<bool> ApplyProfileAsync(string name)
        {
            var profile = await LoadProfileAsync(name);
            if (profile == null)
                return false;

            // Apply settings from profile
            foreach (var setting in profile.Settings)
            {
                await _configService.SetSettingAsync(setting.Key, setting.Value?.ToString() ?? "");
            }

            Console.WriteLine($"✅ Profile '{name}' applied");
            return true;
        }

        public async Task<ScanProfile> CreateProfileFromCurrentAsync(string name, string description)
        {
            var currentConfig = await _configService.GetConfigAsync();
            var settings = new Dictionary<string, object>
            {
                ["OutputFormat"] = currentConfig.OutputFormat,
                ["ScanTimeoutSeconds"] = currentConfig.ScanTimeoutSeconds,
                ["MaxConcurrentScans"] = currentConfig.MaxConcurrentScans,
                ["EnabledComplianceFrameworks"] = currentConfig.EnabledComplianceFrameworks
            };

            return await CreateProfileAsync(name, description, settings);
        }

        // Predefined profiles
        public async Task InitializeDefaultProfilesAsync()
        {
            var defaultProfiles = new[]
            {
                new ScanProfile
                {
                    Name = "minimal",
                    Description = "Minimal scanning for quick checks",
                    Settings = new Dictionary<string, object>
                    {
                        ["ScanTimeoutSeconds"] = 30,
                        ["MaxConcurrentScans"] = 8,
                        ["EnabledComplianceFrameworks"] = new string[] { }
                    }
                },
                new ScanProfile
                {
                    Name = "standard",
                    Description = "Standard scanning with common vulnerabilities",
                    Settings = new Dictionary<string, object>
                    {
                        ["ScanTimeoutSeconds"] = 120,
                        ["MaxConcurrentScans"] = 4,
                        ["EnabledComplianceFrameworks"] = new[] { "OWASP" }
                    }
                },
                new ScanProfile
                {
                    Name = "comprehensive",
                    Description = "Comprehensive scanning with all compliance frameworks",
                    Settings = new Dictionary<string, object>
                    {
                        ["ScanTimeoutSeconds"] = 300,
                        ["MaxConcurrentScans"] = 2,
                        ["EnabledComplianceFrameworks"] = new[] { "PCI-DSS", "HIPAA", "SOX", "GDPR", "OWASP" }
                    }
                },
                new ScanProfile
                {
                    Name = "ci-cd",
                    Description = "Optimized for CI/CD pipelines",
                    Settings = new Dictionary<string, object>
                    {
                        ["OutputFormat"] = "sarif",
                        ["ScanTimeoutSeconds"] = 60,
                        ["MaxConcurrentScans"] = 8,
                        ["EnabledComplianceFrameworks"] = new[] { "OWASP" }
                    }
                }
            };

            foreach (var profile in defaultProfiles)
            {
                var profilePath = Path.Combine(_profilesDirectory, $"{profile.Name}.json");
                if (!File.Exists(profilePath))
                {
                    await SaveProfileAsync(profile);
                }
            }
        }
    }
}