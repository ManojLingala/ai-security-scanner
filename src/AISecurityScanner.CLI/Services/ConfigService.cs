using System.Text.Json;
using AISecurityScanner.CLI.Models;

namespace AISecurityScanner.CLI.Services
{
    public class ConfigService
    {
        private static readonly string ConfigDirectory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), 
            ".aiscan"
        );
        
        private static readonly string ConfigFilePath = Path.Combine(ConfigDirectory, "config.json");
        private CliConfig? _config;

        public async Task<CliConfig> GetConfigAsync()
        {
            if (_config != null)
                return _config;

            if (!File.Exists(ConfigFilePath))
            {
                _config = new CliConfig();
                await SaveConfigAsync(_config);
                return _config;
            }

            try
            {
                var json = await File.ReadAllTextAsync(ConfigFilePath);
                _config = JsonSerializer.Deserialize<CliConfig>(json) ?? new CliConfig();
                return _config;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Warning: Could not read config file: {ex.Message}");
                _config = new CliConfig();
                return _config;
            }
        }

        public async Task SaveConfigAsync(CliConfig config)
        {
            try
            {
                Directory.CreateDirectory(ConfigDirectory);
                var json = JsonSerializer.Serialize(config, new JsonSerializerOptions 
                { 
                    WriteIndented = true 
                });
                await File.WriteAllTextAsync(ConfigFilePath, json);
                _config = config;
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Could not save config file: {ex.Message}", ex);
            }
        }

        public async Task<string?> GetClaudeTokenAsync()
        {
            var config = await GetConfigAsync();
            return config.ClaudeToken;
        }

        public async Task SetClaudeTokenAsync(string token)
        {
            var config = await GetConfigAsync();
            config.ClaudeToken = token;
            config.LastLogin = DateTime.UtcNow;
            await SaveConfigAsync(config);
        }

        public async Task SetUserConsentAsync(bool consent)
        {
            var config = await GetConfigAsync();
            config.UserConsentGiven = consent;
            await SaveConfigAsync(config);
        }

        public async Task<bool> IsAuthenticatedAsync()
        {
            var config = await GetConfigAsync();
            return !string.IsNullOrEmpty(config.ClaudeToken) && config.UserConsentGiven;
        }

        public async Task LogoutAsync()
        {
            var config = await GetConfigAsync();
            config.ClaudeToken = null;
            config.OpenAIToken = null;
            config.UserConsentGiven = false;
            config.LastLogin = null;
            await SaveConfigAsync(config);
        }

        public async Task<T> GetSettingAsync<T>(string key, T defaultValue)
        {
            var config = await GetConfigAsync();
            
            return key.ToLower() switch
            {
                "output_format" => (T)(object)config.OutputFormat,
                "scan_timeout" => (T)(object)config.ScanTimeoutSeconds,
                "max_concurrent_scans" => (T)(object)config.MaxConcurrentScans,
                _ => defaultValue
            };
        }

        public async Task SetSettingAsync<T>(string key, T value)
        {
            var config = await GetConfigAsync();
            
            switch (key.ToLower())
            {
                case "output_format":
                    config.OutputFormat = value?.ToString() ?? "table";
                    break;
                case "scan_timeout":
                    if (int.TryParse(value?.ToString(), out var timeout))
                        config.ScanTimeoutSeconds = timeout;
                    break;
                case "max_concurrent_scans":
                    if (int.TryParse(value?.ToString(), out var maxScans))
                        config.MaxConcurrentScans = maxScans;
                    break;
            }
            
            await SaveConfigAsync(config);
        }
    }
}