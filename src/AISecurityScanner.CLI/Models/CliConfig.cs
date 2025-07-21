using System.Text.Json.Serialization;

namespace AISecurityScanner.CLI.Models
{
    public class CliConfig
    {
        [JsonPropertyName("claude_token")]
        public string? ClaudeToken { get; set; }
        
        [JsonPropertyName("openai_token")]
        public string? OpenAIToken { get; set; }
        
        [JsonPropertyName("output_format")]
        public string OutputFormat { get; set; } = "table";
        
        [JsonPropertyName("scan_timeout")]
        public int ScanTimeoutSeconds { get; set; } = 300;
        
        [JsonPropertyName("max_concurrent_scans")]
        public int MaxConcurrentScans { get; set; } = 3;
        
        [JsonPropertyName("compliance_frameworks")]
        public List<string> EnabledComplianceFrameworks { get; set; } = new();
        
        [JsonPropertyName("last_login")]
        public DateTime? LastLogin { get; set; }
        
        [JsonPropertyName("user_consent_given")]
        public bool UserConsentGiven { get; set; }
    }
}