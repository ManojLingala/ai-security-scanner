using System;

namespace AISecurityScanner.Application.DTOs
{
    public class AIProviderDto
    {
        public Guid Id { get; set; }
        public string Name { get; set; } = string.Empty;
        public string ApiEndpoint { get; set; } = string.Empty;
        public bool IsActive { get; set; }
        public decimal CostPerRequest { get; set; }
        public string? Model { get; set; }
        public int MaxTokens { get; set; }
        public int TimeoutSeconds { get; set; }
        public int RateLimitPerMinute { get; set; }
        public int RateLimitPerHour { get; set; }
        public bool SupportsCodeAnalysis { get; set; }
        public bool SupportsPackageValidation { get; set; }
        public int Priority { get; set; }
        public TimeSpan AverageResponseTime { get; set; }
        public decimal SuccessRate { get; set; }
        public DateTime? LastHealthCheckAt { get; set; }
        public bool IsHealthy { get; set; }
        public string? HealthCheckError { get; set; }
    }
}