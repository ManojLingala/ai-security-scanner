using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace AISecurityScanner.Domain.Entities
{
    public class AIProvider : BaseEntity
    {
        [Required]
        [MaxLength(100)]
        public string Name { get; set; } = string.Empty;
        
        [Required]
        [MaxLength(500)]
        public string ApiEndpoint { get; set; } = string.Empty;
        
        public bool IsActive { get; set; } = true;
        
        public decimal CostPerRequest { get; set; }
        
        [MaxLength(100)]
        public string? Model { get; set; }
        
        public int MaxTokens { get; set; } = 4096;
        public int TimeoutSeconds { get; set; } = 30;
        
        public int RateLimitPerMinute { get; set; } = 60;
        public int RateLimitPerHour { get; set; } = 1000;
        
        [MaxLength(2000)]
        public string? Configuration { get; set; }
        
        public bool SupportsCodeAnalysis { get; set; } = true;
        public bool SupportsPackageValidation { get; set; } = true;
        
        public int Priority { get; set; } = 1;
        
        public TimeSpan AverageResponseTime { get; set; }
        public decimal SuccessRate { get; set; } = 1.0m;
        
        public DateTime? LastHealthCheckAt { get; set; }
        public bool IsHealthy { get; set; } = true;
        
        [MaxLength(500)]
        public string? HealthCheckError { get; set; }
        
        public virtual ICollection<AIProviderUsage> UsageRecords { get; set; } = new List<AIProviderUsage>();
    }
}