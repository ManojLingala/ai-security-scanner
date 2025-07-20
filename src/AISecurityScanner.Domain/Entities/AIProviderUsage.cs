using System;
using System.ComponentModel.DataAnnotations;

namespace AISecurityScanner.Domain.Entities
{
    public class AIProviderUsage : BaseEntity
    {
        [Required]
        public Guid AIProviderId { get; set; }
        
        [Required]
        public Guid OrganizationId { get; set; }
        
        public Guid? SecurityScanId { get; set; }
        
        public DateTime RequestedAt { get; set; }
        public DateTime? CompletedAt { get; set; }
        
        public bool IsSuccessful { get; set; }
        
        [MaxLength(500)]
        public string? ErrorMessage { get; set; }
        
        public int TokensUsed { get; set; }
        public decimal Cost { get; set; }
        
        public TimeSpan? ResponseTime { get; set; }
        
        [MaxLength(100)]
        public string? RequestType { get; set; }
        
        public virtual AIProvider AIProvider { get; set; } = null!;
        public virtual Organization Organization { get; set; } = null!;
        public virtual SecurityScan? SecurityScan { get; set; }
    }
}