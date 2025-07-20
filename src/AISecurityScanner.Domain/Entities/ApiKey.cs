using System;
using System.ComponentModel.DataAnnotations;

namespace AISecurityScanner.Domain.Entities
{
    public class ApiKey : BaseEntity
    {
        [Required]
        [MaxLength(100)]
        public string Name { get; set; } = string.Empty;
        
        [Required]
        [MaxLength(100)]
        public string KeyHash { get; set; } = string.Empty;
        
        [Required]
        [MaxLength(10)]
        public string KeyPrefix { get; set; } = string.Empty;
        
        [Required]
        public Guid OrganizationId { get; set; }
        
        public DateTime? ExpiresAt { get; set; }
        public DateTime? LastUsedAt { get; set; }
        
        public bool IsActive { get; set; } = true;
        
        [MaxLength(500)]
        public string? Scopes { get; set; }
        
        [MaxLength(500)]
        public string? AllowedIPs { get; set; }
        
        public int UsageCount { get; set; }
        
        public virtual Organization Organization { get; set; } = null!;
    }
}