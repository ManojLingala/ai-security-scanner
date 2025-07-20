using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace AISecurityScanner.Domain.Entities
{
    public class Repository : BaseEntity
    {
        [Required]
        [MaxLength(200)]
        public string Name { get; set; } = string.Empty;
        
        [Required]
        [MaxLength(500)]
        public string GitUrl { get; set; } = string.Empty;
        
        [Required]
        public Guid OrganizationId { get; set; }
        
        [MaxLength(50)]
        public string Language { get; set; } = string.Empty;
        
        public DateTime? LastScanAt { get; set; }
        public int TotalScans { get; set; }
        public decimal AICodePercentage { get; set; }
        
        [MaxLength(100)]
        public string? DefaultBranch { get; set; } = "main";
        
        [MaxLength(500)]
        public string? WebhookUrl { get; set; }
        
        [MaxLength(100)]
        public string? WebhookSecret { get; set; }
        
        public bool IsPrivate { get; set; } = true;
        public bool AutoScanEnabled { get; set; }
        
        [MaxLength(100)]
        public string? GitHubInstallationId { get; set; }
        
        public long TotalLinesOfCode { get; set; }
        public long AIGeneratedLines { get; set; }
        
        public virtual Organization Organization { get; set; } = null!;
        public virtual ICollection<SecurityScan> SecurityScans { get; set; } = new List<SecurityScan>();
        public virtual ICollection<RepositoryConfiguration> Configurations { get; set; } = new List<RepositoryConfiguration>();
    }
}