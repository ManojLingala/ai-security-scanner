using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using AISecurityScanner.Domain.Enums;

namespace AISecurityScanner.Domain.Entities
{
    public class SecurityScan : BaseEntity
    {
        [Required]
        public Guid RepositoryId { get; set; }
        
        [Required]
        public Guid UserId { get; set; }
        
        public DateTime StartedAt { get; set; }
        public DateTime? CompletedAt { get; set; }
        
        [Required]
        public ScanStatus Status { get; set; }
        
        [Required]
        public ScanType ScanType { get; set; }
        
        [MaxLength(100)]
        public string? TriggerSource { get; set; }
        
        [MaxLength(100)]
        public string? Branch { get; set; }
        
        [MaxLength(100)]
        public string? CommitHash { get; set; }
        
        public long TotalLinesScanned { get; set; }
        public long AILinesDetected { get; set; }
        public TimeSpan? ScanDuration { get; set; }
        
        [MaxLength(100)]
        public string? AIProviderUsed { get; set; }
        
        public int VulnerabilitiesFound { get; set; }
        public int CriticalCount { get; set; }
        public int HighCount { get; set; }
        public int MediumCount { get; set; }
        public int LowCount { get; set; }
        public int InfoCount { get; set; }
        
        [MaxLength(1000)]
        public string? ErrorMessage { get; set; }
        
        public virtual Repository Repository { get; set; } = null!;
        public virtual User User { get; set; } = null!;
        public virtual ICollection<Vulnerability> Vulnerabilities { get; set; } = new List<Vulnerability>();
        public virtual ICollection<ScanFile> ScannedFiles { get; set; } = new List<ScanFile>();
    }
}