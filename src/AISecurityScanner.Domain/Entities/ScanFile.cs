using System;
using System.ComponentModel.DataAnnotations;

namespace AISecurityScanner.Domain.Entities
{
    public class ScanFile : BaseEntity
    {
        [Required]
        public Guid SecurityScanId { get; set; }
        
        [Required]
        [MaxLength(500)]
        public string FilePath { get; set; } = string.Empty;
        
        [MaxLength(50)]
        public string? Language { get; set; }
        
        public long TotalLines { get; set; }
        public long AIGeneratedLines { get; set; }
        public decimal AIPercentage { get; set; }
        
        public int VulnerabilitiesFound { get; set; }
        
        public bool HasAISignatures { get; set; }
        
        [MaxLength(1000)]
        public string? AISignatureDetails { get; set; }
        
        public virtual SecurityScan SecurityScan { get; set; } = null!;
    }
}