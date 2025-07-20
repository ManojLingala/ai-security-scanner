using System;
using System.ComponentModel.DataAnnotations;

namespace AISecurityScanner.Domain.Entities
{
    public class RepositoryConfiguration : BaseEntity
    {
        [Required]
        public Guid RepositoryId { get; set; }
        
        [Required]
        [MaxLength(100)]
        public string Key { get; set; } = string.Empty;
        
        [Required]
        [MaxLength(1000)]
        public string Value { get; set; } = string.Empty;
        
        [MaxLength(500)]
        public string? Description { get; set; }
        
        public virtual Repository Repository { get; set; } = null!;
    }
}