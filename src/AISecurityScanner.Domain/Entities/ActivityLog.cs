using System;
using System.ComponentModel.DataAnnotations;

namespace AISecurityScanner.Domain.Entities
{
    public class ActivityLog : BaseEntity
    {
        [Required]
        public Guid UserId { get; set; }
        
        [Required]
        public Guid OrganizationId { get; set; }
        
        [Required]
        [MaxLength(100)]
        public string Action { get; set; } = string.Empty;
        
        [Required]
        [MaxLength(100)]
        public string EntityType { get; set; } = string.Empty;
        
        public Guid? EntityId { get; set; }
        
        [MaxLength(2000)]
        public string? Details { get; set; }
        
        [MaxLength(45)]
        public string? IpAddress { get; set; }
        
        [MaxLength(500)]
        public string? UserAgent { get; set; }
        
        public virtual User User { get; set; } = null!;
        public virtual Organization Organization { get; set; } = null!;
    }
}