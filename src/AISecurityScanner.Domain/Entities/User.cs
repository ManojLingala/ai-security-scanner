using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using AISecurityScanner.Domain.Enums;

namespace AISecurityScanner.Domain.Entities
{
    public class User : BaseEntity
    {
        [Required]
        [EmailAddress]
        [MaxLength(256)]
        public string Email { get; set; } = string.Empty;
        
        [Required]
        [MaxLength(100)]
        public string FirstName { get; set; } = string.Empty;
        
        [Required]
        [MaxLength(100)]
        public string LastName { get; set; } = string.Empty;
        
        public string FullName => $"{FirstName} {LastName}";
        
        [Required]
        public UserRole Role { get; set; }
        
        [Required]
        public Guid OrganizationId { get; set; }
        
        public DateTime? LastLoginAt { get; set; }
        public bool IsActive { get; set; } = true;
        
        [MaxLength(500)]
        public string? ProfilePictureUrl { get; set; }
        
        [MaxLength(20)]
        public string? PhoneNumber { get; set; }
        
        public bool TwoFactorEnabled { get; set; }
        
        [MaxLength(100)]
        public string? ExternalId { get; set; }
        
        [MaxLength(50)]
        public string? ExternalProvider { get; set; }
        
        public virtual Organization Organization { get; set; } = null!;
        public virtual ICollection<SecurityScan> InitiatedScans { get; set; } = new List<SecurityScan>();
        public virtual ICollection<ActivityLog> Activities { get; set; } = new List<ActivityLog>();
    }
}