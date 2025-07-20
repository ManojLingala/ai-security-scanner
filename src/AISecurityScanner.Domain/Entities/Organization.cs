using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using AISecurityScanner.Domain.Enums;

namespace AISecurityScanner.Domain.Entities
{
    public class Organization : BaseEntity
    {
        [Required]
        [MaxLength(200)]
        public string Name { get; set; } = string.Empty;
        
        [Required]
        public OrganizationPlan Plan { get; set; }
        
        public bool IsActive { get; set; } = true;
        
        [MaxLength(100)]
        public string? StripeCustomerId { get; set; }
        
        [MaxLength(100)]
        public string? StripeSubscriptionId { get; set; }
        
        public DateTime? SubscriptionStartDate { get; set; }
        public DateTime? SubscriptionEndDate { get; set; }
        
        public int TeamSizeLimit { get; set; } = 5;
        public int MonthlyScansLimit { get; set; } = 100;
        public int RepositoriesLimit { get; set; } = 10;
        
        public long CurrentMonthScans { get; set; }
        public DateTime? LastScanResetDate { get; set; }
        
        [MaxLength(500)]
        public string? BillingEmail { get; set; }
        
        [MaxLength(500)]
        public string? BillingAddress { get; set; }
        
        public virtual ICollection<User> Users { get; set; } = new List<User>();
        public virtual ICollection<Repository> Repositories { get; set; } = new List<Repository>();
        public virtual ICollection<ApiKey> ApiKeys { get; set; } = new List<ApiKey>();
    }
}