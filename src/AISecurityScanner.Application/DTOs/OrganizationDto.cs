using System;
using AISecurityScanner.Domain.Enums;

namespace AISecurityScanner.Application.DTOs
{
    public class OrganizationDto
    {
        public Guid Id { get; set; }
        public string Name { get; set; } = string.Empty;
        public OrganizationPlan Plan { get; set; }
        public bool IsActive { get; set; }
        public int TeamSizeLimit { get; set; }
        public int MonthlyScansLimit { get; set; }
        public int RepositoriesLimit { get; set; }
        public long CurrentMonthScans { get; set; }
        public DateTime? LastScanResetDate { get; set; }
        public string? BillingEmail { get; set; }
        public DateTime CreatedAt { get; set; }
        
        // Usage metrics
        public int CurrentUserCount { get; set; }
        public int CurrentRepositoryCount { get; set; }
        public decimal UsagePercentage => MonthlyScansLimit > 0 ? (decimal)CurrentMonthScans / MonthlyScansLimit * 100 : 0;
    }
}