using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AISecurityScanner.Application.DTOs;
using AISecurityScanner.Application.Models;
using AISecurityScanner.Domain.Enums;

namespace AISecurityScanner.Application.Interfaces
{
    public interface ITeamManagementService
    {
        Task<OrganizationDto?> GetOrganizationAsync(Guid organizationId, CancellationToken cancellationToken = default);
        Task<PagedResult<UserDto>> GetOrganizationUsersAsync(Guid organizationId, PaginationRequest pagination, CancellationToken cancellationToken = default);
        Task<UserDto?> GetUserAsync(Guid userId, CancellationToken cancellationToken = default);
        Task<UserDto> CreateUserAsync(CreateUserRequest request, CancellationToken cancellationToken = default);
        Task<UserDto> UpdateUserAsync(Guid userId, UpdateUserRequest request, CancellationToken cancellationToken = default);
        Task<bool> DeactivateUserAsync(Guid userId, CancellationToken cancellationToken = default);
        Task<bool> InviteUserAsync(InviteUserRequest request, Guid invitedByUserId, CancellationToken cancellationToken = default);
        Task<OrganizationUsage> GetOrganizationUsageAsync(Guid organizationId, CancellationToken cancellationToken = default);
        Task<bool> CanAddUserAsync(Guid organizationId, CancellationToken cancellationToken = default);
        Task<bool> CanAddRepositoryAsync(Guid organizationId, CancellationToken cancellationToken = default);
        Task<bool> CanPerformScanAsync(Guid organizationId, CancellationToken cancellationToken = default);
        Task<List<ActivityLogDto>> GetRecentActivityAsync(Guid organizationId, int limit = 50, CancellationToken cancellationToken = default);
    }

    public class CreateUserRequest
    {
        public string Email { get; set; } = string.Empty;
        public string FirstName { get; set; } = string.Empty;
        public string LastName { get; set; } = string.Empty;
        public UserRole Role { get; set; }
        public Guid OrganizationId { get; set; }
        public string? PhoneNumber { get; set; }
    }

    public class UpdateUserRequest
    {
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public UserRole? Role { get; set; }
        public string? PhoneNumber { get; set; }
        public bool? IsActive { get; set; }
    }

    public class InviteUserRequest
    {
        public string Email { get; set; } = string.Empty;
        public string FirstName { get; set; } = string.Empty;
        public string LastName { get; set; } = string.Empty;
        public UserRole Role { get; set; }
        public Guid OrganizationId { get; set; }
        public string? Message { get; set; }
    }

    public class OrganizationUsage
    {
        public int CurrentUsers { get; set; }
        public int UserLimit { get; set; }
        public int CurrentRepositories { get; set; }
        public int RepositoryLimit { get; set; }
        public long CurrentMonthScans { get; set; }
        public long MonthlyScansLimit { get; set; }
        public decimal ScanUsagePercentage { get; set; }
        public decimal UserUsagePercentage { get; set; }
        public decimal RepositoryUsagePercentage { get; set; }
        public bool IsNearingLimits { get; set; }
    }

    public class ActivityLogDto
    {
        public Guid Id { get; set; }
        public Guid UserId { get; set; }
        public string UserName { get; set; } = string.Empty;
        public string Action { get; set; } = string.Empty;
        public string EntityType { get; set; } = string.Empty;
        public Guid? EntityId { get; set; }
        public string? Details { get; set; }
        public string? IpAddress { get; set; }
        public DateTime CreatedAt { get; set; }
    }
}