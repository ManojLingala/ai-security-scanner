using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AutoMapper;
using Microsoft.Extensions.Logging;
using AISecurityScanner.Application.DTOs;
using AISecurityScanner.Application.Interfaces;
using AISecurityScanner.Application.Models;
using AISecurityScanner.Domain.Entities;
using AISecurityScanner.Domain.Interfaces;

namespace AISecurityScanner.Application.Services
{
    public class TeamManagementService : ITeamManagementService
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMapper _mapper;
        private readonly ILogger<TeamManagementService> _logger;

        public TeamManagementService(
            IUnitOfWork unitOfWork,
            IMapper mapper,
            ILogger<TeamManagementService> logger)
        {
            _unitOfWork = unitOfWork;
            _mapper = mapper;
            _logger = logger;
        }

        public async Task<OrganizationDto?> GetOrganizationAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            var organization = await _unitOfWork.Organizations.GetByIdAsync(organizationId, cancellationToken);
            if (organization == null) return null;

            var orgDto = _mapper.Map<OrganizationDto>(organization);
            
            // Add usage metrics
            orgDto.CurrentUserCount = await _unitOfWork.Users.CountAsync(
                u => u.OrganizationId == organizationId && u.IsActive, cancellationToken);
            
            orgDto.CurrentRepositoryCount = await _unitOfWork.Repositories.CountAsync(
                r => r.OrganizationId == organizationId, cancellationToken);

            return orgDto;
        }

        public async Task<PagedResult<UserDto>> GetOrganizationUsersAsync(Guid organizationId, PaginationRequest pagination, CancellationToken cancellationToken = default)
        {
            var users = await _unitOfWork.Users.FindAsync(
                u => u.OrganizationId == organizationId,
                cancellationToken);

            if (!string.IsNullOrEmpty(pagination.SearchTerm))
            {
                users = users.Where(u =>
                    u.FirstName.Contains(pagination.SearchTerm, StringComparison.OrdinalIgnoreCase) ||
                    u.LastName.Contains(pagination.SearchTerm, StringComparison.OrdinalIgnoreCase) ||
                    u.Email.Contains(pagination.SearchTerm, StringComparison.OrdinalIgnoreCase));
            }

            var totalCount = users.Count();
            var pagedUsers = users
                .Skip((pagination.PageNumber - 1) * pagination.PageSize)
                .Take(pagination.PageSize);

            return new PagedResult<UserDto>
            {
                Items = _mapper.Map<IEnumerable<UserDto>>(pagedUsers),
                TotalCount = totalCount,
                PageNumber = pagination.PageNumber,
                PageSize = pagination.PageSize
            };
        }

        public async Task<UserDto?> GetUserAsync(Guid userId, CancellationToken cancellationToken = default)
        {
            var user = await _unitOfWork.Users.GetByIdAsync(userId, cancellationToken);
            return user != null ? _mapper.Map<UserDto>(user) : null;
        }

        public async Task<UserDto> CreateUserAsync(CreateUserRequest request, CancellationToken cancellationToken = default)
        {
            try
            {
                // Check if organization can add more users
                var canAdd = await _unitOfWork.Organizations.CanAddUserAsync(request.OrganizationId, cancellationToken);
                if (!canAdd)
                {
                    throw new InvalidOperationException("User limit exceeded for organization");
                }

                var user = new User
                {
                    Id = Guid.NewGuid(),
                    Email = request.Email,
                    FirstName = request.FirstName,
                    LastName = request.LastName,
                    Role = request.Role,
                    OrganizationId = request.OrganizationId,
                    PhoneNumber = request.PhoneNumber,
                    IsActive = true,
                    CreatedAt = DateTime.UtcNow,
                    ModifiedAt = DateTime.UtcNow
                };

                await _unitOfWork.Users.AddAsync(user, cancellationToken);
                await _unitOfWork.SaveChangesAsync(cancellationToken);

                _logger.LogInformation("User {Email} created with ID {UserId}", request.Email, user.Id);

                return _mapper.Map<UserDto>(user);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating user {Email}", request.Email);
                throw;
            }
        }

        public async Task<UserDto> UpdateUserAsync(Guid userId, UpdateUserRequest request, CancellationToken cancellationToken = default)
        {
            try
            {
                var user = await _unitOfWork.Users.GetByIdAsync(userId, cancellationToken);
                if (user == null)
                {
                    throw new ArgumentException("User not found");
                }

                if (!string.IsNullOrEmpty(request.FirstName))
                    user.FirstName = request.FirstName;

                if (!string.IsNullOrEmpty(request.LastName))
                    user.LastName = request.LastName;

                if (request.Role.HasValue)
                    user.Role = request.Role.Value;

                if (!string.IsNullOrEmpty(request.PhoneNumber))
                    user.PhoneNumber = request.PhoneNumber;

                if (request.IsActive.HasValue)
                    user.IsActive = request.IsActive.Value;

                user.ModifiedAt = DateTime.UtcNow;

                await _unitOfWork.Users.UpdateAsync(user, cancellationToken);
                await _unitOfWork.SaveChangesAsync(cancellationToken);

                _logger.LogInformation("User {UserId} updated", userId);

                return _mapper.Map<UserDto>(user);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating user {UserId}", userId);
                throw;
            }
        }

        public async Task<bool> DeactivateUserAsync(Guid userId, CancellationToken cancellationToken = default)
        {
            try
            {
                var user = await _unitOfWork.Users.GetByIdAsync(userId, cancellationToken);
                if (user == null)
                {
                    return false;
                }

                user.IsActive = false;
                user.ModifiedAt = DateTime.UtcNow;

                await _unitOfWork.Users.UpdateAsync(user, cancellationToken);
                await _unitOfWork.SaveChangesAsync(cancellationToken);

                _logger.LogInformation("User {UserId} deactivated", userId);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deactivating user {UserId}", userId);
                return false;
            }
        }

        public async Task<bool> InviteUserAsync(InviteUserRequest request, Guid invitedByUserId, CancellationToken cancellationToken = default)
        {
            try
            {
                // Check if organization can add more users
                var canAdd = await _unitOfWork.Organizations.CanAddUserAsync(request.OrganizationId, cancellationToken);
                if (!canAdd)
                {
                    return false;
                }

                // In a real implementation, you would:
                // 1. Create an invitation record
                // 2. Send an email invitation
                // 3. Generate a secure invitation token
                
                _logger.LogInformation("User invitation sent to {Email} by user {InvitedBy}", request.Email, invitedByUserId);
                
                // For demo purposes, we'll just return true
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error inviting user {Email}", request.Email);
                return false;
            }
        }

        public async Task<OrganizationUsage> GetOrganizationUsageAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            var organization = await _unitOfWork.Organizations.GetByIdAsync(organizationId, cancellationToken);
            if (organization == null)
            {
                throw new ArgumentException("Organization not found");
            }

            var currentUsers = await _unitOfWork.Users.CountAsync(
                u => u.OrganizationId == organizationId && u.IsActive, cancellationToken);
            
            var currentRepositories = await _unitOfWork.Repositories.CountAsync(
                r => r.OrganizationId == organizationId, cancellationToken);

            var scanUsagePercentage = organization.MonthlyScansLimit > 0 
                ? (decimal)organization.CurrentMonthScans / organization.MonthlyScansLimit * 100 
                : 0;
            
            var userUsagePercentage = organization.TeamSizeLimit > 0 
                ? (decimal)currentUsers / organization.TeamSizeLimit * 100 
                : 0;
            
            var repoUsagePercentage = organization.RepositoriesLimit > 0 
                ? (decimal)currentRepositories / organization.RepositoriesLimit * 100 
                : 0;

            return new OrganizationUsage
            {
                CurrentUsers = currentUsers,
                UserLimit = organization.TeamSizeLimit,
                CurrentRepositories = currentRepositories,
                RepositoryLimit = organization.RepositoriesLimit,
                CurrentMonthScans = organization.CurrentMonthScans,
                MonthlyScansLimit = organization.MonthlyScansLimit,
                ScanUsagePercentage = scanUsagePercentage,
                UserUsagePercentage = userUsagePercentage,
                RepositoryUsagePercentage = repoUsagePercentage,
                IsNearingLimits = scanUsagePercentage > 80 || userUsagePercentage > 80 || repoUsagePercentage > 80
            };
        }

        public async Task<bool> CanAddUserAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            return await _unitOfWork.Organizations.CanAddUserAsync(organizationId, cancellationToken);
        }

        public async Task<bool> CanAddRepositoryAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            return await _unitOfWork.Organizations.CanAddRepositoryAsync(organizationId, cancellationToken);
        }

        public async Task<bool> CanPerformScanAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            return await _unitOfWork.Organizations.CanPerformScanAsync(organizationId, cancellationToken);
        }

        public async Task<List<ActivityLogDto>> GetRecentActivityAsync(Guid organizationId, int limit = 50, CancellationToken cancellationToken = default)
        {
            var activities = await _unitOfWork.ActivityLogs.FindAsync(
                a => a.OrganizationId == organizationId,
                cancellationToken);

            var recentActivities = activities
                .OrderByDescending(a => a.CreatedAt)
                .Take(limit);

            return _mapper.Map<List<ActivityLogDto>>(recentActivities);
        }
    }
}