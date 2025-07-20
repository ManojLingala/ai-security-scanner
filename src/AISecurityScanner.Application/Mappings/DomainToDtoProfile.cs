using AutoMapper;
using AISecurityScanner.Domain.Entities;
using AISecurityScanner.Application.DTOs;
using AISecurityScanner.Application.Interfaces;

namespace AISecurityScanner.Application.Mappings
{
    public class DomainToDtoProfile : Profile
    {
        public DomainToDtoProfile()
        {
            CreateMap<Organization, OrganizationDto>();
            
            CreateMap<User, UserDto>()
                .ForMember(dest => dest.FullName, opt => opt.MapFrom(src => $"{src.FirstName} {src.LastName}"));
            
            CreateMap<Repository, RepositoryDto>();
            
            CreateMap<SecurityScan, SecurityScanDto>();
            
            CreateMap<Vulnerability, VulnerabilityDto>();
            
            CreateMap<AIProvider, AIProviderDto>();
            
            CreateMap<ActivityLog, ActivityLogDto>()
                .ForMember(dest => dest.UserName, opt => opt.MapFrom(src => src.User != null ? $"{src.User.FirstName} {src.User.LastName}" : "Unknown"));
            
            CreateMap<PackageVulnerability, PackageVulnerabilityDto>();
        }
    }
}