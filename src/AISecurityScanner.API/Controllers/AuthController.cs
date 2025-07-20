using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using AISecurityScanner.Application.Interfaces;
using AISecurityScanner.Application.DTOs;
using AISecurityScanner.Application.Models;

namespace AISecurityScanner.API.Controllers
{
    public class AuthController : BaseController
    {
        private readonly ITeamManagementService _teamService;
        private readonly IConfiguration _configuration;
        private readonly ILogger<AuthController> _logger;

        public AuthController(
            ITeamManagementService teamService,
            IConfiguration configuration,
            ILogger<AuthController> logger)
        {
            _teamService = teamService;
            _configuration = configuration;
            _logger = logger;
        }

        /// <summary>
        /// Authenticate user and return JWT token
        /// </summary>
        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login([FromBody] LoginRequest request, CancellationToken cancellationToken)
        {
            try
            {
                // In a real implementation, you would validate credentials against your user store
                // For demo purposes, we'll create a mock authentication
                
                if (string.IsNullOrEmpty(request.Email) || string.IsNullOrEmpty(request.Password))
                {
                    return BadRequest(new { message = "Email and password are required" });
                }

                // Mock user validation - replace with real authentication logic
                var user = await ValidateUserCredentials(request.Email, request.Password, cancellationToken);
                
                if (user == null)
                {
                    return Unauthorized(new { message = "Invalid credentials" });
                }

                var token = GenerateJwtToken(user);
                
                return Ok(new LoginResponse
                {
                    Token = token,
                    ExpiresAt = DateTime.UtcNow.AddMinutes(_configuration.GetValue<int>("Jwt:ExpirationMinutes")),
                    User = user
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during login for user {Email}", request.Email);
                return HandleException(ex);
            }
        }

        /// <summary>
        /// Register a new user
        /// </summary>
        [HttpPost("register")]
        [AllowAnonymous]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request, CancellationToken cancellationToken)
        {
            try
            {
                // In a real implementation, you would hash the password and store the user
                // For demo purposes, we'll create a mock registration
                
                var createUserRequest = new CreateUserRequest
                {
                    Email = request.Email,
                    FirstName = request.FirstName,
                    LastName = request.LastName,
                    Role = Domain.Enums.UserRole.Developer, // Default role
                    OrganizationId = request.OrganizationId
                };

                var user = await _teamService.CreateUserAsync(createUserRequest, cancellationToken);
                
                return CreatedAtAction(nameof(GetProfile), null, new { message = "User registered successfully", userId = user.Id });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during registration for user {Email}", request.Email);
                return HandleException(ex);
            }
        }

        /// <summary>
        /// Get current user profile
        /// </summary>
        [HttpGet("profile")]
        [Authorize]
        public async Task<IActionResult> GetProfile(CancellationToken cancellationToken)
        {
            try
            {
                var userId = GetCurrentUserId();
                if (userId == Guid.Empty)
                {
                    return Unauthorized();
                }

                var user = await _teamService.GetUserAsync(userId, cancellationToken);
                return HandleResult(user);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving user profile");
                return HandleException(ex);
            }
        }

        /// <summary>
        /// Refresh JWT token
        /// </summary>
        [HttpPost("refresh")]
        [Authorize]
        public async Task<IActionResult> RefreshToken(CancellationToken cancellationToken)
        {
            try
            {
                var userId = GetCurrentUserId();
                if (userId == Guid.Empty)
                {
                    return Unauthorized();
                }

                var user = await _teamService.GetUserAsync(userId, cancellationToken);
                if (user == null)
                {
                    return Unauthorized();
                }

                var token = GenerateJwtToken(user);
                
                return Ok(new { 
                    token, 
                    expiresAt = DateTime.UtcNow.AddMinutes(_configuration.GetValue<int>("Jwt:ExpirationMinutes"))
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error refreshing token");
                return HandleException(ex);
            }
        }

        /// <summary>
        /// Logout user (client-side token invalidation)
        /// </summary>
        [HttpPost("logout")]
        [Authorize]
        public IActionResult Logout()
        {
            // In a stateless JWT system, logout is typically handled client-side
            // by removing the token. For server-side invalidation, you would need
            // to maintain a blacklist of tokens or use shorter expiration times
            
            return Ok(new { message = "Logged out successfully" });
        }

        private async Task<UserDto?> ValidateUserCredentials(string email, string password, CancellationToken cancellationToken)
        {
            // Mock implementation - replace with real credential validation
            // This should hash the password and check against your user store
            
            if (email == "demo@aisecurityscanner.com" && password == "demo123")
            {
                return new UserDto
                {
                    Id = Guid.Parse("11111111-1111-1111-1111-111111111111"),
                    Email = email,
                    FirstName = "Demo",
                    LastName = "User",
                    FullName = "Demo User",
                    Role = Domain.Enums.UserRole.Admin,
                    OrganizationId = Guid.Parse("22222222-2222-2222-2222-222222222222"),
                    OrganizationName = "Demo Organization",
                    IsActive = true,
                    CreatedAt = DateTime.UtcNow.AddDays(-30)
                };
            }

            return null;
        }

        private string GenerateJwtToken(UserDto user)
        {
            var jwtConfig = _configuration.GetSection("Jwt");
            var key = Encoding.UTF8.GetBytes(jwtConfig["Secret"] ?? throw new InvalidOperationException("JWT Secret not configured"));
            
            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.Name, user.FullName),
                new Claim(ClaimTypes.Role, user.Role.ToString()),
                new Claim("OrganizationId", user.OrganizationId.ToString()),
                new Claim("OrganizationName", user.OrganizationName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
            };

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddMinutes(jwtConfig.GetValue<int>("ExpirationMinutes")),
                Issuer = jwtConfig["Issuer"],
                Audience = jwtConfig["Audience"],
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);
            
            return tokenHandler.WriteToken(token);
        }
    }

    public class LoginRequest
    {
        public string Email { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public bool RememberMe { get; set; }
    }

    public class RegisterRequest
    {
        public string Email { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public string FirstName { get; set; } = string.Empty;
        public string LastName { get; set; } = string.Empty;
        public Guid OrganizationId { get; set; }
    }

    public class LoginResponse
    {
        public string Token { get; set; } = string.Empty;
        public DateTime ExpiresAt { get; set; }
        public UserDto User { get; set; } = null!;
    }
}