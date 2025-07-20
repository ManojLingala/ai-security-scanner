using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace AISecurityScanner.API.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public abstract class BaseController : ControllerBase
    {
        protected Guid GetCurrentUserId()
        {
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            return Guid.TryParse(userIdClaim, out var userId) ? userId : Guid.Empty;
        }

        protected Guid GetCurrentOrganizationId()
        {
            var orgIdClaim = User.FindFirst("OrganizationId")?.Value;
            return Guid.TryParse(orgIdClaim, out var orgId) ? orgId : Guid.Empty;
        }

        protected string GetCurrentUserRole()
        {
            return User.FindFirst(ClaimTypes.Role)?.Value ?? "Viewer";
        }

        protected IActionResult HandleResult<T>(T? result, string? errorMessage = null)
        {
            if (result == null)
            {
                return NotFound(new { message = errorMessage ?? "Resource not found" });
            }

            return Ok(result);
        }

        protected IActionResult HandleException(Exception ex)
        {
            // Log the exception here
            return StatusCode(500, new { message = "An internal server error occurred" });
        }
    }
}