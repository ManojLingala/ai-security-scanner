using Microsoft.AspNetCore.Mvc;

namespace AISecurityScanner.API.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class HealthController : ControllerBase
    {
        [HttpGet]
        public IActionResult Get()
        {
            return Ok(new { 
                Status = "Healthy", 
                Timestamp = DateTime.UtcNow,
                Message = "AI Security Scanner API is running successfully!"
            });
        }

        [HttpGet("test")]
        public IActionResult Test()
        {
            return Ok("API is working!");
        }
    }
}