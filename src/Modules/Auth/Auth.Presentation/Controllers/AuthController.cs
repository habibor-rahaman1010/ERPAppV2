using System.Security.Claims;
using Auth.Application.DTOs;
using Auth.Application.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace Auth.Presentation.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController(IAuthService authService, ILogger<AuthController> logger) : ControllerBase
{
    private string? ClientIp => HttpContext.Connection.RemoteIpAddress?.ToString();

    [AllowAnonymous]
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequestDto request, CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var result = await authService.LoginAsync(request, ClientIp, cancellationToken);
        if (result.Succeeded)
            return Ok(result.Data);

        logger.LogWarning("Login failed for username: {Username}, reason: {Reason}", request.UserName, result.Error);
        return result.Error == AuthError.LockedOut
            ? Unauthorized(new { message = "Account is temporarily locked due to repeated failed logins. Try again later." })
            : Unauthorized(new { message = "Invalid username or password" });
    }

    [AllowAnonymous]
    [HttpPost("refresh")]
    public async Task<IActionResult> Refresh([FromBody] RefreshTokenRequestDto request, CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var result = await authService.RefreshAsync(request.RefreshToken, ClientIp, cancellationToken);
        return result.Succeeded
            ? Ok(result.Data)
            : Unauthorized(new { message = "Invalid or expired refresh token" });
    }

    [Authorize]
    [HttpPost("logout")]
    public async Task<IActionResult> Logout([FromBody] RefreshTokenRequestDto request, CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        await authService.LogoutAsync(request.RefreshToken, User.FindFirstValue(ClaimTypes.NameIdentifier)!, cancellationToken);
        return NoContent();
    }

    [Authorize]
    [HttpGet("me")]
    [ProducesResponseType<CurrentUserDto>(StatusCodes.Status200OK)]
    public async Task<IActionResult> Me(CancellationToken cancellationToken)
    {
        var user = await authService.GetCurrentUserAsync(User.FindFirstValue(ClaimTypes.NameIdentifier)!, cancellationToken);
        return user == null ? Unauthorized() : Ok(user);
    }
}
