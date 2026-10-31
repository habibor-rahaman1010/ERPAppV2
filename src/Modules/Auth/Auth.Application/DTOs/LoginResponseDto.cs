namespace Auth.Application.DTOs;

public class LoginResponseDto
{
    /// <summary>JWT access token.</summary>
    public string Token { get; set; } = default!;
    public DateTime TokenExpiresAtUtc { get; set; }
    public string RefreshToken { get; set; } = default!;
    public DateTime RefreshTokenExpiresAtUtc { get; set; }
    public string UserId { get; set; } = default!;
    public string UserName { get; set; } = default!;
    public string? FullName { get; set; }
    public string? Role { get; set; }
    public string? Department { get; set; }
}
