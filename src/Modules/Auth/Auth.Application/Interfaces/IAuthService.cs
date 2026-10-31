using Auth.Application.DTOs;

namespace Auth.Application.Interfaces;

public interface IAuthService
{
    Task<AuthResult> LoginAsync(LoginRequestDto request, string? ipAddress, CancellationToken cancellationToken = default);
    Task<AuthResult> RefreshAsync(string refreshToken, string? ipAddress, CancellationToken cancellationToken = default);
    Task LogoutAsync(string refreshToken, string userId, CancellationToken cancellationToken = default);
    Task<CurrentUserDto?> GetCurrentUserAsync(string userId, CancellationToken cancellationToken = default);
    Task<bool> ValidateUserAsync(string userId);
}
