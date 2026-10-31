using Auth.Application.DTOs;
using Auth.Application.Interfaces;
using Auth.Domain.Entities;
using Auth.Infrastructure.Options;
using ERPApp.Shared.Abstractions.Cryptography;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Auth.Infrastructure.Services;

public class AuthService(
    AuthDbContext context,
    IPasswordHasher<AspNetUser> passwordHasher,
    IPasswordHasherService legacyHasher,
    IUserPermissionService permissionService,
    JwtTokenService tokenService,
    IOptions<AuthLockoutOptions> lockoutOptions,
    TimeProvider timeProvider) : IAuthService
{
    private readonly AuthLockoutOptions _lockout = lockoutOptions.Value;

    private DateTime UtcNow => timeProvider.GetUtcNow().UtcDateTime;

    public async Task<AuthResult> LoginAsync(LoginRequestDto request, string? ipAddress, CancellationToken cancellationToken = default)
    {
        var user = await context.AspNetUsers
            .FirstOrDefaultAsync(u => u.UserName == request.UserName, cancellationToken);
        if (user == null)
            return AuthResult.Failure(AuthError.InvalidCredentials);

        var now = UtcNow;
        if (user.IsLockedOut(now))
            return AuthResult.Failure(AuthError.LockedOut);

        if (!IsPasswordValid(user, request.Password))
        {
            user.RegisterFailedLogin(now, _lockout.MaxFailedAttempts, TimeSpan.FromMinutes(_lockout.LockoutMinutes));
            await context.SaveChangesAsync(cancellationToken);
            return AuthResult.Failure(user.IsLockedOut(now) ? AuthError.LockedOut : AuthError.InvalidCredentials);
        }

        if (user.AccessFailedCount != 0 || user.LockoutEndDateUtc != null)
            user.RegisterSuccessfulLogin();

        var userControl = await context.UserControls.FirstOrDefaultAsync(u => u.Id == user.Id, cancellationToken);
        if (userControl == null || userControl.IsActive != true)
        {
            await context.SaveChangesAsync(cancellationToken);
            return AuthResult.Failure(AuthError.InactiveUser);
        }

        var dept = await context.Departments.FirstOrDefaultAsync(d => d.DeptId == userControl.DeptId, cancellationToken);
        if (dept == null)
        {
            await context.SaveChangesAsync(cancellationToken);
            return AuthResult.Failure(AuthError.InactiveUser);
        }

        return AuthResult.Success(await IssueTokensAsync(user, userControl, dept.DeptId, Guid.NewGuid(), ipAddress, cancellationToken));
    }

    public async Task<AuthResult> RefreshAsync(string refreshToken, string? ipAddress, CancellationToken cancellationToken = default)
    {
        var hash = JwtTokenService.HashRefreshToken(refreshToken);
        var stored = await context.RefreshTokens.FirstOrDefaultAsync(t => t.TokenHash == hash, cancellationToken);
        if (stored == null)
            return AuthResult.Failure(AuthError.InvalidRefreshToken);

        var now = UtcNow;
        if (!stored.IsActive(now))
        {
            // A rotated-out token being presented again means it was likely stolen: kill the whole session.
            if (stored.ReplacedByTokenId != null)
            {
                await RevokeFamilyAsync(stored.TokenFamily, "ReuseDetected", cancellationToken);
                await context.SaveChangesAsync(cancellationToken);
            }
            return AuthResult.Failure(AuthError.InvalidRefreshToken);
        }

        var userControl = await context.UserControls.FirstOrDefaultAsync(u => u.UserId == stored.UserId, cancellationToken);
        var user = userControl == null
            ? null
            : await context.AspNetUsers.FirstOrDefaultAsync(u => u.Id == userControl.Id, cancellationToken);
        var dept = userControl == null
            ? null
            : await context.Departments.FirstOrDefaultAsync(d => d.DeptId == userControl.DeptId, cancellationToken);

        if (userControl?.IsActive != true || user == null || user.IsLockedOut(now) || dept == null)
        {
            await RevokeFamilyAsync(stored.TokenFamily, "UserInactive", cancellationToken);
            await context.SaveChangesAsync(cancellationToken);
            return AuthResult.Failure(AuthError.InvalidRefreshToken);
        }

        var response = await IssueTokensAsync(user, userControl, dept.DeptId, stored.TokenFamily, ipAddress, cancellationToken,
            onCreated: newToken => stored.Revoke(now, "Rotated", newToken.Id));
        return AuthResult.Success(response);
    }

    public async Task LogoutAsync(string refreshToken, string userId, CancellationToken cancellationToken = default)
    {
        var hash = JwtTokenService.HashRefreshToken(refreshToken);
        var stored = await context.RefreshTokens
            .FirstOrDefaultAsync(t => t.TokenHash == hash && t.UserId == userId, cancellationToken);
        if (stored == null)
            return;

        await RevokeFamilyAsync(stored.TokenFamily, "Logout", cancellationToken);
        await context.SaveChangesAsync(cancellationToken);
    }

    public async Task<CurrentUserDto?> GetCurrentUserAsync(string userId, CancellationToken cancellationToken = default)
    {
        var userControl = await context.UserControls.FirstOrDefaultAsync(u => u.UserId == userId, cancellationToken);
        if (userControl == null || userControl.IsActive != true)
            return null;

        var user = await context.AspNetUsers.FirstOrDefaultAsync(u => u.Id == userControl.Id, cancellationToken);
        if (user == null)
            return null;

        return new CurrentUserDto
        {
            UserId = userControl.UserId,
            UserName = user.UserName,
            FullName = userControl.FullName,
            Role = userControl.UserRoleID,
            Department = userControl.DeptId,
            Permissions = await permissionService.GetUserPermissionsAsync(userControl.UserId)
        };
    }

    public async Task<bool> ValidateUserAsync(string userId)
    {
        var user = await context.UserControls.FirstOrDefaultAsync(u => u.Id == userId);
        return user != null && user.IsActive == true;
    }

    private bool IsPasswordValid(AspNetUser user, string password)
    {
        var result = passwordHasher.VerifyHashedPassword(user, user.PasswordHash ?? "", password);
        if (result is PasswordVerificationResult.Success or PasswordVerificationResult.SuccessRehashNeeded)
            return true;

        // Legacy SHA256 hashes from the old system.
        return legacyHasher.Sha256Hash(password) == user.PasswordHash;
    }

    private async Task<LoginResponseDto> IssueTokensAsync(
        AspNetUser user, UserControl userControl, string departmentId, Guid tokenFamily, string? ipAddress,
        CancellationToken cancellationToken, Action<RefreshToken>? onCreated = null)
    {
        var (accessToken, accessExpires) = tokenService.CreateAccessToken(userControl, departmentId);
        var (rawRefresh, refreshEntity) = tokenService.CreateRefreshToken(userControl.UserId, tokenFamily, ipAddress);

        context.RefreshTokens.Add(refreshEntity);
        onCreated?.Invoke(refreshEntity);
        await context.SaveChangesAsync(cancellationToken);

        return new LoginResponseDto
        {
            Token = accessToken,
            TokenExpiresAtUtc = accessExpires,
            RefreshToken = rawRefresh,
            RefreshTokenExpiresAtUtc = refreshEntity.ExpiresAtUtc,
            UserId = userControl.UserId,
            UserName = user.UserName,
            FullName = userControl.FullName,
            Role = userControl.UserRoleID,
            Department = departmentId
        };
    }

    private async Task RevokeFamilyAsync(Guid tokenFamily, string reason, CancellationToken cancellationToken)
    {
        var now = UtcNow;
        var active = await context.RefreshTokens
            .Where(t => t.TokenFamily == tokenFamily && t.RevokedAtUtc == null)
            .ToListAsync(cancellationToken);

        foreach (var token in active)
            token.Revoke(now, reason);
    }
}
