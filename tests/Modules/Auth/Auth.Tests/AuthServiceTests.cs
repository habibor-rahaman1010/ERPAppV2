using Auth.Application.DTOs;
using Auth.Domain.Entities;
using Auth.Infrastructure;
using Auth.Infrastructure.Options;
using Auth.Infrastructure.Services;
using ERPApp.Shared.Services.Cryptography;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Time.Testing;

namespace Auth.Tests;

public class AuthServiceTests
{
    private const string Password = "P@ssw0rd!";
    private readonly FakeTimeProvider _time = new(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
    private readonly AuthDbContext _db;
    private readonly AuthService _sut;

    public AuthServiceTests()
    {
        _db = new AuthDbContext(new DbContextOptionsBuilder<AuthDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString()).Options);

        var jwt = Microsoft.Extensions.Options.Options.Create(new JwtOptions
        {
            Key = new string('k', 64), Issuer = "test", Audience = "test", AccessTokenMinutes = 15, RefreshTokenDays = 7
        });
        var lockout = Microsoft.Extensions.Options.Options.Create(new AuthLockoutOptions { MaxFailedAttempts = 3, LockoutMinutes = 15 });

        _sut = new AuthService(_db, new PasswordHasher<AspNetUser>(), new PasswordHasherService(),
            new UserPermissionService(_db), new JwtTokenService(jwt, _time), lockout, _time);
    }

    private AspNetUser SeedUser(string userName = "admin", bool active = true, bool legacyHash = false)
    {
        var user = new AspNetUser { Id = Guid.NewGuid().ToString(), UserName = userName };
        user.PasswordHash = legacyHash
            ? new PasswordHasherService().Sha256Hash(Password)
            : new PasswordHasher<AspNetUser>().HashPassword(user, Password);

        _db.AspNetUsers.Add(user);
        _db.UserControls.Add(new UserControl
        {
            UserId = "U-" + userName, Id = user.Id, FullName = "Test User", UserTypeId = "1",
            UserRoleID = "ADMIN", DeptId = "D1", IsActive = active
        });
        if (!_db.Departments.Any())
            _db.Departments.Add(new UserDepartment { DeptId = "D1", DeptName = "IT", IsActive = 1 });
        _db.SaveChanges();
        return user;
    }

    private Task<AuthResult> Login(string password = Password, string userName = "admin") =>
        _sut.LoginAsync(new LoginRequestDto { UserName = userName, Password = password }, "127.0.0.1");

    [Fact]
    public async Task Login_with_valid_password_returns_access_and_refresh_token()
    {
        SeedUser();

        var result = await Login();

        Assert.True(result.Succeeded);
        Assert.False(string.IsNullOrEmpty(result.Data!.Token));
        Assert.False(string.IsNullOrEmpty(result.Data.RefreshToken));
        Assert.Equal("U-admin", result.Data.UserId);
        Assert.Equal(_time.GetUtcNow().UtcDateTime.AddMinutes(15), result.Data.TokenExpiresAtUtc);

        var stored = Assert.Single(_db.RefreshTokens);
        Assert.NotEqual(result.Data.RefreshToken, stored.TokenHash);
    }

    [Fact]
    public async Task Login_with_legacy_sha256_hash_succeeds()
    {
        SeedUser(legacyHash: true);

        Assert.True((await Login()).Succeeded);
    }

    [Fact]
    public async Task Login_with_unknown_user_or_wrong_password_fails()
    {
        SeedUser();

        Assert.Equal(AuthError.InvalidCredentials, (await Login(userName: "nobody")).Error);
        Assert.Equal(AuthError.InvalidCredentials, (await Login("wrong")).Error);
    }

    [Fact]
    public async Task Repeated_failures_lock_account_until_lockout_expires()
    {
        var user = SeedUser();

        await Login("wrong");
        await Login("wrong");
        Assert.Equal(AuthError.LockedOut, (await Login("wrong")).Error);
        Assert.Equal(AuthError.LockedOut, (await Login()).Error);

        _time.Advance(TimeSpan.FromMinutes(16));
        Assert.True((await Login()).Succeeded);
        Assert.Equal(0, user.AccessFailedCount);
        Assert.Null(user.LockoutEndDateUtc);
    }

    [Fact]
    public async Task Successful_login_resets_failed_count()
    {
        var user = SeedUser();
        await Login("wrong");
        await Login("wrong");

        Assert.True((await Login()).Succeeded);
        Assert.Equal(0, user.AccessFailedCount);
    }

    [Fact]
    public async Task Inactive_user_cannot_login()
    {
        SeedUser(active: false);

        Assert.Equal(AuthError.InactiveUser, (await Login()).Error);
    }

    [Fact]
    public async Task Refresh_rotates_token_and_old_token_stops_working()
    {
        SeedUser();
        var login = (await Login()).Data!;

        var refreshed = await _sut.RefreshAsync(login.RefreshToken, null);

        Assert.True(refreshed.Succeeded);
        Assert.NotEqual(login.RefreshToken, refreshed.Data!.RefreshToken);
        Assert.Equal(2, _db.RefreshTokens.Count());
        Assert.Single(_db.RefreshTokens, t => t.RevokedAtUtc == null);
    }

    [Fact]
    public async Task Reusing_rotated_refresh_token_revokes_whole_session()
    {
        SeedUser();
        var login = (await Login()).Data!;
        var refreshed = (await _sut.RefreshAsync(login.RefreshToken, null)).Data!;

        var reuse = await _sut.RefreshAsync(login.RefreshToken, null);

        Assert.Equal(AuthError.InvalidRefreshToken, reuse.Error);
        Assert.All(_db.RefreshTokens, t => Assert.NotNull(t.RevokedAtUtc));
        Assert.False((await _sut.RefreshAsync(refreshed.RefreshToken, null)).Succeeded);
    }

    [Fact]
    public async Task Expired_refresh_token_is_rejected()
    {
        SeedUser();
        var login = (await Login()).Data!;

        _time.Advance(TimeSpan.FromDays(8));

        Assert.Equal(AuthError.InvalidRefreshToken, (await _sut.RefreshAsync(login.RefreshToken, null)).Error);
    }

    [Fact]
    public async Task Refresh_fails_when_user_was_deactivated()
    {
        SeedUser();
        var login = (await Login()).Data!;
        _db.UserControls.Single().IsActive = false;
        await _db.SaveChangesAsync();

        Assert.False((await _sut.RefreshAsync(login.RefreshToken, null)).Succeeded);
    }

    [Fact]
    public async Task Logout_revokes_refresh_token()
    {
        SeedUser();
        var login = (await Login()).Data!;

        await _sut.LogoutAsync(login.RefreshToken, login.UserId);

        Assert.False((await _sut.RefreshAsync(login.RefreshToken, null)).Succeeded);
    }

    [Fact]
    public async Task Logout_ignores_token_of_another_user()
    {
        SeedUser();
        var login = (await Login()).Data!;

        await _sut.LogoutAsync(login.RefreshToken, "someone-else");

        Assert.True((await _sut.RefreshAsync(login.RefreshToken, null)).Succeeded);
    }

    [Fact]
    public async Task GetCurrentUser_returns_profile_and_permissions()
    {
        SeedUser();
        _db.PagewiseActions.Add(new PagewiseAction
        {
            ActionID = "A1", UserId = "U-admin", MenuId = 12, ActionPermissionJson = "{\"View\":true,\"Delete\":false}"
        });
        await _db.SaveChangesAsync();

        var me = await _sut.GetCurrentUserAsync("U-admin");

        Assert.NotNull(me);
        Assert.Equal("admin", me!.UserName);
        Assert.True(me.Permissions.PagewisePermissions[12]["View"]);
    }
}
