using System.ComponentModel.DataAnnotations;

namespace Auth.Infrastructure.Options;

public sealed class AuthLockoutOptions
{
    public const string SectionName = "Lockout";

    [Range(1, 100)]
    public int MaxFailedAttempts { get; set; } = 5;

    [Range(1, 1440)]
    public int LockoutMinutes { get; set; } = 15;
}
