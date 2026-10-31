namespace Auth.Domain.Entities;

public class AspNetUser
{
    public string Id { get; set; } = default!; // From AspNetUsers
    public string? Email { get; set; }
    public bool EmailConfirmed { get; set; }
    public string? PasswordHash { get; set; }
    public string? SecurityStamp { get; set; }
    public string? PhoneNumber { get; set; }
    public bool PhoneNumberConfirmed { get; set; }
    public bool TwoFactorEnabled { get; set; }
    public DateTime? LockoutEndDateUtc { get; set; }
    public bool LockoutEnabled { get; set; }
    public int AccessFailedCount { get; set; }
    public string UserName { get; set; } = default!;
    public int OrderBy { get; set; }

    public bool IsLockedOut(DateTime nowUtc) => LockoutEndDateUtc is not null && LockoutEndDateUtc > nowUtc;

    public void RegisterFailedLogin(DateTime nowUtc, int maxFailedAttempts, TimeSpan lockoutDuration)
    {
        AccessFailedCount++;
        if (AccessFailedCount < maxFailedAttempts)
            return;

        LockoutEndDateUtc = nowUtc.Add(lockoutDuration);
        AccessFailedCount = 0;
    }

    public void RegisterSuccessfulLogin()
    {
        AccessFailedCount = 0;
        LockoutEndDateUtc = null;
    }
}
