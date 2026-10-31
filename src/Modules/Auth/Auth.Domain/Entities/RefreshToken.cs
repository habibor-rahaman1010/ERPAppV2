namespace Auth.Domain.Entities;

public class RefreshToken
{
    public Guid Id { get; set; }
    public string UserId { get; set; } = default!;
    public string TokenHash { get; set; } = default!;
    public Guid TokenFamily { get; set; }
    public DateTime CreatedAtUtc { get; set; }
    public DateTime ExpiresAtUtc { get; set; }
    public string? CreatedByIp { get; set; }
    public DateTime? RevokedAtUtc { get; set; }
    public string? RevokedReason { get; set; }
    public Guid? ReplacedByTokenId { get; set; }

    public bool IsActive(DateTime nowUtc) => RevokedAtUtc is null && ExpiresAtUtc > nowUtc;

    public void Revoke(DateTime nowUtc, string reason, Guid? replacedByTokenId = null)
    {
        if (RevokedAtUtc is not null)
            return;

        RevokedAtUtc = nowUtc;
        RevokedReason = reason;
        ReplacedByTokenId = replacedByTokenId;
    }
}
