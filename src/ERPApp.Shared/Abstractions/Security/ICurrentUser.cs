namespace ERPApp.Shared.Abstractions.Security;

public interface ICurrentUser
{
    bool IsAuthenticated { get; }
    string? UserId { get; }
    string? UserName { get; }
    string? Role { get; }
    string? DepartmentId { get; }
}
