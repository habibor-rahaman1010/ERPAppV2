namespace ERPApp.Shared.Abstractions.Security;

/// <summary>
/// Cross-module contract for page/action permission checks. Implemented by the Auth module,
/// consumed by any module through <c>[HasPermission]</c> or directly.
/// </summary>
public interface IPermissionChecker
{
    Task<bool> HasPermissionAsync(string userId, int menuId, string action, CancellationToken cancellationToken = default);
}
