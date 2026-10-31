using Microsoft.AspNetCore.Authorization;

namespace ERPApp.Infrastructure.Security;

/// <summary>
/// Requires the authenticated user to have <paramref name="action"/> permission on menu <paramref name="menuId"/>.
/// Usage: <c>[HasPermission(12, PermissionActions.Insert)]</c>
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true)]
public sealed class HasPermissionAttribute(int menuId, string action)
    : AuthorizeAttribute(PermissionPolicy.Build(menuId, action));
