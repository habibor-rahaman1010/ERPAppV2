using System.Globalization;
using Microsoft.AspNetCore.Authorization;

namespace ERPApp.Infrastructure.Security;

internal static class PermissionPolicy
{
    public const string Prefix = "Permission:";

    public static string Build(int menuId, string action) =>
        string.Create(CultureInfo.InvariantCulture, $"{Prefix}{menuId}:{action}");

    public static bool TryParse(string policyName, out PermissionRequirement? requirement)
    {
        requirement = null;
        if (!policyName.StartsWith(Prefix, StringComparison.Ordinal))
            return false;

        var parts = policyName[Prefix.Length..].Split(':', 2);
        if (parts.Length != 2 || !int.TryParse(parts[0], NumberStyles.Integer, CultureInfo.InvariantCulture, out var menuId)
            || string.IsNullOrWhiteSpace(parts[1]))
            return false;

        requirement = new PermissionRequirement(menuId, parts[1]);
        return true;
    }
}

internal sealed record PermissionRequirement(int MenuId, string Action) : IAuthorizationRequirement;
