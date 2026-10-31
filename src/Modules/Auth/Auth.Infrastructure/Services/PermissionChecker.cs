using Auth.Application.Interfaces;
using ERPApp.Shared.Abstractions.Security;
using Microsoft.Extensions.Caching.Memory;

namespace Auth.Infrastructure.Services;

internal sealed class PermissionChecker(IUserPermissionService permissionService, IMemoryCache cache) : IPermissionChecker
{
    private static readonly TimeSpan CacheDuration = TimeSpan.FromMinutes(2);

    public async Task<bool> HasPermissionAsync(string userId, int menuId, string action, CancellationToken cancellationToken = default)
    {
        var permissions = await cache.GetOrCreateAsync($"auth:permissions:{userId}", entry =>
        {
            entry.AbsoluteExpirationRelativeToNow = CacheDuration;
            return permissionService.GetUserPermissionsAsync(userId);
        });

        return permissions is not null
            && permissions.PagewisePermissions.TryGetValue(menuId, out var actions)
            && actions.TryGetValue(action, out var allowed)
            && allowed;
    }
}
