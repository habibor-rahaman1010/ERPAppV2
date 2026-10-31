using System.Security.Claims;
using ERPApp.Shared.Abstractions.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;

namespace ERPApp.Infrastructure.Security;

internal sealed class PermissionAuthorizationHandler(IPermissionChecker permissionChecker, IHttpContextAccessor httpContextAccessor)
    : AuthorizationHandler<PermissionRequirement>
{
    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, PermissionRequirement requirement)
    {
        var userId = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrEmpty(userId))
            return;

        var cancellationToken = httpContextAccessor.HttpContext?.RequestAborted ?? CancellationToken.None;
        if (await permissionChecker.HasPermissionAsync(userId, requirement.MenuId, requirement.Action, cancellationToken))
            context.Succeed(requirement);
    }
}
