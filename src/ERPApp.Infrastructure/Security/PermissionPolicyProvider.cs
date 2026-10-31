using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;

namespace ERPApp.Infrastructure.Security;

internal sealed class PermissionPolicyProvider(IOptions<AuthorizationOptions> options)
    : DefaultAuthorizationPolicyProvider(options)
{
    public override async Task<AuthorizationPolicy?> GetPolicyAsync(string policyName)
    {
        if (!PermissionPolicy.TryParse(policyName, out var requirement))
            return await base.GetPolicyAsync(policyName);

        return new AuthorizationPolicyBuilder()
            .RequireAuthenticatedUser()
            .AddRequirements(requirement!)
            .Build();
    }
}
