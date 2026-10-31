using System.Security.Claims;
using ERPApp.Shared.Abstractions.Security;
using Microsoft.AspNetCore.Http;

namespace ERPApp.Infrastructure.Security;

internal sealed class CurrentUser(IHttpContextAccessor httpContextAccessor) : ICurrentUser
{
    private ClaimsPrincipal? Principal => httpContextAccessor.HttpContext?.User;

    public bool IsAuthenticated => Principal?.Identity?.IsAuthenticated == true;
    public string? UserId => Principal?.FindFirstValue(ClaimTypes.NameIdentifier);
    public string? UserName => Principal?.FindFirstValue(ClaimTypes.Name);
    public string? Role => Principal?.FindFirstValue(ClaimTypes.Role);
    public string? DepartmentId => Principal?.FindFirstValue(ErpClaimTypes.DepartmentId);
}
