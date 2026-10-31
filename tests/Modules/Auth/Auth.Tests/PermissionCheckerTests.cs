using Auth.Domain.Entities;
using Auth.Infrastructure;
using Auth.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;

namespace Auth.Tests;

public class PermissionCheckerTests
{
    [Theory]
    [InlineData(12, "View", true)]
    [InlineData(12, "Delete", false)]
    [InlineData(12, "Insert", false)]
    [InlineData(99, "View", false)]
    public async Task HasPermission_reads_pagewise_action_json(int menuId, string action, bool expected)
    {
        var db = new AuthDbContext(new DbContextOptionsBuilder<AuthDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString()).Options);
        db.UserControls.Add(new UserControl { UserId = "U1", Id = "X", UserTypeId = "1", IsActive = true });
        db.PagewiseActions.Add(new PagewiseAction
        {
            ActionID = "A1", UserId = "U1", MenuId = 12, ActionPermissionJson = "{\"View\":true,\"Delete\":false}"
        });
        await db.SaveChangesAsync();

        var sut = new PermissionChecker(new UserPermissionService(db), new MemoryCache(new MemoryCacheOptions()));

        Assert.Equal(expected, await sut.HasPermissionAsync("U1", menuId, action));
    }
}
