using System.Reflection;

namespace Auth.Tests;

public class ModuleIsolationTests
{
    private static string[] ReferencedAuthAssemblies(string assemblyName) =>
        Assembly.Load(assemblyName).GetReferencedAssemblies()
            .Select(a => a.Name!)
            .Where(n => n.StartsWith("Auth.", StringComparison.Ordinal))
            .ToArray();

    [Fact]
    public void Domain_depends_on_no_other_layer() =>
        Assert.Empty(ReferencedAuthAssemblies("Auth.Domain"));

    [Fact]
    public void Application_does_not_depend_on_infrastructure_or_presentation() =>
        Assert.DoesNotContain(ReferencedAuthAssemblies("Auth.Application"),
            n => n is "Auth.Infrastructure" or "Auth.Presentation");

    [Fact]
    public void Presentation_does_not_depend_on_infrastructure() =>
        Assert.DoesNotContain("Auth.Infrastructure", ReferencedAuthAssemblies("Auth.Presentation"));

    [Fact]
    public void Shared_kernel_does_not_depend_on_any_module() =>
        Assert.Empty(ReferencedAuthAssemblies("ERPApp.Shared"));
}
