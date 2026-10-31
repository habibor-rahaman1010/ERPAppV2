using System.Reflection;
using ERPApp.Shared.Interfaces;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace ERPApp.Infrastructure.Modules;

/// <summary>
/// Discovers module assemblies by naming convention (<c>*.Infrastructure.dll</c> / <c>*.Presentation.dll</c>)
/// so the host never references module types directly.
/// </summary>
public static class ModuleExtensions
{
    private static readonly string[] ModuleAssemblySuffixes = [".Infrastructure", ".Presentation"];

    public static IReadOnlyList<Assembly> LoadModuleAssemblies(string? directory = null)
    {
        directory ??= AppContext.BaseDirectory;

        return Directory.EnumerateFiles(directory, "*.dll")
            .Select(Path.GetFileNameWithoutExtension)
            .Where(name => name is not null
                && !name.StartsWith("Microsoft.", StringComparison.Ordinal)
                && !name.StartsWith("System.", StringComparison.Ordinal)
                && ModuleAssemblySuffixes.Any(suffix => name.EndsWith(suffix, StringComparison.Ordinal)))
            .Select(name => Assembly.Load(new AssemblyName(name!)))
            .Distinct()
            .ToList();
    }

    public static IServiceCollection InstallModules(
        this IServiceCollection services, IConfiguration configuration, IEnumerable<Assembly> assemblies)
    {
        var installers = assemblies
            .SelectMany(assembly => assembly.GetTypes())
            .Where(type => typeof(IServiceInstaller).IsAssignableFrom(type) && type is { IsAbstract: false, IsInterface: false })
            .Select(Activator.CreateInstance)
            .Cast<IServiceInstaller>();

        foreach (var installer in installers)
            installer.InstallServices(services, configuration);

        return services;
    }

    public static IMvcBuilder AddModuleControllers(this IMvcBuilder builder, IEnumerable<Assembly> assemblies)
    {
        foreach (var assembly in assemblies.Where(a => a.GetName().Name?.EndsWith(".Presentation", StringComparison.Ordinal) == true))
            builder.AddApplicationPart(assembly);

        return builder;
    }
}
