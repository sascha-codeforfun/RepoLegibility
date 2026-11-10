using System.IO;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace RepoLegibility.Core;

/// <summary>A project file as far as the scan needs it.</summary>
public sealed class ProjectFile
{
    public required string Path { get; init; }
    public required string Dir { get; init; }
    public required string Name { get; init; }
    public required string OutputType { get; init; }
    public required IReadOnlyList<string> Frameworks { get; init; }
    public required string Ui { get; init; }
    public required bool IsTest { get; init; }
    public string? Manifest { get; init; }
    public required IReadOnlyList<(string Name, string Version)> Packages { get; init; }
    public required IReadOnlyList<string> ProjectReferences { get; init; }
    public required IReadOnlyList<string> FrameworkReferences { get; init; }
    public required IReadOnlyList<string> DllReferences { get; init; }
    /// <summary>Paths or patterns the project leaves out with Compile Remove.</summary>
    public required IReadOnlyList<string> CompileRemoved { get; init; }

    public string Kind => IsTest ? "Tests"
        : OutputType.Equals("Exe", StringComparison.OrdinalIgnoreCase) || OutputType.Equals("WinExe", StringComparison.OrdinalIgnoreCase) ? "App (exe)"
        : "Library";
}

/// <summary>Reads .csproj files (and the central package versions) with the base library's XML reader.</summary>
public static class ProjectScan
{
    private static readonly string[] TestPackages =
        ["Microsoft.NET.Test.Sdk", "xunit", "xunit.v3", "NUnit", "MSTest.TestFramework", "MSTest", "TUnit"];

    public static List<ProjectFile> Read(IReadOnlyList<RepoFile> files)
    {
        // Central package management: versions in Directory.Packages.props.
        var central = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var props in files.Where(f => f.Name.Equals("Directory.Packages.props", StringComparison.OrdinalIgnoreCase) && f.Text is not null))
        {
            var doc = Parse(props.Text!);
            if (doc is null) continue;
            foreach (var e in Elements(doc, "PackageVersion"))
            {
                var name = Attr(e, "Include") ?? Attr(e, "Update");
                var version = Attr(e, "Version") ?? Child(e, "Version");
                if (name is not null && version is not null) central[name] = version;
            }
        }

        // Directory.Build.props packages apply to every project under it.
        var buildProps = files
            .Where(f => f.Name.Equals("Directory.Build.props", StringComparison.OrdinalIgnoreCase) && f.Text is not null)
            .Select(f => (Dir: f.Dir, Doc: Parse(f.Text!)))
            .Where(x => x.Doc is not null)
            .ToList();

        var projects = new List<ProjectFile>();
        foreach (var file in files.Where(f => f.Extension is ".csproj" && f.Text is not null))
        {
            var doc = Parse(file.Text!);
            if (doc is null) continue;

            string Prop(string name) =>
                Elements(doc, name).Select(e => e.Value.Trim()).LastOrDefault(v => v.Length > 0) ?? "";

            var name = Prop("AssemblyName");
            if (name.Length == 0 || name.Contains("$(")) name = System.IO.Path.GetFileNameWithoutExtension(file.Path);

            var frameworks = (Prop("TargetFrameworks") is { Length: > 0 } many ? many : Prop("TargetFramework"))
                .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();

            var sdk = doc.Root?.Attribute("Sdk")?.Value ?? "";
            var ui = Prop("UseWPF").Equals("true", StringComparison.OrdinalIgnoreCase) ? "WPF"
                : Prop("UseWindowsForms").Equals("true", StringComparison.OrdinalIgnoreCase) ? "Windows Forms"
                : sdk.Contains("Web", StringComparison.OrdinalIgnoreCase) ? "Web"
                : sdk.Contains("Razor", StringComparison.OrdinalIgnoreCase) ? "Razor"
                : "";

            var packages = new List<(string, string)>();
            void AddPackages(XDocument d)
            {
                foreach (var e in Elements(d, "PackageReference"))
                {
                    var n = Attr(e, "Include") ?? Attr(e, "Update");
                    if (n is null) continue;
                    var v = Attr(e, "Version") ?? Child(e, "Version") ?? Attr(e, "VersionOverride")
                            ?? (central.TryGetValue(n, out var c) ? c : "(no version)");
                    packages.Add((n, v));
                }
            }
            AddPackages(doc);
            foreach (var (dir, props) in buildProps)
                if (IsSameOrUnder(file.Dir, dir)) AddPackages(props!);

            bool isTest = Prop("IsTestProject").Equals("true", StringComparison.OrdinalIgnoreCase)
                          || packages.Any(p => TestPackages.Contains(p.Item1, StringComparer.OrdinalIgnoreCase))
                          || Regex.IsMatch(name, @"\.(?:Tests?|UnitTests|IntegrationTests|Specs)$", RegexOptions.IgnoreCase);

            var manifest = Prop("ApplicationManifest");

            projects.Add(new ProjectFile
            {
                Path = file.Path,
                Dir = file.Dir,
                Name = name,
                OutputType = Prop("OutputType") is { Length: > 0 } o ? o : "Library",
                Frameworks = frameworks,
                Ui = ui,
                IsTest = isTest,
                Manifest = manifest.Length > 0 ? Join(file.Dir, manifest) : null,
                Packages = packages.Distinct().ToList(),
                ProjectReferences = Elements(doc, "ProjectReference").Select(e => Attr(e, "Include")).OfType<string>().ToList(),
                FrameworkReferences = Elements(doc, "FrameworkReference").Select(e => Attr(e, "Include")).OfType<string>().ToList(),
                DllReferences = Elements(doc, "Reference")
                    .Select(e => Child(e, "HintPath") ?? Attr(e, "Include"))
                    .OfType<string>()
                    .Where(r => r.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) || r.Contains('\\') || r.Contains('/'))
                    .ToList(),
                CompileRemoved = Elements(doc, "Compile").Select(e => Attr(e, "Remove")).OfType<string>().ToList()
            });
        }

        return projects.OrderBy(p => p.Path, StringComparer.OrdinalIgnoreCase).ToList();
    }

    /// <summary>The project a file belongs to: the deepest project folder above it.</summary>
    public static ProjectFile? Owner(IReadOnlyList<ProjectFile> projects, string path)
    {
        var dir = path.Contains('/') ? path[..path.LastIndexOf('/')] : "";
        return projects
            .Where(p => IsSameOrUnder(dir, p.Dir))
            .OrderByDescending(p => p.Dir.Length)
            .FirstOrDefault();
    }

    /// <summary>True when a file is left out of its project's build with Compile Remove.</summary>
    public static bool IsRemoved(ProjectFile project, string path)
    {
        if (project.CompileRemoved.Count == 0) return false;
        var relative = project.Dir.Length == 0 ? path : path[(project.Dir.Length + 1)..];
        foreach (var pattern in project.CompileRemoved.SelectMany(p => p.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)))
        {
            var regex = "^" + Regex.Escape(pattern.Replace('\\', '/'))
                .Replace(@"\*\*/", "(?:.*/)?")
                .Replace(@"\*\*", ".*")
                .Replace(@"\*", "[^/]*")
                .Replace(@"\?", "[^/]") + "$";
            if (Regex.IsMatch(relative, regex, RegexOptions.IgnoreCase)) return true;
        }
        return false;
    }

    public static bool IsSameOrUnder(string dir, string root) =>
        root.Length == 0 || dir.Equals(root, StringComparison.OrdinalIgnoreCase)
        || dir.StartsWith(root + "/", StringComparison.OrdinalIgnoreCase);

    public static string Join(string dir, string relative)
    {
        var parts = new List<string>(dir.Length == 0 ? [] : dir.Split('/'));
        foreach (var part in relative.Replace('\\', '/').Split('/', StringSplitOptions.RemoveEmptyEntries))
        {
            if (part == ".") continue;
            if (part == "..") { if (parts.Count > 0) parts.RemoveAt(parts.Count - 1); continue; }
            parts.Add(part);
        }
        return string.Join('/', parts);
    }

    public static XDocument? Parse(string text)
    {
        try { return XDocument.Parse(text, LoadOptions.SetLineInfo); }
        catch (System.Xml.XmlException) { return null; }
    }

    /// <summary>Elements by local name, so old-style projects with the MSBuild namespace read the same.</summary>
    public static IEnumerable<XElement> Elements(XDocument doc, string localName) =>
        doc.Descendants().Where(e => e.Name.LocalName == localName);

    public static string? Attr(XElement e, string name) =>
        e.Attributes().FirstOrDefault(a => a.Name.LocalName == name)?.Value.Trim();

    private static string? Child(XElement e, string name) =>
        e.Elements().FirstOrDefault(c => c.Name.LocalName == name)?.Value.Trim();
}
