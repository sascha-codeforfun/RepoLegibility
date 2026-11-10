using System.Windows;
using RepoLegibility.Core;

namespace RepoLegibility.Ui;

/// <summary>A label, a value and an optional word for a tag: one row of the Facts view. An icon key puts the kit's icon before the label.</summary>
public sealed record FactRow(string Label, string Value, string? Tag = null, string? Help = null, ShowRequest? Show = null, string? Icon = null)
{
    public bool HasIcon => Icon is not null;
    public bool HasTag => Tag is not null;
    public bool HasHelp => Help is not null;
    public bool CanShow => Show is { Findings.Count: > 0 };
    public string ShowText => Show is null ? "" : $"Show {Show.Findings.Count}";
}

/// <summary>One of the largest files: its lines, a bar for its size against the largest, and its findings.</summary>
public sealed class FileRow(FileSize f, int largest, IReadOnlyList<Finding> findings)
{
    public string Path { get; } = f.Path;
    public string Lines { get; } = $"{f.Sloc:N0} lines";
    public GridLength Filled { get; } = new(Math.Max(1, f.Sloc), GridUnitType.Star);
    public GridLength Rest { get; } = new(Math.Max(0, largest - f.Sloc), GridUnitType.Star);
    public ShowRequest Show { get; } = new(System.IO.Path.GetFileName(f.Path), findings);
    public bool CanShow { get; } = findings.Count > 0;
    public string ShowText { get; } = $"Show {findings.Count}";
}

/// <summary>
/// The Facts tab: one sentence, then four groups, each answering a question: how big it is, how it's
/// built, what comes from outside, what the scan covered. Rows that would only say "none" are left out.
/// </summary>
public sealed class FactsView(ScanReport r)
{
    public string Headline { get; } = FactsText.Headline(r);

    // ---- how big is it ----
    public IReadOnlyList<FactRow> Size { get; } = FactsText.Size(r).Select(x => new FactRow(x.Label, x.Value)).ToList();

    // The C# split three ways, as one bar: app code, tests, comments.
    public GridLength AppPart { get; } = Part(r.Metrics.AppSloc);
    public GridLength TestPart { get; } = Part(r.Metrics.TestSloc);
    public GridLength CommentPart { get; } = Part(r.Metrics.CommentLines);
    public string AppText { get; } = $"App code {r.Metrics.AppSloc:N0}";
    public string TestText { get; } = $"Tests {r.Metrics.TestSloc:N0}";
    public string CommentText { get; } = $"Comments {r.Metrics.CommentLines:N0}";
    public bool HasTests { get; } = r.Metrics.TestSloc > 0;
    public bool HasComments { get; } = r.Metrics.CommentLines > 0;
    public bool HasCode { get; } = r.Metrics.Sloc > 0;

    public IReadOnlyList<FileRow> Largest { get; } = r.Metrics.Largest
        .Select(l => new FileRow(l, r.Metrics.Largest.Count == 0 ? 1 : r.Metrics.Largest.Max(x => x.Sloc),
            r.Findings.Where(f => f.File == l.Path).ToList())).ToList();
    public bool HasLargest => Largest.Count > 0;

    // ---- how it's built ----
    public IReadOnlyList<FactRow> Projects { get; } = r.Projects
        .Select(p => new FactRow(p.Path, $"{string.Join(", ", p.Frameworks)}{(p.Ui.Length > 0 ? " · " + p.Ui : "")} · {p.Sloc:N0} lines", p.Kind,
            FactsText.ProjectKind(p.Kind), new ShowRequest($"Project {p.Name}", r.Findings.Where(f => f.Project == p.Name).ToList())))
        .ToList();
    public string ProjectsEmpty => Projects.Count == 0 ? "No project files found." : "";
    public bool HasNoProjects => Projects.Count == 0;
    public IReadOnlyList<string> FileTypes { get; } = r.Metrics.ByExtension.Take(12).Select(e => $"{e.Extension} {e.Count:N0}").ToList();

    // ---- what comes from outside ----
    public IReadOnlyList<FactRow> Dependencies { get; } =
        r.Packages.Select(p => new FactRow(p.Name, $"{p.Version} · {p.Project}", p.TestOnly ? "Tests only" : "NuGet"))
        .Concat(r.References.Where(x => x.Kind != "Project").Select(x => new FactRow(x.Name, "in " + x.From, x.Kind)))
        .Concat(r.References.Where(x => x.Kind == "Project").Select(x => new FactRow(x.Name, "referenced by " + x.From, "Project")))
        .Concat(r.CiActions.Select(a => new FactRow(a.Uses, a.Where, a.Pinned ? "CI, pinned" : "CI, not pinned")))
        .ToList();
    public IReadOnlyList<FactRow> BlackBoxes { get; } = r.BlackBoxes
        .Select(b => new FactRow(b.Path, $"{AiExport.Size(b.Bytes)} · SHA-256 {b.Sha256}", b.Kind, Icon: "Icon.File")).ToList();
    public IReadOnlyList<FactRow> Endpoints { get; } = r.Endpoints
        .Select(e => new FactRow(e.Display, string.Join(", ", e.Where.Take(3)), Icon: "Icon.Globe")).ToList();
    public string DependenciesEmpty => Dependencies.Count == 0 ? "None: the code uses only .NET itself." : "";
    public string BlackBoxesEmpty => BlackBoxes.Count == 0 ? "None: no compiled code or archives in the zip." : "";
    public string EndpointsEmpty => Endpoints.Count == 0 ? "None." : "";

    // ---- what the scan covered ----
    public IReadOnlyList<FactRow> Coverage { get; } = FactsText.Coverage(r).Select(x => new FactRow(x.Label, x.Value)).ToList();
    public IReadOnlyList<string> NotCovered { get; } = r.NotCovered;
    public string NotCoveredEmpty => NotCovered.Count == 0 ? "Nothing reported." : "";

    // The "none" lines show only when their list is empty, so an empty line leaves no gap.
    public bool NoDependencies => Dependencies.Count == 0;
    public bool NoBlackBoxes => BlackBoxes.Count == 0;
    public bool NoEndpoints => Endpoints.Count == 0;
    public bool NoNotCovered => NotCovered.Count == 0;

    private static GridLength Part(int n) => n > 0 ? new GridLength(n, GridUnitType.Star) : new GridLength(0);
}
