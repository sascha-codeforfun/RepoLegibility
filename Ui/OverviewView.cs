using RepoLegibility.Core;

namespace RepoLegibility.Ui;

/// <summary>What a "Show these" button asks for: a title for the list's banner, and the findings.</summary>
public sealed record ShowRequest(string Title, IReadOnlyList<Finding> Findings, string? CombinationKey = null);

/// <summary>A plain question and its answer.</summary>
public sealed class AnswerRow(OverviewAnswer a)
{
    public string Question => a.Question;
    public string Answer => a.Answer;
    public bool Notable => a.Notable;
    public bool Serious => a.Serious;
    public bool CanShow => a.Findings.Count > 0;
    public string ShowText => $"Show {a.Findings.Count}";
    public ShowRequest Show { get; } = new(a.Question.TrimEnd('?'), a.Findings);
}

/// <summary>An area of the overview: what it reads (or receives) and what it changes (or sends, or starts).</summary>
public sealed class LineRow(OverviewLine l)
{
    public string Area => l.Area;
    public string IconKey { get; } = Overview.Icon(l);

    /// <summary>What the area is, in plain words: the tooltip on its name.</summary>
    public string AreaHelp => l.Area switch
    {
        "Registry" => "The Windows registry: the database where Windows and apps keep their settings. The whole computer (HKLM) applies to everyone; your account (HKCU) only to you.",
        "Group policy" => "Rules for how Windows behaves, usually set by an administrator. They win over ordinary settings, and stay after the app is gone.",
        "Files" => "Files and folders on this computer.",
        "Internet" => "Other computers out on the internet.",
        "Local network" => "Other computers and devices on your own network, shared folders, and connections the app accepts.",
        "Internet or local network" => "An address the app is given while it runs: it could be on the internet or on your own network.",
        "Programs" => "Other programs the app starts, or code it loads while it runs.",
        _ => ""
    };
    /// <summary>"whole computer (HKLM)": plain words, the technical term in brackets.</summary>
    public string Reach => l.Reach.Length == 0 ? (l.Tech.Length == 0 ? "" : l.Tech) : l.Reach + (l.Tech.Length > 0 ? $" ({l.Tech})" : "");
    public string ReadsText => l.Reads?.Line ?? "";
    public string ChangesText => l.Changes?.Line ?? "";
    public bool HasReads => l.Reads is { Count: > 0 };
    public bool HasChanges => l.Changes is { Count: > 0 };
    public ShowRequest? ShowReads { get; } = l.Reads is { } r ? new($"{l.Area}{(l.Reach.Length > 0 ? ", " + l.Reach : "")}: {r.Verb}", r.Findings) : null;
    public ShowRequest? ShowChanges { get; } = l.Changes is { } c ? new($"{l.Area}{(l.Reach.Length > 0 ? ", " + l.Reach : "")}: {c.Verb}", c.Findings) : null;
}

/// <summary>Findings that mean more together, with what the README says.</summary>
public sealed class CombinationRow(Combination c)
{
    public string Title => c.Title;
    public string Sentence => c.Sentence;
    public string Declaration => c.Declaration.Text;
    public bool Expected => c.Expected;
    /// <summary>Known but not fully declared: mentioned in the README, or declared without naming everything.</summary>
    // Declared or mentioned: neutral, the author knew. Partly declared, not declared, can't be: worth a look.
    public bool Mentioned => c.Declaration.Kind == DeclarationKind.Mentioned;
    public bool Missing => c.Declaration.Kind is DeclarationKind.NotFound or DeclarationKind.CantBeDeclared
                           || c.Declaration.Kind == DeclarationKind.Declared && !c.Expected;
    public string Standing => c.Standing;
    public string Check => c.Check;
    public string ShowText => $"Show {c.Members.Count}";
    public ShowRequest Show { get; } = new(c.Title, c.Members, c.Key);
}

/// <summary>The Overview tab.</summary>
public sealed class OverviewView(ScanReport r)
{
    public string Headline { get; } = r.Overview?.Headline ?? "";
    public IReadOnlyList<AnswerRow> Answers { get; } = (r.Overview?.Answers ?? []).Select(a => new AnswerRow(a)).ToList();
    public IReadOnlyList<LineRow> Lines { get; } = (r.Overview?.Lines ?? []).Select(l => new LineRow(l)).ToList();
    public IReadOnlyList<CombinationRow> Combinations { get; } = r.Combinations.Select(c => new CombinationRow(c)).ToList();
    public bool HasCombinations => Combinations.Count > 0;
    public bool HasLines => Lines.Count > 0;
    public string LinesEmpty => Lines.Count == 0 ? "Nothing found that reads or changes files, settings or the network." : "";
}
