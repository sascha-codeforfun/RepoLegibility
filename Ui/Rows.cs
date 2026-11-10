using System.IO;
using RepoLegibility.Core;

namespace RepoLegibility.Ui;

/// <summary>One finding as the list and the detail pane show it.</summary>
public sealed class FindingRow(Finding finding)
{
    public Finding Finding { get; } = finding;

    public int Id => Finding.Id;
    public Legibility Legibility => Finding.Legibility;
    public Scope Scope => Finding.Scope;
    public bool IsTest => Finding.Origin == Origin.Tests;

    /// <summary>A row of findings that mean more together, at the top of the list.</summary>
    public bool IsTogether => Finding.Kind == FindingKind.Combination;

    /// <summary>"Opaque", "Untraced", "Run time", "Clear", or "Together": the word on the pill.</summary>
    public string LegibilityText => IsTogether ? "Together" : Names.Of(Finding.Legibility);

    /// <summary>What picks the pill's style: the legibility, or "Together".</summary>
    public object PillKey => IsTogether ? "TogetherPill" : Finding.Legibility;

    /// <summary>The list's group: "Together", "Admin scope", or "Tests" for findings in test code.</summary>
    public string Group => IsTogether ? "Together" : IsTest ? "In tests" : Names.Of(Finding.Scope);

    /// <summary>Sorts the groups in the list: what's together first, then widest reach, tests last.</summary>
    public int GroupOrder => IsTogether ? -1 : IsTest ? 9 : Finding.Scope switch
    {
        Scope.Admin => 0,
        Scope.WebService => 1,
        Scope.User => 2,
        _ => 3
    };

    public string ScopeText => Names.Of(Finding.Scope);
    public string KindText => Names.Of(Finding.Kind);
    /// <summary>The kit icon for what it touches, beside the headline and the kind; "" for none.</summary>
    public string IconKey => Overview.Icon(Finding);
    public bool HasIcon => IconKey.Length > 0;

    // In plain words, for someone who doesn't read code.
    public string WhatThisIs => Names.Explain(Finding.Kind);
    public string LegibilityExplain => IsTogether ? Names.Explain(FindingKind.Combination) : Names.Explain(Finding.Legibility);
    public string? WhoDecides => Finding.WhoDecides;
    public bool HasWhoDecides => Finding.WhoDecides is not null;
    public string? LooksInside => Finding.LooksInside;
    public bool HasLooksInside => Finding.LooksInside is not null;
    public string OriginText => Names.Of(Finding.Origin);
    public bool ShowOrigin => Finding.Origin != Origin.App;

    public bool HiddenOnPurpose => Finding.HiddenOnPurpose;
    public string HowHidden => "Hidden on purpose: " + (Finding.HowHidden ?? "the author hid the value") + ". The value is shown where the source fixes it.";
    public bool Unused => Finding.Unused;
    public IReadOnlyList<string> Directions { get; } = Names.Of(finding.Direction).ToList();

    // The list row shows one mark, the strongest: hidden, then not used, then not called by the app.
    // The Obscured pill already says it: the mark only where a finding is hidden but legible otherwise.
    public bool ListShowsHidden => Finding.HiddenOnPurpose && Finding.Legibility != Legibility.Obscured;
    public bool ShowHiddenTag => Finding.HiddenOnPurpose && Finding.Legibility != Legibility.Obscured;
    public bool ListShowsUnused => Finding.Unused && !Finding.HiddenOnPurpose;
    public bool ListShowsNotCalled => Finding.NotCalledByApp && !Finding.Unused && !Finding.HiddenOnPurpose;

    /// <summary>Only tests reach the code this runs in: the "Not called by the app" tag.</summary>
    public bool NotCalledByApp => Finding.NotCalledByApp;

    public string Headline => IsTogether ? Finding.Summary : KindText + " · " + Finding.Target;
    public string Where => IsTogether
        ? $"{Finding.Key}  ·  {Finding.Calls.Count} finding{(Finding.Calls.Count == 1 ? "" : "s")}  ·  {(Finding.Target.StartsWith("Declared", StringComparison.Ordinal) ? "declared in the README" : Finding.Target.StartsWith("Hidden", StringComparison.Ordinal) ? "can't be declared" : Finding.Target.StartsWith("Not declared", StringComparison.Ordinal) ? "not in the README" : "only mentioned in the README")}"
        : $"{Finding.File}:{Finding.Line}";

    // The detail's headings: a combination has its findings and the README where a finding has its target and calls.
    public string TargetHeading => IsTogether ? "WHAT THE README SAYS" : "TARGET";
    public string NotesHeading => IsTogether ? "BEFORE BUILDING" : "NOTES";
    public bool HasWhere => !IsTogether;

    /// <summary>The key that stays with the finding across scans: "N-3f2a1c". The #n is only the place in this list.</summary>
    public string Key => Finding.Key;
    public string WhereLong => IsTogether ? Where : Key + "  ·  " + Where + (Finding.Excerpt?.Member is { } m ? "  in " + m : "") + (Finding.Project is { } p ? "  ·  project " + p : "");
    public string Summary => Finding.Summary;
    public string Call => Finding.Call;
    public string Target => Finding.Target;

    public IReadOnlyList<string> Reasons => Finding.Reasons;
    public bool HasReasons => Finding.Reasons.Count > 0;
    public IReadOnlyList<string> Notes => Finding.Notes;
    public bool HasNotes => Finding.Notes.Count > 0;
    public IReadOnlyList<TraceStep> Trace => Finding.Trace;
    public bool HasTrace => Finding.Trace.Count > 0;

    // With a single call, its reason is the finding's own and stands under WHERE IT'S DECIDED already.
    public IReadOnlyList<CallRow> Calls { get; } = finding.Calls
        .Select(c => new CallRow(c, finding.Call, showReason: finding.Kind == FindingKind.Combination || finding.Calls.Count > 1 || finding.CallsNotFollowed > 0)).ToList();
    public bool HasCalls => Calls.Count > 0;
    public string CallsHeading => IsTogether ? $"THE FINDINGS IN IT ({Calls.Count}) · SEARCH A KEY TO OPEN ONE"
        : Calls.Count == 1 && Finding.CallsNotFollowed == 0 ? "THE ONE CALL THAT DECIDES IT" : $"CALLS THAT DECIDE IT ({Calls.Count + Finding.CallsNotFollowed})";
    public bool HasCallsMore => Finding.CallsNotFollowed > 0;
    public string CallsMore => $"{Finding.CallsNotFollowed} more call{(Finding.CallsNotFollowed == 1 ? "" : "s")} not followed; the scan stopped after {Calls.Count}.";

    public IReadOnlyList<CodeLine> Code { get; } = finding.Excerpt is { } x ? Lines(x, finding.File) : [];

    /// <summary>The excerpt's lines, coloured when they're C#.</summary>
    private static List<CodeLine> Lines(Excerpt x, string file)
    {
        var spans = file.EndsWith(".cs", StringComparison.OrdinalIgnoreCase) ? Highlight.Lines(x.Lines)
            : Highlight.IsXml(file) ? Highlight.Xml(x.Lines)
            : x.Lines.Select(l => (IReadOnlyList<CodeSpan>)[new CodeSpan(l.Replace("\t", "    "), SpanKind.Plain)]).ToList();
        return x.Lines.Select((text, i) => new CodeLine(x.FirstLine + i, text.Replace("\t", "    "), x.FirstLine + i == x.Focus, spans[i])).ToList();
    }
    public bool HasCode => Code.Count > 0;

    /// <summary>What the search box matches: the file, the target, the summary, the call.</summary>
    public bool Matches(string text) =>
        Finding.Key.Equals(text, StringComparison.OrdinalIgnoreCase) ||
        Finding.File.Contains(text, StringComparison.OrdinalIgnoreCase)
        || Finding.Target.Contains(text, StringComparison.OrdinalIgnoreCase)
        || Finding.Summary.Contains(text, StringComparison.OrdinalIgnoreCase)
        || Finding.Call.Contains(text, StringComparison.OrdinalIgnoreCase)
        || KindText.Contains(text, StringComparison.OrdinalIgnoreCase)
        || Finding.NotCalledByApp && "Not called by the app".Contains(text, StringComparison.OrdinalIgnoreCase)
        || Finding.HiddenOnPurpose && "Hidden on purpose".Contains(text, StringComparison.OrdinalIgnoreCase)
        || Finding.Unused && "Not used in this source".Contains(text, StringComparison.OrdinalIgnoreCase)
        || Finding.Sends?.Contains(text, StringComparison.OrdinalIgnoreCase) == true
        || Finding.Notes.Any(n => n.Contains(text, StringComparison.OrdinalIgnoreCase))
        || Finding.Calls.Any(c => c.File.Contains(text, StringComparison.OrdinalIgnoreCase) || c.Target.Contains(text, StringComparison.OrdinalIgnoreCase));
}

/// <summary>One call of a helper, as the detail pane lists it.</summary>
public sealed class CallRow(CallSite call, string sinkCall, bool showReason)
{
    private static readonly System.Text.RegularExpressions.Regex Helper = new(@"^Through (\w+) ");

    public Legibility Legibility => call.Legibility;
    public string LegibilityText => Names.Of(call.Legibility);

    /// <summary>"ConnectivityCheck.cs:48 · through CheckAsync → Dns.GetHostAddressesAsync · Web service".</summary>
    public string Where
    {
        get
        {
            var helpers = call.Via.Select(v => Helper.Match(v)).Where(m => m.Success).Select(m => m.Groups[1].Value).ToList();
            var baseCall = sinkCall.Contains(" → ") ? sinkCall[(sinkCall.LastIndexOf(" → ", StringComparison.Ordinal) + 3)..] : sinkCall;
            var through = helpers.Count > 0 ? "  ·  through " + string.Join(" → ", helpers.Append(baseCall)) : "";
            // A combination's findings: no helper in between.
            return $"{call.File}:{call.Line}{through}  ·  {Names.Short(call.Scope)}";
        }
    }

    public string Target => call.Target;
    public string Reason => call.Reason ?? "";
    public bool HasReason => showReason && !string.IsNullOrEmpty(call.Reason);
}

/// <summary>A line of the code excerpt; the finding's own line is marked.</summary>
public sealed record CodeLine(int Number, string Text, bool IsFocus, IReadOnlyList<CodeSpan> Spans);
