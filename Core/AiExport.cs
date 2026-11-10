using System.IO;
using System.Globalization;
using System.Text;

namespace RepoLegibility.Core;

/// <summary>
/// The report as Markdown for an AI assistant: a second opinion on the findings, or a close look at
/// the opaque ones. It says what the scan is and isn't, then the facts, then every finding with its
/// code and trace, opaque first. Within the size limit, opaque and untraced findings always stay in full.
/// </summary>
public static class AiExport
{
    /// <summary>About 100,000 tokens: what most assistants take in one message, with room to answer.</summary>
    public const int MaxCharacters = 400_000;

    /// <summary>Full, without code, one line, or (for tests) counted per file.</summary>
    private enum Detail { Full, NoCode, Line, Grouped }

    /// <summary>
    /// Numbers in one form whatever the machine's language: 61,002 and 4.0, never 61.002 (sixty-one
    /// in English) beside 4.0. The window and the PDF keep the user's own format.
    /// </summary>
    private static string Invariant(Func<string> write)
    {
        var culture = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.InvariantCulture;
            return write();
        }
        finally
        {
            CultureInfo.CurrentCulture = culture;
        }
    }

    public static string Build(ScanReport r) => Invariant(() => BuildText(r));

    public static string BuildOne(ScanReport r, Finding f) => Invariant(() => BuildOneText(r, f));

    private static string BuildText(ScanReport r)
    {
        // Shrink step by step until it fits: tests to one line, then clear, then run time without code.
        var plans = new (Func<Finding, Detail> Detail, string? Note)[]
        {
            (_ => Detail.Full, null),
            (f => f.Origin == Origin.Tests ? Detail.Line : Detail.Full, "Findings in tests are listed in one line each."),
            (f => f.Origin == Origin.Tests || f.Legibility == Legibility.Clear ? Detail.Line : Detail.Full,
                "Findings in tests and clear findings are listed in one line each."),
            (f => Kept(f) ? Detail.Full : f.Origin == Origin.Tests ? Detail.Grouped : f.Legibility == Legibility.Clear ? Detail.Line : Detail.NoCode,
                "Findings in tests are counted per file; clear findings are one line each; run-time ones are shown without code."),
            (f => Kept(f) ? Detail.Full : f.Origin == Origin.Tests ? Detail.Grouped : Detail.Line,
                "Only obscured, opaque and untraced findings are shown in full; findings in tests are counted per file; every other finding is one line, with what decides it."),
            (f => f.Origin != Origin.Tests && f.Legibility is Legibility.Obscured or Legibility.Opaque ? Detail.Full : Kept(f) ? Detail.NoCode : f.Origin == Origin.Tests ? Detail.Grouped : Detail.Line,
                "Only obscured and opaque findings are shown in full; untraced ones without code (ask for the code of any you want to follow); findings in tests are counted per file; every other finding is one line, with what decides it.")
        };

        string text = "";
        foreach (var (detail, note) in plans)
        {
            text = Write(r, detail, note);
            if (text.Length <= MaxCharacters) return text;
        }
        return text[..MaxCharacters] + "\n\n[Cut at " + MaxCharacters.ToString("N0", CultureInfo.InvariantCulture) + " characters.]\n";
    }

    /// <summary>What a reader has to look at themselves: kept in full however large the report.</summary>
    private static bool Kept(Finding f) => f.Origin != Origin.Tests && f.Legibility is Legibility.Obscured or Legibility.Opaque or Legibility.Untraced;

    private static string Write(ScanReport r, Func<Finding, Detail> detail, string? shrinkNote)
    {
        var sb = new StringBuilder();
        var m = r.Metrics;

        sb.AppendLine($"# RepoLegibility {r.ToolVersion} report: {r.RepoName}");
        sb.AppendLine();
        sb.AppendLine("## Your task");
        sb.AppendLine();
        sb.AppendLine("Give a second opinion on this static scan of a C# repository. Assess what the code can do to the machine, the user's data and accounts, and the services it talks to.");
        sb.AppendLine();
        sb.AppendLine("- Start with the obscured findings (written so the source can't be read), then the opaque ones, then the untraced ones (the scan stopped before it found where a value comes from; finish the trace from the code shown), then the run-time ones. Clear ones need a look only where their scope is admin or web service.");
        sb.AppendLine("- For each finding you comment on, give its key in brackets ([N-3f2a1c], which stays the same across scans) and its #n, what the code most likely does, whether that fits what the repository is for, and what would have to be read or run to confirm it.");
        sb.AppendLine("- Say where you disagree with a scope or a legibility, and name anything the scan missed in the code shown.");
        sb.AppendLine("- Check the combined findings: whether each holds up, and whether the README's declaration (if any) matches what the code does.");
        sb.AppendLine("- End with an overall view: what someone should check before running a build of this repo.");
        sb.AppendLine();
        sb.AppendLine("Purpose: help a reviewer decide where to look. This is a map of what the code involves, not a verdict on whether it is safe. Obscured marks code written so it can't be read; Opaque marks code whose behaviour the source can't show by nature. Honest code uses both, so read it to tell which.");
        sb.AppendLine();
        sb.AppendLine("How the scan works, so you can weigh it: it reads the source; it doesn't compile or run it. It finds calls that touch files, the registry, the network, processes, identities and credentials, reflection, code loading and native code, and follows each target back through variables, fields, methods and their callers. Names are matched by name, not by type, so a trace can now and then pass through a same-named member of another class. Traces stop at 12 steps deep or 120 in all, or at dead ends; the reasons say where.");
        sb.AppendLine();
        sb.AppendLine("Not covered: the code inside NuGet packages (listed under Dependencies), binaries in the repo (listed as black boxes), code fetched or generated at run time (the places that load or compile it are findings), and code in other languages.");
        sb.AppendLine();
        sb.AppendLine("Terms: **Scope** is how far a finding reaches: App (its own folder), User (the user's profile, HKCU, the user's credentials), Admin (needs administrator rights: machine-wide changes, services, the firewall, elevated starts, reading the SAM or SECURITY hive; a read any user can do is User), Web service (remote endpoints). **Legibility**: Clear (the source shows what and where), Run time (the kind of action is known; the target is decided when the app runs, and the reasons say by what: settings, the command line, what the user types or picks, a property set by binding), Untraced (the scan didn't reach where a value comes from; the reasons say where it stopped: a method nothing calls, a delegate, a lambda, or the step limits), Opaque (the source can't show what happens, by nature: computed names, loaded code, shell commands built at run time, a third-party CI action not pinned to a commit), Obscured (the source holds it but written so it can't be read: Base64, character codes, fragments, XOR, encoded PowerShell; read these first). " +
                      "Code built from an expression tree in the source is Run time too: what runs is put together while the app runs, from parts the source shows. " +
                      "So is one of GitHub's own CI actions (actions/, github/) pinned to a tag: what runs is decided outside this repo. " +
                      "A finding marked \"not called by the app\" sits in code only the repo's tests call: in the shipped app it runs only if something outside the repo calls it. " +
                      "Where a call sits in a helper that passes its value straight on, the finding lists the helper's calls, each judged where it is, and takes the least legible and widest of them.");
        sb.AppendLine("Marks: **hidden on purpose** means the author hid the value (Base64, character codes, fragments, XOR, encoded PowerShell); where the source fixes it, the value is worked out without running anything and shown, marked (decoded) or (assembled), and the finding stays Obscured. " +
                      "**Not used in this source** means declared, looked up or created but never used: something the code can do, not something it does. " +
                      "**Reads / changes / sends / receives / runs** says which way a finding moves things: in from this machine, onto it, out of it, in from outside, or code it starts or loads.");
        if (shrinkNote is not null)
        {
            sb.AppendLine();
            sb.AppendLine("Size: " + shrinkNote);
        }
        sb.AppendLine();

        sb.AppendLine("## Input");
        sb.AppendLine();
        sb.AppendLine($"- Zip: `{r.ZipName}`, {Size(r.ZipBytes)}");
        sb.AppendLine($"- SHA-256: `{r.ZipSha256}`");
        sb.AppendLine($"- Scanned {r.ScannedAt:yyyy-MM-dd HH:mm} with RepoLegibility {r.ToolVersion} in {r.Took.TotalSeconds.ToString("0.0", CultureInfo.InvariantCulture)} s");
        sb.AppendLine();

        sb.AppendLine("## Summary");
        sb.AppendLine();
        var counted = r.Counted.ToList();
        sb.AppendLine($"- Findings: {counted.Count} outside tests (obscured {r.Obscured}, opaque {r.Opaque}, untraced {r.Untraced}, run time {r.PartlyClear}, clear {r.Clear}); {r.Findings.Count - counted.Count} in tests");
        sb.AppendLine("- By scope: " + string.Join(", ", Enum.GetValues<Scope>().Select(s => $"{Names.Short(s)} {counted.Count(f => f.Scope == s)}")));
        sb.AppendLine($"- Runs as administrator: {(r.Admin ? "yes" : "no")}");
        sb.AppendLine($"- Writes: {r.Writes} code passages write or delete, to {r.Paths} distinct places");
        sb.AppendLine($"- Density: {r.AppDensity.ToString("0.0", CultureInfo.InvariantCulture)} findings per 1,000 lines of app C# ({r.CodeFindings} in {r.Metrics.AppSloc:N0} lines; {r.OtherFindings} more in build, CI and config files, not counted); " +
                      $"tests {r.TestDensity.ToString("0.0", CultureInfo.InvariantCulture)} per 1,000 lines of test code ({r.TestFindings} in {r.Metrics.TestSloc:N0} lines)");
        sb.AppendLine();

        AppendOverview(sb, r);
        AppendCombined(sb, r);

        sb.AppendLine("## Facts");
        sb.AppendLine();
        sb.AppendLine($"- Files: {m.Files:N0} ({Size(m.Bytes)}); C# files: {m.CsFiles:N0}");
        sb.AppendLine($"- Lines of C# code: {m.Sloc:N0} (comments {m.CommentLines:N0}; tests {m.TestSloc:N0}; generated, not counted: {m.GeneratedSloc:N0} in {m.GeneratedFiles} files); XAML lines: {m.XamlLines:N0}");
        sb.AppendLine($"- Careful review at 200–400 lines an hour: {Hours(m.ReviewHours.Low)}–{Hours(m.ReviewHours.High)}");
        sb.AppendLine($"- P/Invoke declarations: {m.PInvokes}; unsafe: {m.UnsafeBlocks}"
                      + (m.UnsafeAllowedIn.Count > 0 ? $"; AllowUnsafeBlocks on in {string.Join(", ", m.UnsafeAllowedIn)}" : ""));
        if (m.Largest.Count > 0)
            sb.AppendLine("- Largest C# files: " + string.Join(", ", m.Largest.Select(l => $"`{l.Path}` ({l.Sloc:N0})")));
        sb.AppendLine();

        sb.AppendLine("### Projects");
        sb.AppendLine();
        if (r.Projects.Count == 0) sb.AppendLine("None found.");
        foreach (var p in r.Projects)
            sb.AppendLine($"- `{p.Path}`: {p.Kind}, {string.Join(", ", p.Frameworks)}{(p.Ui.Length > 0 ? ", " + p.Ui : "")}, {p.Sloc:N0} lines");
        sb.AppendLine();

        sb.AppendLine("### Dependencies");
        sb.AppendLine();
        if (r.Packages.Count == 0 && r.References.Count == 0 && r.CiActions.Count == 0) sb.AppendLine("None.");
        foreach (var p in r.Packages)
            sb.AppendLine($"- NuGet `{p.Name}` {p.Version} in {p.Project}{(p.TestOnly ? " (tests only)" : "")}");
        foreach (var x in r.References.Where(x => x.Kind != "Project"))
            sb.AppendLine($"- {x.Kind} `{x.Name}` in {x.From}");
        foreach (var x in r.References.Where(x => x.Kind == "Project"))
            sb.AppendLine($"- Project reference {x.From} → {x.Name}");
        foreach (var a in r.CiActions)
            sb.AppendLine($"- CI action `{a.Uses}`{(a.Pinned ? " (pinned to a commit)" : " (not pinned to a commit)")} at {a.Where}");
        sb.AppendLine();

        sb.AppendLine("### Black boxes");
        sb.AppendLine();
        if (r.BlackBoxes.Count == 0) sb.AppendLine("None: no compiled code or archives in the zip.");
        foreach (var b in r.BlackBoxes)
            sb.AppendLine($"- `{b.Path}`: {b.Kind}, {Size(b.Bytes)}, SHA-256 `{b.Sha256}`");
        sb.AppendLine();

        sb.AppendLine("### Web addresses named in the code and its configuration");
        sb.AppendLine();
        if (r.Endpoints.Count == 0) sb.AppendLine("None.");
        foreach (var e in r.Endpoints)
            sb.AppendLine($"- {e.Display} · {string.Join(", ", e.Where.Take(3))}");
        sb.AppendLine();

        sb.AppendLine("### Not covered by the scan");
        sb.AppendLine();
        if (r.NotCovered.Count == 0) sb.AppendLine("Nothing reported.");
        foreach (var n in r.NotCovered) sb.AppendLine("- " + n);
        sb.AppendLine();

        sb.AppendLine("## Findings");
        sb.AppendLine();
        var ordered = r.Findings
            .OrderBy(f => f.Origin == Origin.Tests)
            .ThenByDescending(f => f.Legibility)
            .ThenBy(f => f.Unused)
            .ThenByDescending(f => f.Scope == Scope.Admin)
            .ThenBy(f => f.Id);
        var grouped = new List<Finding>();
        foreach (var f in ordered)
        {
            var d = detail(f);
            if (d == Detail.Grouped) grouped.Add(f);
            else AppendFinding(sb, f, d);
        }

        // Tests counted per file: what each test file does, without a line per call. Opaque and untraced
        // findings in tests aren't counted here; they're listed like the rest.
        if (grouped.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine($"### Findings in tests, counted per file ({grouped.Count})");
            sb.AppendLine();
            foreach (var g in grouped.GroupBy(f => f.File, StringComparer.OrdinalIgnoreCase).OrderBy(g => g.Key, StringComparer.OrdinalIgnoreCase))
            {
                var kinds = g.GroupBy(f => f.Kind).OrderByDescending(k => k.Count()).ThenBy(k => k.Key)
                    .Select(k => $"{k.Count()} × {Names.Of(k.Key).ToLowerInvariant()}");
                var ids = g.OrderBy(f => f.Id).Select(f => $"#{f.Id} [{f.Key}]").ToList();
                sb.AppendLine($"- `{g.Key}`: {string.Join(", ", kinds)} ({string.Join(", ", ids)})");
            }
        }

        return sb.ToString();
    }

    /// <summary>
    /// Findings that mean more together, each with what the README says and its keys; then the
    /// checklist for before building, made from them.
    /// </summary>
    private static void AppendCombined(StringBuilder sb, ScanReport r)
    {
        sb.AppendLine("## Combined findings");
        sb.AppendLine();
        sb.AppendLine($"Findings that mean more together. A combination claims a flow (fetches and runs, sends what it reads) only where a trace shows it. " +
                      $"The README can declare one in a \"{Combined.SectionHeading}\" section (one bold label per line, such as **Changes security settings:**). " +
                      $"{Combined.DeclaredIsNotSafe} Hidden code, and code another program can plant, can't be declared.");
        sb.AppendLine();
        sb.AppendLine("- In short: " + Combined.Headline(r.Combinations));
        foreach (var c in r.Combinations)
        {
            // "Declared in README.md, line 5: …" says it already; the tag only where it adds something.
            var standing = c.Declaration.Kind is DeclarationKind.Declared && c.Expected || c.Declaration.Kind is DeclarationKind.NotFound or DeclarationKind.CantBeDeclared ? "" : c.Standing + ". ";
            sb.AppendLine($"- [{c.Key}] {c.Sentence} README: {standing}{c.Declaration.Text}");
            sb.AppendLine($"  - Findings ({c.Members.Count}): " + string.Join(", ", c.Members.Select(f => $"#{f.Id} [{f.Key}]")));
        }
        sb.AppendLine();
        var checklist = Combined.Checklist(r);
        if (checklist.Count > 0)
        {
            sb.AppendLine("### Before building");
            sb.AppendLine();
            foreach (var g in checklist)
            {
                sb.AppendLine($"{g.Heading}:");
                foreach (var item in g.Items) sb.AppendLine("- " + item);
                sb.AppendLine();
            }
        }
    }

    /// <summary>The Overview as a reader who doesn't read code sees it: each question, its answer, and the findings behind it.</summary>
    private static void AppendOverview(StringBuilder sb, ScanReport r)
    {
        if (r.Overview is not { } o) return;
        sb.AppendLine("## Overview, as shown to someone who doesn't read code");
        sb.AppendLine();
        sb.AppendLine("Check that each answer matches the findings it names.");
        sb.AppendLine();
        sb.AppendLine("- " + o.Headline);
        foreach (var a in o.Answers)
            sb.AppendLine($"- {a.Question} {a.Answer}" + (a.Findings.Count > 0
                ? " Findings: " + string.Join(", ", a.Findings.Select(f => $"#{f.Id} [{f.Key}]"))
                : ""));
        foreach (var l in o.Lines)
            sb.AppendLine($"- {l.Area}{(l.Reach.Length > 0 ? ", " + l.Reach : "")}: " + string.Join("; ", new[] { l.Reads, l.Changes }.Where(x => x is not null)
                .Select(x => $"{x!.Line} ({string.Join(", ", x.Findings.Select(f => f.Key))})")));
        sb.AppendLine();
    }

    public static string BuildCombination(ScanReport r, Combination c) => Invariant(() =>
    {
        var sb = new StringBuilder();
        sb.AppendLine($"# A combined finding from a RepoLegibility {r.ToolVersion} scan of {r.RepoName}");
        sb.AppendLine();
        sb.AppendLine($"Zip `{r.ZipName}`, SHA-256 `{r.ZipSha256}`.");
        sb.AppendLine();
        sb.AppendLine("These findings from a static scan of a C# repository mean more together. Say whether the combination holds up, what the code most likely does with it, " +
                      "whether that fits what the repository says it is for, and whether the README's declaration (if any) matches what the code does.");
        sb.AppendLine();
        sb.AppendLine($"## [{c.Key}] {c.Title}");
        sb.AppendLine();
        sb.AppendLine($"- What: {c.Sentence}");
        sb.AppendLine($"- README: {c.Declaration.Text}");
        sb.AppendLine($"- Before building: {c.Check}");
        sb.AppendLine();
        foreach (var f in c.Members.Take(12)) AppendFinding(sb, f, Detail.Full);
        foreach (var f in c.Members.Skip(12)) AppendFinding(sb, f, Detail.Line);
        return sb.ToString();
    });

    /// <summary>One finding, with enough around it to look at it on its own: a close look at an opaque item.</summary>
    private static string BuildOneText(ScanReport r, Finding f)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"# One finding from a RepoLegibility {r.ToolVersion} scan of {r.RepoName}");
        sb.AppendLine();
        sb.AppendLine($"Zip `{r.ZipName}`, SHA-256 `{r.ZipSha256}`, scanned with RepoLegibility {r.ToolVersion}.");
        sb.AppendLine();
        sb.AppendLine("Look closely at this finding from a static scan of a C# repository (it reads the source and runs nothing; values are followed by name, not by type). " +
                      "Say what the code most likely does, step by step if it's hidden; what it can reach on the machine, in the user's accounts and on the network; " +
                      "whether that fits a normal app; and what would have to be read or run to confirm it. If the code shown isn't enough, say which file or member you'd need.");
        sb.AppendLine();
        sb.AppendLine("Scope: App (its own folder), User (the user's profile, HKCU, credentials), Admin (what needs administrator rights; a read any user can do is User), Web service (remote endpoints). " +
                      "Legibility: Clear, Run time (decided when the app runs; the reasons say by what), Untraced (the scan stopped before it found where a value comes from; the reasons say where), Opaque (the source can't show it by nature), Obscured (written so it can't be read).");
        sb.AppendLine();
        AppendFinding(sb, f, Detail.Full);
        return sb.ToString();
    }

    private static void AppendFinding(StringBuilder sb, Finding f, Detail detail)
    {
        if (detail == Detail.Line)
        {
            // What decides it, short: the first reason, for anything not plainly clear.
            // What decides it is the point of the line: the first reason, never cut.
            var decider = f.Reasons.Count > 0 ? f.Reasons[0].TrimEnd('.') : null;
            var decided = f.Legibility != Legibility.Clear && decider is not null ? " · decided by: " + decider : "";
            sb.AppendLine($"- #{f.Id} [{f.Key}] {Names.Of(f.Legibility)} · {Names.Of(f.Scope)} · {Names.Of(f.Kind)}{string.Concat(f.Marks().Select(m => " · " + m))} · `{f.File}:{f.Line}` · {f.Summary}{decided}");
            return;
        }

        sb.AppendLine($"### #{f.Id} [{f.Key}] · {Names.Of(f.Legibility)} · {Names.Of(f.Scope)} · {Names.Of(f.Kind)}{string.Concat(f.Marks().Select(m => " · " + m))}");
        sb.AppendLine();
        sb.AppendLine($"- Where: `{f.File}:{f.Line}`{(f.Excerpt?.Member is { } member ? $" in `{member}`" : "")}{(f.Project is null ? "" : $" · project {f.Project}")} · {Names.Of(f.Origin)}");
        sb.AppendLine($"- Call: `{f.Call}`");
        sb.AppendLine($"- Target: {f.Target}");
        sb.AppendLine($"- What: {f.Summary}");
        if (f.LooksInside is { } inside) sb.AppendLine($"- What it looks inside: {inside}");
        if (f.WhoDecides is { } who) sb.AppendLine($"- Who decides: {who}");
        foreach (var reason in f.Reasons) sb.AppendLine($"- Where it's decided: {reason}");
        foreach (var note in f.Notes) sb.AppendLine($"- Note: {note}");
        if (f.Calls.Count > 0)
        {
            sb.AppendLine($"- Calls that decide it ({f.Calls.Count + f.CallsNotFollowed}):");
            foreach (var c in f.Calls)
                sb.AppendLine($"  - `{c.File}:{c.Line}`{(c.Via.Count > 0 ? " · " + string.Join(" ", c.Via).TrimEnd('.') : "")} · {Names.Of(c.Legibility)} · {Names.Short(c.Scope)} · {c.Target}{(c.Reason is { Length: > 0 } why ? " · " + why : "")}");
            if (f.CallsNotFollowed > 0) sb.AppendLine($"  - … {f.CallsNotFollowed} more not followed");
        }
        if (f.Trace.Count > 0)
        {
            // The nearest steps say how the scan got there; the full trace is in the app.
            sb.AppendLine(f.Trace.Count > 12 ? $"- Trace, nearest first (the first 12 of {f.Trace.Count} steps):" : "- Trace, nearest first:");
            foreach (var step in f.Trace.Take(12))
                sb.AppendLine($"  - `{step.File}:{step.Line}` `{step.Code.Replace("`", "'")}`");
        }

        if (detail == Detail.Full && f.Excerpt is { } x)
        {
            sb.AppendLine();
            sb.AppendLine(f.File.EndsWith(".cs", StringComparison.OrdinalIgnoreCase) ? "```csharp" : "```");
            int width = (x.FirstLine + x.Lines.Count).ToString(CultureInfo.InvariantCulture).Length;
            for (int i = 0; i < x.Lines.Count; i++)
            {
                int line = x.FirstLine + i;
                sb.Append(line == x.Focus ? '>' : ' ')
                  .Append(line.ToString(CultureInfo.InvariantCulture).PadLeft(width))
                  .Append(" | ")
                  .AppendLine(x.Lines[i].Replace("```", "'''"));
            }
            sb.AppendLine("```");
        }
        sb.AppendLine();
    }

    public static string Size(long bytes) => bytes switch
    {
        < 1024 => $"{bytes} bytes",
        < 1024 * 1024 => (bytes / 1024.0).ToString("0.#", CultureInfo.InvariantCulture) + " KB",
        _ => (bytes / 1024.0 / 1024.0).ToString("0.#", CultureInfo.InvariantCulture) + " MB"
    };

    public static string Hours(double hours) => hours < 1
        ? Math.Max(1, (int)Math.Round(hours * 60)).ToString(CultureInfo.InvariantCulture) + " min"
        : hours.ToString(hours < 10 ? "0.#" : "0", CultureInfo.InvariantCulture) + " h";
}
