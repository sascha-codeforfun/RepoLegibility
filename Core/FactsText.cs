using System.Globalization;

namespace RepoLegibility.Core;

/// <summary>
/// The Facts in plain words, shared by the window and the PDF: one sentence on top, then rows that say
/// something (rows that would only say "none" or "0" are left out), each group answering one question.
/// </summary>
public static class FactsText
{
    /// <summary>"About 101,000 lines of C# in 3 projects, 40 % of them tests. A careful review takes …".</summary>
    public static string Headline(ScanReport r)
    {
        var m = r.Metrics;
        if (m.Sloc == 0) return "No C# in this repo.";
        var lines = m.Sloc < 1000 ? $"{m.Sloc:N0} lines of C#" : $"About {Round(m.Sloc):N0} lines of C#";
        var projects = r.Projects.Count switch { 0 => "", 1 => " in 1 project", var n => $" in {n} projects" };
        int testShare = (int)Math.Round(100.0 * m.TestSloc / m.Sloc);
        var tests = m.TestSloc == 0 ? ", none of them tests" : testShare >= 1 ? $", {testShare} % of them tests" : ", a few of them tests";
        return $"{lines}{projects}{tests}. A careful review takes {Reading(m.ReviewHours.Low, m.ReviewHours.High)}.";
    }

    /// <summary>Hours a reader can picture: minutes, hours, days or weeks of full-time reading, the hours in brackets.</summary>
    public static string Reading(double low, double high)
    {
        string Hours(double h) => AiExport.Hours(h).Replace(" h", "", StringComparison.Ordinal);
        if (high < 1) return $"about {AiExport.Hours(high)}";
        if (high <= 16) return $"{Hours(low)} to {Hours(high)} hours";
        if (high <= 80) return $"roughly {Days(low)} to {Days(high)} days of full-time reading ({Hours(low)} to {Hours(high)} hours)";
        return $"roughly {Weeks(low)} to {Weeks(high)} weeks of full-time reading ({Hours(low)} to {Hours(high)} hours)";
    }

    private static string Days(double hours) => Math.Max(1, (int)Math.Round(hours / 8)).ToString(CultureInfo.CurrentCulture);
    private static string Weeks(double hours) => Math.Max(1, (int)Math.Round(hours / 40)).ToString(CultureInfo.CurrentCulture);

    private static int Round(int n) => n < 10_000 ? (int)Math.Round(n / 100.0) * 100 : (int)Math.Round(n / 1000.0) * 1000;

    /// <summary>How big it is: only rows that say something.</summary>
    public static List<(string Label, string Value)> Size(ScanReport r)
    {
        var m = r.Metrics;
        var rows = new List<(string, string)>
        {
            ("Files", $"{m.Files:N0} files ({AiExport.Size(m.Bytes)}), {m.CsFiles:N0} of them C#"),
            ("Reading time", char.ToUpperInvariant(Reading(m.ReviewHours.Low, m.ReviewHours.High)[0]) + Reading(m.ReviewHours.Low, m.ReviewHours.High)[1..]
                             + ", at 200 to 400 lines an hour")
        };
        if (m.XamlLines > 0) rows.Add(("XAML", $"{m.XamlLines:N0} lines of window layout"));
        if (m.GeneratedFiles > 0) rows.Add(("Generated", $"{m.GeneratedSloc:N0} lines in {m.GeneratedFiles} file{(m.GeneratedFiles == 1 ? "" : "s")}, made by tools and not counted"));
        if (m.PInvokes > 0 || m.UnsafeBlocks > 0 || m.UnsafeAllowedIn.Count > 0)
        {
            var parts = new List<string>();
            if (m.PInvokes > 0) parts.Add($"{m.PInvokes} call{(m.PInvokes == 1 ? "" : "s")} into Windows or other machine code (P/Invoke)");
            if (m.UnsafeBlocks > 0) parts.Add($"unsafe code in {m.UnsafeBlocks} place{(m.UnsafeBlocks == 1 ? "" : "s")}");
            if (m.UnsafeAllowedIn.Count > 0) parts.Add("unsafe code allowed in " + string.Join(", ", m.UnsafeAllowedIn.Select(System.IO.Path.GetFileName)));
            rows.Add(("Native code", string.Join("; ", parts)));
        }
        return rows;
    }

    /// <summary>The C# split three ways: app code, tests, comments. Lines, not files.</summary>
    public static (int App, int Tests, int Comments) Split(ScanReport r) => (r.Metrics.AppSloc, r.Metrics.TestSloc, r.Metrics.CommentLines);

    public static string SplitText(ScanReport r)
    {
        var (app, tests, comments) = Split(r);
        var parts = new List<string> { $"{app:N0} lines of app code" };
        if (tests > 0) parts.Add($"{tests:N0} of tests");
        if (comments > 0) parts.Add($"{comments:N0} of comments");
        return string.Join(", ", parts);
    }

    /// <summary>What a project kind is, in plain words.</summary>
    public static string ProjectKind(string kind) => kind switch
    {
        "Tests" => "Code that checks the rest. Not part of the app you run.",
        "App (exe)" => "The program itself: what you start.",
        _ => "Code the program uses, built into it."
    };

    /// <summary>What the scan covered: findings per 1,000 lines, where there are any.</summary>
    public static List<(string Label, string Value)> Coverage(ScanReport r)
    {
        var m = r.Metrics;
        var rows = new List<(string, string)>
        {
            ("Findings in the app", $"{r.AppDensity.ToString("0.0", CultureInfo.CurrentCulture)} per {1000:N0} lines of C# ({r.CodeFindings:N0} in {m.AppSloc:N0} lines)")
        };
        if (m.TestSloc > 0)
            rows.Add(("Findings in tests", $"{r.TestDensity.ToString("0.0", CultureInfo.CurrentCulture)} per {1000:N0} lines ({r.TestFindings:N0} in {m.TestSloc:N0} lines)"));
        if (r.OtherFindings > 0)
            rows.Add(("Build, CI, config", $"{r.OtherFindings:N0} finding{(r.OtherFindings == 1 ? "" : "s")}, not counted per line"));
        return rows;
    }
}
