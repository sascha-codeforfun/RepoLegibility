using System.Text.RegularExpressions;

namespace RepoLegibility.Core;

/// <summary>
/// Who decides what a finding does, in plain words, from where its trace ended: the author (written so
/// the source doesn't show it), a server on the internet, the app's settings, the user, how the app is
/// started, a file, a list in the source. Read from the finding's reasons and marks; nothing is guessed:
/// what can't be told says so.
/// </summary>
public static class WhoDecides
{
    private static readonly Regex SettingsFile = new(@"(?i)\b[\w.-]*(?:config|settings|options|preferences)[\w.-]*\.(?:json|xml|ini|config|toml|ya?ml)\b", RegexOptions.Compiled);

    /// <summary>The app's settings file, when the findings name one: "crawlersuite.config.json".</summary>
    public static string? SettingsFileOf(IEnumerable<Finding> findings) =>
        findings.Where(f => f.Origin == Origin.App && f.Kind is FindingKind.FileRead or FindingKind.FileWrite)
            .Select(f => SettingsFile.Match(f.Target)).Where(m => m.Success).Select(m => m.Value)
            .GroupBy(v => v, StringComparer.OrdinalIgnoreCase).OrderByDescending(g => g.Count()).Select(g => g.Key).FirstOrDefault();

    public static string? Of(Finding f, string? settingsFile)
    {
        if (f.Kind == FindingKind.Combination) return null;
        if (f.Legibility == Legibility.Obscured || f.HiddenOnPurpose)
        {
            var decoded = f.Reasons.Select(r => Regex.Match(r, @"worked out from the source: (?<v>.+)$")).FirstOrDefault(m => m.Success)?.Groups["v"].Value;
            return "The author, written so the source doesn't show it plainly"
                   + (f.HowHidden is { } how ? $" ({how})" : "")
                   + (decoded is not null ? $". The scan worked it out: {Tracer.Clip(decoded, 120)}." : ".");
        }
        if (f.Legibility == Legibility.Clear) return null;

        // Code loaded from a file: whatever that file holds when it runs; the source can't say what that is.
        if (f.Kind == FindingKind.LoadsCode && f.Target is { Length: > 0 } t && t != Finding.NotTraced && !t.Contains("memory", StringComparison.Ordinal))
            return $"Whatever is in the file it loads ({Tracer.Clip(t, 80)}) when it runs; the source can't say what that is.";

        var text = string.Join(" \n ", f.Reasons) + " \n " + f.Target + " \n " + f.Summary;
        var who = new List<string>();

        if (Regex.IsMatch(text, @"(?i)\b(?:web response|downloaded|from the (?:web|internet)|server's (?:answer|response)|GetString(?:Async)?|ReadAsString|DownloadString|DownloadData|GetByteArray)\b"))
            who.Add("a server on the internet: what happens is decided outside your computer");
        if (Regex.IsMatch(text, @"(?i)\ba setting\b|, a setting in |filled from JSON|from the settings|settings file|IConfiguration|appsettings"))
            who.Add("the app's settings, which you can change in the app or in its settings file" + (settingsFile is null ? "" : $" ({settingsFile})"));
        // A list in a window: say which, so it can be found on screen.
        var lists = Regex.Matches(text, @"picks in a list in the window: (?<w>.+?)(?:;|\.\s*(?:\n|$))").Select(m => m.Groups["w"].Value).Distinct().ToList();
        if (lists.Count > 0)
            who.Add("you, by what you pick in a list in the app (" + Tracer.Clip(string.Join(", ", lists), 160) + ")");
        else
        {
            // Each way you hand it something, named: a file you pick, files you drop onto the window, what you type.
            var ways = new List<string>();
            if (Regex.IsMatch(text, @"(?i)a file or folder the user picks|\buser (?:picks|chooses)\b")) ways.Add("a file or folder you pick");
            if (Regex.IsMatch(text, @"(?i)drops onto the window")) ways.Add("files you drop onto the window");
            if (Regex.IsMatch(text, @"(?i)what the user types|\buser (?:types|enters)\b|a (?:path|folder) the user types")) ways.Add("what you type");
            if (ways.Count == 0 && Regex.IsMatch(text, @"(?i)\bby binding\b")) ways.Add("what you type or pick in the app");
            if (ways.Count > 0)
                who.Add("you, through " + (ways.Count == 1 ? ways[0] : string.Join(", ", ways.Take(ways.Count - 1)) + " or " + ways[^1]));
        }
        if (Regex.IsMatch(text, @"(?i)\bcommand line\b|\benvironment variable\b"))
            who.Add("how the app is started (its command line or environment)");
        if (Regex.IsMatch(text, @"(?i)files found in a folder|found at run time in"))
            who.Add("which files are in a folder when it runs");
        if (Regex.IsMatch(text, @"(?i)\bread from (?:a|the) file\b|\bcontents of a file\b|\bfrom a file it reads\b"))
            who.Add("the contents of a file it reads");
        if (Regex.IsMatch(text, @"(?i)\bregistry value\b|\bread from the registry\b"))
            who.Add("a value in the registry");
        var list = Regex.Match(text, @"one of (?<n>\d+) values set where");
        if (list.Success)
            who.Add($"one of {list.Groups["n"].Value} values written in the source; which one, the app picks while it runs");
        if (who.Count == 0 && Regex.IsMatch(text, @"(?i)\bcaller decides\b|\bdecided by the caller\b|calls? that decide"))
            who.Add("the code that calls it; see its calls");

        if (who.Count == 0)
            return f.Legibility == Legibility.Untraced
                ? "The scan couldn't tell: the trace stopped before it found out."
                : Regex.IsMatch(text, @"(?i)set at run time|computed at run time|chosen at run time")
                    ? "The app itself, while it runs; the scan can't tell from what."
                    : null;
        var line = string.Join("; and ", who.Distinct().Take(3));
        // Some of the calls weren't traced: the answer covers the others, and says so.
        var untraced = Regex.Match(text, @"(?<n>\d+) untraced");
        if (untraced.Success) line += $" ({untraced.Groups["n"].Value} of the calls the scan couldn't trace)";
        return char.ToUpperInvariant(line[0]) + line[1..] + ".";
    }
}
