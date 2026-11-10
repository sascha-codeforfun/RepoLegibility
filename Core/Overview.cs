using System.Text.RegularExpressions;

namespace RepoLegibility.Core;

/// <summary>One cell of the overview: what the findings do there, in plain words, and which they are.</summary>
public sealed record OverviewCell(string Verb, IReadOnlyList<Finding> Findings, string Text)
{
    public int Count => Findings.Count;
    /// <summary>"changes 53: Windows Firewall settings, …".</summary>
    public string Line => $"{Verb} {Count}" + (Text.Length > 0 ? ": " + Text : "");
}

/// <summary>A row of the overview: an area (the registry, files, the internet), how far it reaches, and its two cells.</summary>
public sealed record OverviewLine(string Area, string Reach, string Tech, OverviewCell? Reads, OverviewCell? Changes)
{
    public IEnumerable<Finding> All => (Reads?.Findings ?? []).Concat(Changes?.Findings ?? []);
}

/// <summary>A plain question with its answer, and the findings behind the answer.</summary>
/// <param name="Serious">Rests on code written to be hard to read, or on a server deciding what runs: the red dot.</param>
public sealed record OverviewAnswer(string Question, string Answer, IReadOnlyList<Finding> Findings, bool Notable, bool Serious = false);

/// <summary>
/// The report for someone who doesn't read code: plain questions, then what the app reads and
/// changes, area by area, the technical term in brackets. Every line points to its findings.
/// </summary>
public sealed class Overview
{
    public required string Headline { get; init; }
    public required IReadOnlyList<OverviewAnswer> Answers { get; init; }
    public required IReadOnlyList<OverviewLine> Lines { get; init; }

    private static readonly Regex AdminTool = new(@"^(?:schtasks|sc|netsh|bcdedit|icacls|takeown|vssadmin|wevtutil|diskpart|dism|msiexec|shutdown|net|net1|reg|pnputil|fsutil|wmic|certutil|bitsadmin|ipconfig|wusa|sfc|cmd)$", RegexOptions.Compiled);
    private static readonly Regex PolicyTool = new(@"^(?:gpupdate|secedit|auditpol|lgpo)$", RegexOptions.Compiled);

    private static readonly Dictionary<string, string> ToolWords = new(StringComparer.OrdinalIgnoreCase)
    {
        ["netsh"] = "network and firewall settings", ["reg"] = "the registry", ["schtasks"] = "scheduled tasks",
        ["sc"] = "Windows services", ["bcdedit"] = "boot settings", ["icacls"] = "file permissions", ["takeown"] = "file ownership",
        ["vssadmin"] = "restore points", ["wevtutil"] = "event logs", ["diskpart"] = "disks", ["dism"] = "Windows features",
        ["msiexec"] = "installs software", ["shutdown"] = "shuts down or restarts", ["net"] = "users, shares and services",
        ["pnputil"] = "drivers", ["fsutil"] = "the file system", ["ipconfig"] = "network settings", ["wmic"] = "system information",
        ["certutil"] = "certificates", ["bitsadmin"] = "background downloads", ["cmd"] = "command prompt",
        ["gpupdate"] = "applies group policy", ["secedit"] = "security policy", ["auditpol"] = "audit policy", ["lgpo"] = "local group policy",
        ["explorer"] = "opens folders and files", ["powershell"] = "PowerShell", ["start"] = "starts another program"
    };

    public static Overview Build(ScanReport report, IReadOnlyList<Combination> combinations, Func<string, Declaration?>? declares = null, bool hasReadme = false, string? securityWriting = null)
    {
        // The shipped app: not tests, not what's only declared, not script files nothing is shown to start.
        var findings = report.Counted.Where(f => !f.Unused && f.Call != "script file" && f.Origin != Origin.CI).ToList();
        var lines = new List<OverviewLine>();

        // Registry and group policy, by reach.
        foreach (var (reach, tech, test) in new (string, string, Func<Finding, bool>)[]
                 {
                     ("whole computer", "HKLM", f => !IsUserHive(f)),
                     ("your account", "HKCU", IsUserHive)
                 })
        {
            var reg = findings.Where(f => f.Kind is FindingKind.RegistryRead or FindingKind.RegistryWrite && !IsPolicy(f) && test(f)).ToList();
            AddLine(lines, "Registry", reach, tech, reg, f => f.Kind == FindingKind.RegistryWrite, RegistryWords);
        }
        foreach (var (reach, tech, test) in new (string, string, Func<Finding, bool>)[]
                 {
                     ("whole computer", "machine policy", f => !IsUserHive(f) && !f.Target.Contains("User\\Registry.pol", StringComparison.OrdinalIgnoreCase)),
                     ("your account", "user policy", f => IsUserHive(f) || f.Target.Contains("User\\Registry.pol", StringComparison.OrdinalIgnoreCase))
                 })
        {
            var policy = findings.Where(f => IsPolicy(f) && test(f)).ToList();
            AddLine(lines, "Group policy", reach, tech, policy, f => f.Direction.HasFlag(Direction.Changes) || f.Direction.HasFlag(Direction.Runs), PolicyWords);
        }

        // Files, by reach.
        var files = findings.Where(f => f.Kind is FindingKind.FileRead or FindingKind.FileWrite or FindingKind.FileDelete or FindingKind.FolderListing
                                        && !IsPolicy(f) && !IsShare(f)).ToList();
        AddLine(lines, "Files", "whole computer", "Program Files, ProgramData, Windows", files.Where(f => f.Scope == Scope.Admin || f.MachineWide).ToList(), IsChange, FileWords);
        AddLine(lines, "Files", "your account", "your profile, documents, temp", files.Where(f => f.Scope is Scope.User or Scope.WebService && !f.MachineWide).ToList(), IsChange, FileWords);
        AddLine(lines, "Files", "its own folder", "next to the exe", files.Where(f => f.Scope == Scope.App).ToList(), IsChange, FileWords);

        // The network: out on the internet, the local network, or wherever the address points.
        var net = findings.Where(f => f.Kind is FindingKind.Network or FindingKind.Listens or FindingKind.Database && f.Direction != Direction.Runs || IsShare(f)).ToList();
        AddNet(lines, "Internet", "addresses outside the local network", net.Where(f => Where(f) == NetPlace.Internet).ToList());
        AddNet(lines, "Local network", "local addresses, shares, sockets, listening", net.Where(f => Where(f) == NetPlace.Local).ToList());
        AddNet(lines, "Internet or local network", "address decided while it runs", net.Where(f => Where(f) == NetPlace.Either).ToList());

        // Programs: PowerShell, system tools, anything else; and code it loads.
        // An elevation finding is a program only where it starts one (runas); the manifest and admin checks are the first question.
        var programs = findings.Where(f => (f.Kind == FindingKind.Process || f.Kind == FindingKind.Elevation && f.Program is not null) && f.Direction.HasFlag(Direction.Runs)
                                           && !(f.Program is { } p && PolicyTool.IsMatch(p))).ToList();
        var ps = programs.Where(f => f.Program is "powershell" or "pwsh").ToList();
        var tools = programs.Where(f => !ps.Contains(f) && f.Program is { } p && AdminTool.IsMatch(p)).ToList();
        // Web pages opened in the browser are programs started too: the browser.
        var other = programs.Where(f => !ps.Contains(f) && !tools.Contains(f))
            .Concat(findings.Where(f => f.Kind == FindingKind.Network && f.Direction == Direction.Runs))
            // Native code that starts programs: ShellExecuteW, CreateProcessW, the Open with dialog.
            .Concat(findings.Where(f => f.Kind == FindingKind.NativeCode && !f.Unused && f.Notes.Any(n => NativeStarts.IsMatch(n)))).ToList();
        if (ps.Count > 0) lines.Add(new OverviewLine("Programs", "PowerShell", "powershell.exe", null, new OverviewCell("starts", ps, PowerShellWords(ps))));
        if (tools.Count > 0) lines.Add(new OverviewLine("Programs", "system tools", ClipWords(string.Join(", ", tools.Select(f => f.Program).Distinct()), 60), null,
            new OverviewCell("starts", tools, ToolsText(tools))));
        if (other.Count > 0) lines.Add(new OverviewLine("Programs", "other programs", "", null, new OverviewCell("starts", other, OtherText(other))));
        var loads = findings.Where(f => f.Kind == FindingKind.LoadsCode).ToList();
        if (loads.Count > 0) lines.Add(new OverviewLine("Programs", "code it loads", "Assembly.Load and the like", null,
            new OverviewCell("loads", loads, Examples(loads.Select(f => f.Target)))));

        return new Overview
        {
            Headline = Combined.Headline(combinations),
            Answers = Ask(report, findings, combinations, lines, declares ?? (_ => null), hasReadme, securityWriting),
            Lines = lines
        };
    }

    // ---- the questions -------------------------------------------------------------------------

    private static List<OverviewAnswer> Ask(ScanReport report, List<Finding> findings, IReadOnlyList<Combination> combinations, List<OverviewLine> lines,
        Func<string, Declaration?> declares, bool hasReadme, string? securityWriting)
    {
        var adminDeclared = declares(Combined.AdminLabel);
        // Declared or not, it needs the rights all the same: the README only says the author meant it.
        string declaredAdmin = adminDeclared is { } d ? $" The README declares it ({d.File}, line {d.Line})." : "";
        var answers = new List<OverviewAnswer>();

        var manifest = findings.Where(f => f.Kind == FindingKind.Elevation && f.Call.StartsWith("requestedExecutionLevel", StringComparison.Ordinal)).ToList();
        var runas = findings.Where(f => f.AsAdministrator && f.Scope == Scope.Admin && f.Program is not null).ToList();
        answers.Add(manifest.Count > 0
            ? new OverviewAnswer("Does it need administrator rights?",
                "Yes: it asks Windows for them when it starts" + (manifest[0].Target.Contains("highest", StringComparison.OrdinalIgnoreCase) || manifest[0].Call.Contains("highestAvailable", StringComparison.Ordinal)
                    ? ", where the user has them (highestAvailable)." : " (requireAdministrator).") + declaredAdmin, manifest, true)
            : runas.Count > 0
                ? new OverviewAnswer("Does it need administrator rights?", $"It starts {Plural(runas.Count, "program")} as administrator (runas); Windows asks first." + declaredAdmin, runas, true)
                : new OverviewAnswer("Does it need administrator rights?", "No: nothing in the source asks for them.", [], false));

        var stays = combinations.FirstOrDefault(c => c.Rule == "stays");
        // It doesn't keep running: it starts again, at login or on a schedule. Ask what happens.
        answers.Add(stays is null
            ? new OverviewAnswer("Does it start on its own?", "No: no scheduled task, service, Run key or Startup entry found.", [], false)
            : new OverviewAnswer("Does it start on its own?", (stays.Maybe ? "Possibly: it " : "Yes: ") + After(stays.Sentence), stays.Members, true));

        // Security settings first (the firewall turned off is the widest change of all), then registry and files.
        var security = findings.Where(f => Combined.ChangesSecurity(f) && f.Origin == Origin.App).ToList();
        var changesComputer = security.Concat(lines.Where(l => l.Reach == "whole computer" && l.Changes is { Count: > 0 })
            .SelectMany(l => l.Changes!.Findings).Where(f => !security.Contains(f)))
            // RegLoadKey: a hive file mounted under HKLM or HKU, there for everyone until it's unloaded.
            .Concat(findings.Where(MountsHive)).ToList();
        // Writes and deletes in a place the user chooses, said once with what goes there, rather than "a path the
        // user types" again for each: "writes and deletes in a folder you choose: NTUSER-{}.DAT; SOFTWARE, …".
        var chosen = changesComputer.Where(f => f.Kind is FindingKind.FileWrite or FindingKind.FileDelete && ChosenPlaces(f.Target) is { Count: > 0 }).ToList();
        var named = new List<string>();
        if (chosen.Count > 1)
        {
            var verbs = chosen.Select(f => f.Kind == FindingKind.FileDelete ? "deletes" : "writes").Distinct().OrderByDescending(v => v).ToList();
            var names = chosen.SelectMany(f => ChosenPlaces(f.Target)!).Where(n => n.Length > 0).Distinct().ToList();
            named.Add(string.Join(" and ", verbs) + " in a folder you choose" + (names.Count > 0 ? " (" + string.Join("; ", names.Take(4)) + (names.Count > 4 ? "; …" : "") + ")" : ""));
        }
        else chosen.Clear();
        named.AddRange(changesComputer.Where(f => !chosen.Contains(f)).Select(Change));
        named = named.Distinct().ToList();
        // SAM and SECURITY: what the hives hold, and that it can save them to files.
        var secrets = findings.Where(f => f.Notes.Any(n => n.StartsWith("The SAM hive", StringComparison.Ordinal) || n.StartsWith("The SECURITY hive", StringComparison.Ordinal))).ToList();
        bool saves = findings.Any(f => f.Kind == FindingKind.NativeCode && !f.Unused && (Regex.IsMatch(f.Target, @"›\s*RegSaveKey") || f.Notes.Any(n => Regex.IsMatch(n, @"^Called:.*\bRegSaveKey"))));
        string secretLine = secrets.Count == 0 ? ""
            : " It reads the " + (secrets.Any(f => f.Notes.Any(n => n.StartsWith("The SECURITY hive", StringComparison.Ordinal))) ? "SAM and SECURITY hives (local accounts' password hashes, the system's stored secrets)" : "SAM hive (local accounts' password hashes)")
              + (saves ? " and can save registry hives to files." : ".");
        var shown = changesComputer.Concat(secrets).Distinct().ToList();
        answers.Add(changesComputer.Count > 0
            ? new OverviewAnswer("Does it change things for everyone on this computer?",
                // 67 places, 46 different changes: "and 42 more" counts changes, so say both counts.
                $"Yes: {Plural(changesComputer.Count, "place")} in the code change the whole computer"
                + (named.Count < changesComputer.Count && named.Count > 4 ? $", {named.Count} different changes" : "") + ": " + string.Join("; ", named.Take(4))
                + (named.Count > 4 ? $"; and {named.Count - 4} more" : "") + "." + secretLine,
                shown, true)
            : new OverviewAnswer("Does it change things for everyone on this computer?", "No: it changes nothing machine-wide.", [], false));

        var internet = lines.Where(l => l.Area.StartsWith("Internet", StringComparison.Ordinal)).SelectMany(l => l.All).Distinct().ToList();
        var sends = internet.Where(f => f.Direction.HasFlag(Direction.Sends) && f.Kind == FindingKind.Network && !f.Summary.StartsWith("Looks up", StringComparison.Ordinal)).ToList();
        bool onlyMaybe = internet.Count > 0 && lines.Where(l => l.Area == "Internet").All(l => !l.All.Any());
        // Not itself, but through a program it starts (dotnet publish fetching packages) or the pages it opens in the
        // browser: said, so "No" isn't read as "nothing goes out".
        var viaPrograms = findings.Where(f => f.Kind == FindingKind.Process && f.Origin == Origin.App && !f.Unused && NetworkProgram(f) is not null).ToList();
        var pages = findings.Where(f => f.Kind == FindingKind.Network && f.Origin == Origin.App && !f.Unused
                                        && f.Summary.Contains("in the browser", StringComparison.Ordinal)).ToList();
        string Through()
        {
            var parts = new List<string>();
            var programs = viaPrograms.Select(f => NetworkProgram(f)!).Distinct().ToList();
            if (programs.Count > 0) parts.Add("it starts " + string.Join("; and ", programs));
            int distinct = pages.Select(f => f.Target).Distinct(StringComparer.OrdinalIgnoreCase).Count();
            if (distinct > 0) parts.Add($"it opens {(distinct == 1 ? "a web page" : $"{distinct} web pages")} in your browser");
            return string.Join("; and ", parts);
        }
        answers.Add(internet.Count == 0 && (viaPrograms.Count > 0 || pages.Count > 0)
            ? new OverviewAnswer("Does it go on the internet?", "Not itself: no connection of its own. But " + Through() + ".",
                viaPrograms.Concat(pages).ToList(), viaPrograms.Count > 0)
            : internet.Count == 0
            ? new OverviewAnswer("Does it go on the internet?", "No: no internet address or connection found.", [], false)
            : onlyMaybe
                ? new OverviewAnswer("Does it go on the internet?",
                    $"Possibly: it connects to addresses decided while it runs: {Hosts(internet)}. They could be on the internet or on the local network.", internet, true, internet.Any(Serious))
            : new OverviewAnswer("Does it go on the internet?",
                // Where it sends leads, with what it sends; the rest is named too, so every finding the answer lists is
                // in its text, each address marked where the source hides it.
                "Yes: " + (sends.Count > 0
                    ? (sends.FirstOrDefault(f => f.Sends is not null) is { } s ? $"it sends {s.Sends} to " : "it sends to ") + MarkedHosts(sends)
                      + (internet.Except(sends).ToList() is { Count: > 0 } others
                          ? $"; and {(others.All(f => f.Summary.StartsWith("Looks up", StringComparison.Ordinal)) ? "looks up" : "receives from")} {(others.Count == 1 ? "1 more" : $"{others.Count} more")}: {MarkedHosts(others)}"
                          : "")
                    : internet.All(f => f.Summary.StartsWith("Looks up", StringComparison.Ordinal))
                        ? $"it looks up {Hosts(internet)}; nothing is sent"
                        : $"it connects to {Hosts(internet)}"
                          + (internet.Any(f => f.Legibility == Legibility.Obscured) ? "; an address written so the source doesn't show it plainly" : ""))
                + ".",
                internet, sends.Count > 0 || internet.Any(Serious), internet.Any(Serious)));

        // Two different things: written to be hard to read (obscured, the author's choice), and what the source
        // can't show by nature (opaque: settings, a computed name). Obscured is the one to read first.
        var obscured = findings.Where(f => f.Legibility == Legibility.Obscured).ToList();
        var opaque = findings.Where(f => f.Legibility == Legibility.Opaque).ToList();
        // Each says what it depends on, from its own "who decides"; CI's are counted apart (they run on CI, not here).
        var ciOpaqueFindings = report.Counted.Where(f => f.Legibility == Legibility.Opaque && f.Origin == Origin.CI && !opaque.Contains(f)).ToList();
        var ciOpaque = ciOpaqueFindings.Count;
        var byNature = opaque.Count == 0 ? ""
            : $"{Plural(opaque.Count, "passage")} in the app can't be read in the source by nature" + (EachWho(opaque) is { Length: > 0 } who ? $": {who}" : "") + "."
              + (ciOpaque > 0 ? $" {ciOpaque} more in CI." : "");
        // Untraced isn't hidden, but it isn't shown either: the answer mustn't claim the source shows it all.
        var untraced = findings.Where(f => f.Legibility == Legibility.Untraced).ToList();
        var notFound = untraced.Count == 0 ? ""
            : $" For {Plural(untraced.Count, "place")} the scan didn't find what decides {(untraced.Count == 1 ? "it" : "them")}; read {(untraced.Count == 1 ? "it" : "those")} to finish the trace.";
        answers.Add(obscured.Count > 0
            ? new OverviewAnswer("Is anything hidden in the code?",
                $"Yes: {Plural(obscured.Count, "passage")} {(obscured.Count == 1 ? "is" : "are")} written so the source doesn't show {(obscured.Count == 1 ? "it" : "them")} plainly"
                + (report.Decoded > 0 ? $"; the scan worked out {report.Decoded}" : "") + ". Read these first." + (byNature.Length > 0 ? " Besides, " + char.ToLowerInvariant(byNature[0]) + byNature[1..] : "") + notFound,
                // Every passage the answer speaks of is listed: obscured first, then those that can't be read by nature
                // (the app's, then CI's), then those the scan didn't finish.
                obscured.Concat(opaque).Concat(ciOpaqueFindings).Concat(untraced).Distinct().ToList(), true, true)
            : opaque.Count > 0
                ? new OverviewAnswer("Is anything hidden in the code?", "No: nothing is written to be hard to read. " + byNature + notFound, opaque.Concat(ciOpaqueFindings).Concat(untraced).Distinct().ToList(), true)
            : untraced.Count > 0
                ? new OverviewAnswer("Is anything hidden in the code?", "No: nothing is written to be hard to read." + notFound, untraced, false)
                : new OverviewAnswer("Is anything hidden in the code?", "No: nothing is written to be hard to read, and the source shows what everything does or who decides it.", [], false));

        // What a README must declare: the combinations it can, and administrator rights. What it could also
        // declare (warn, not fail, as AppConsistency checks it): other programs, the whole computer, the network.
        var declarable = combinations.Where(c => c.Declaration.Kind != DeclarationKind.CantBeDeclared).ToList();
        int cant = combinations.Count - declarable.Count;
        string notDeclarable = cant == 0 ? "" : $" {cant} more can't be declared away.";
        // Where the author writes about security: a pointer, never a verdict, and it changes nothing above.
        if (securityWriting is not null) notDeclarable += " " + securityWriting;
        bool needsAdmin = manifest.Count > 0 || runas.Count > 0;
        var adminFindings = manifest.Count > 0 ? manifest : runas;
        int mustCount = declarable.Count + (needsAdmin ? 1 : 0);
        int declaredCount = declarable.Count(c => c.Declaration.Kind == DeclarationKind.Declared) + (needsAdmin && adminDeclared is not null ? 1 : 0);
        var members = declarable.SelectMany(c => c.Members).Concat(needsAdmin ? adminFindings : []).Distinct().ToList();

        var couldAlso = new List<string>();
        bool startsPrograms = lines.Any(l => l.Area == "Programs" && l.Reach != "code it loads");
        bool network = lines.Any(l => l.Area.Contains("network", StringComparison.OrdinalIgnoreCase) || l.Area.StartsWith("Internet", StringComparison.Ordinal));
        if (startsPrograms && declares(Combined.ProgramsLabel) is null) couldAlso.Add("starts other programs");
        if (changesComputer.Count > 0 && declares(Combined.WholeComputerLabel) is null) couldAlso.Add("changes the whole computer");
        if (network && declares(Combined.NetworkLabel) is null) couldAlso.Add("talks to other computers");
        string also = couldAlso.Count == 0 ? ""
            : $" It could also declare that it {(couldAlso.Count == 1 ? couldAlso[0] : string.Join(", ", couldAlso.Take(couldAlso.Count - 1)) + " and " + couldAlso[^1])}.";

        var openItems = (needsAdmin && adminDeclared is null ? new[] { "needs administrator rights" } : [])
            .Concat(declarable.Where(c => c.Declaration.Kind != DeclarationKind.Declared).Select(c => Lower(c.Title))).ToList();
        // Two read as a sentence ("that it needs administrator rights and changes security settings"); more as a list,
        // counted the way the headline counts: the things worth knowing together, and administrator rights apart, so
        // "6 a README could declare" up there isn't "7 things" down here.
        string MustName() => openItems.Count <= 2
            ? "that it " + string.Join(" and ", openItems)
            : Things();
        string Things()
        {
            var combos = declarable.Where(c => c.Declaration.Kind != DeclarationKind.Declared).Select(c => Lower(c.Title)).ToList();
            bool adminOpen = needsAdmin && adminDeclared is null;
            string head = combos.Count == 0 ? ""
                : combos.Count == declarable.Count
                    ? (combos.Count == 1 ? "the one thing worth knowing together" : $"the {combos.Count} things worth knowing together") + ": " + string.Join("; ", combos)
                    : $"{combos.Count} of the things worth knowing together: " + string.Join("; ", combos);
            return head.Length == 0 ? "that it needs administrator rights"
                : head + (adminOpen ? "; and that it needs administrator rights" : "");
        }

        if (mustCount == 0)
            answers.Add(new OverviewAnswer("Does the README say what it changes?",
                (couldAlso.Count == 0 ? "Nothing here a README could declare." : "Nothing it must declare." + also) + notDeclarable, [], false));
        else if (!hasReadme)
            answers.Add(new OverviewAnswer("Does the README say what it changes?",
                (openItems.Count <= 2 ? $"No: the repo has no README to declare {MustName()}." : $"No: the repo has no README. It could declare {Things()}.") + also + notDeclarable, members, true));
        else if (declaredCount == mustCount)
            answers.Add(new OverviewAnswer("Does the README say what it changes?",
                $"Yes, for {(mustCount == 1 ? "the one thing" : mustCount == 2 ? "both things" : $"all {mustCount} things")} a README should declare."
                + (declarable.Any(c => c.Declaration.Gaps.Count > 0) ? " Some lines don't name everything the code does." : "")
                + " " + Combined.DeclaredIsNotSafe + also + notDeclarable, members, false));
        else
            answers.Add(new OverviewAnswer("Does the README say what it changes?",
                (declaredCount == 0 ? (openItems.Count <= 2
                        ? $"No: the README doesn't declare {MustName()} in a \"{Combined.SectionHeading}\" section."
                        : $"No: the README doesn't declare, in a \"{Combined.SectionHeading}\" section, {Things()}.")
                    : $"Partly: {declaredCount} of {mustCount} things a README should declare are declared, but not {MustName()}.") + also + notDeclarable,
                members, true));
        return answers;
    }

    /// <summary>
    /// A program it starts that goes on the network by what it does, where the source shows the program and what it's
    /// told to do: "dotnet (publish), which downloads packages from nuget.org when they're missing". Null otherwise.
    /// </summary>
    internal static string? NetworkProgram(Finding f)
    {
        var program = Regex.Match(f.Target, @"^\s*""?(?:[^""\s]*[\\/])?(?<p>[\w.-]+?)(?:\.exe)?(?=[\s""]|$)").Groups["p"].Value.ToLowerInvariant();
        // What it's told: the literals on its trace that start with a word, and the target.
        var said = f.Target + " " + string.Join(" ", f.Trace.SelectMany(t => Regex.Matches(t.Code, @"""(?<w>[^""]*)""").Select(m => m.Groups["w"].Value)));
        string? Verb(string pattern) => Regex.Match(said, @"(?i)(?:^|[\s""])(?<v>" + pattern + @")(?=[\s""]|$)") is { Success: true } m ? m.Groups["v"].Value.ToLowerInvariant() : null;
        return program switch
        {
            "dotnet" when Verb("restore|build|publish|run|test|pack|tool|workload|add") is { } v =>
                $"dotnet ({v}), which downloads packages from nuget.org when they're missing",
            "git" when Verb("clone|fetch|pull|push|ls-remote|submodule") is { } v => $"git ({v}), which talks to the repository's server",
            "curl" or "wget" => $"{program}, which downloads from the addresses it's given",
            "winget" or "choco" or "scoop" => $"{program}, which downloads and installs software",
            "npm" or "yarn" or "pnpm" or "pip" or "pip3" or "nuget" => $"{program}, which downloads packages",
            "powershell" or "pwsh" when Verb("Invoke-WebRequest|Invoke-RestMethod|iwr|irm|Start-BitsTransfer") is { } v => $"PowerShell ({v}), which downloads from the internet",
            _ => null
        };
    }

    /// <summary>A change to the whole computer in a few words: "turns off Windows Firewall for all profiles", "writes HKLM › SOFTWARE\Shady".</summary>
    private static string Change(Finding f) => f.Kind switch
    {
        FindingKind.NativeCode when MountsHive(f) => "mounts a registry hive file under HKLM or HKU while it reads it (RegLoadKey)",
        FindingKind.Process or FindingKind.Elevation when f.Summary.Contains(':') => Lower(f.Summary[..f.Summary.IndexOf(':')]),
        _ when f.Target == Finding.NotTraced => (f.Kind switch
        {
            FindingKind.FileDelete => "deletes files",
            FindingKind.RegistryWrite => "writes registry keys",
            FindingKind.FileWrite => "writes files",
            _ => Lower(f.Summary.TrimEnd('.'))
        }) + $" the scan couldn't trace ({f.File}:{f.Line})",
        FindingKind.RegistryWrite => "writes " + f.Target,
        FindingKind.FileDelete when Regex.IsMatch(f.Target, @"^\d+ places: ") => "deletes in " + ClipWords(f.Target, 90),
        FindingKind.FileDelete => "deletes " + f.Target.Split('›').Select(p => p.Trim()).Last(p => p is not ("…" or "")),
        FindingKind.FileWrite => "writes " + f.Target,
        _ => Lower(f.Summary.TrimEnd('.'))
    };

    private static string Lower(string s) => s.Length == 0 ? s : char.ToLowerInvariant(s[0]) + s[1..];

    /// <summary>
    /// What each depends on, from its own "who decides", counted: "1 depends on how the app is started (its
    /// command line or environment), 1 on whatever is in the file it loads (temp folder › p.bin)".
    /// </summary>
    private static string EachWho(List<Finding> found)
    {
        var groups = found.Select(f => f.WhoDecides is { } w && !w.StartsWith("The scan couldn't", StringComparison.Ordinal)
                ? Lower(w.Split(';')[0].TrimEnd('.').Replace(" when it runs", "").Trim()) : "the scan can't tell what")
            .GroupBy(w => w).Select(g => (Count: g.Count(), Who: g.Key)).ToList();
        return string.Join(", ", groups.Select((g, i) => $"{g.Count} {(i == 0 ? (g.Count == 1 ? "depends on " : "depend on ") : "on ")}{g.Who}"));
    }

    /// <summary>Written to be hard to read, or decided by a server on the internet.</summary>
    private static bool Serious(Finding f) =>
        f.Legibility == Legibility.Obscured || f.WhoDecides?.StartsWith("A server on the internet", StringComparison.Ordinal) == true;

    private static string After(string sentence) => sentence[(sentence.IndexOf(':') + 1)..].Trim();

    // ---- the lines -----------------------------------------------------------------------------

    private static void AddLine(List<OverviewLine> lines, string area, string reach, string tech, List<Finding> found,
        Func<Finding, bool> changes, Func<IReadOnlyList<Finding>, string> words)
    {
        if (found.Count == 0) return;
        var changed = found.Where(changes).ToList();
        var read = found.Except(changed).ToList();
        lines.Add(new OverviewLine(area, reach, tech,
            read.Count > 0 ? new OverviewCell("reads", read, words(read)) : null,
            changed.Count > 0 ? new OverviewCell("changes", changed, words(changed)) : null));
    }

    private static void AddNet(List<OverviewLine> lines, string area, string tech, List<Finding> found)
    {
        if (found.Count == 0) return;
        var sent = found.Where(f => f.Direction.HasFlag(Direction.Sends) && !f.Summary.StartsWith("Looks up", StringComparison.Ordinal)).ToList();
        var received = found.Except(sent).ToList();
        lines.Add(new OverviewLine(area, "", tech,
            received.Count > 0 ? new OverviewCell("receives", received, Hosts(received)) : null,
            sent.Count > 0 ? new OverviewCell("sends", sent, Hosts(sent) + (sent.FirstOrDefault(f => f.Sends is not null) is { } s ? $" ({s.Sends})" : "")) : null));
    }

    private static bool IsChange(Finding f) => f.Direction.HasFlag(Direction.Changes);

    private static bool IsUserHive(Finding f) => f.Target.StartsWith("HKCU", StringComparison.Ordinal) || f.Target.StartsWith("HKEY_CURRENT_USER", StringComparison.Ordinal)
                                                 || f.Kind is FindingKind.RegistryRead or FindingKind.RegistryWrite && f.Scope != Scope.Admin && !f.MachineWide && !f.Target.StartsWith("HKLM", StringComparison.Ordinal);

    // ---- the icons -----------------------------------------------------------------------------

    /// <summary>
    /// The kit icon for what a finding touches, as its resource key ("" for none): a file, the registry,
    /// group policy, the internet or the local network, a program, a script, code, a credential. It is
    /// always shown beside the word it stands for, never instead of it.
    /// </summary>
    public static string Icon(Finding f)
    {
        if (f.Kind == FindingKind.Combination) return "";
        if (IsPolicy(f)) return "Icon.Policy";
        if (IsShare(f)) return "Icon.Network";
        return f.Kind switch
        {
            FindingKind.FileRead or FindingKind.FileWrite or FindingKind.FileDelete or FindingKind.EventLog or FindingKind.EmbeddedData => "Icon.File",
            FindingKind.FolderListing => "Icon.Folder",
            FindingKind.RegistryRead or FindingKind.RegistryWrite => "Icon.Registry",
            FindingKind.Network => Where(f) == NetPlace.Local ? "Icon.Network" : "Icon.Globe",
            FindingKind.Listens => "Icon.Network",
            FindingKind.Database => "Icon.Database",
            FindingKind.Process or FindingKind.Elevation => f.Program is "powershell" or "pwsh" ? "Icon.Script" : "Icon.Program",
            FindingKind.Identity or FindingKind.Credential or FindingKind.Secret => "Icon.Key",
            FindingKind.Reflection or FindingKind.LoadsCode or FindingKind.NativeCode or FindingKind.Com or FindingKind.Wmi => "Icon.Code",
            FindingKind.Service => "Icon.Clock",
            FindingKind.Environment => "Icon.Settings",
            FindingKind.Clipboard => "Icon.Copy",
            FindingKind.BuildStep or FindingKind.CiStep or FindingKind.CiAction => "Icon.Build",
            _ => ""
        };
    }

    /// <summary>The icon for a line of "What it reads and changes": its area, and for programs what starts.</summary>
    public static string Icon(OverviewLine l) => l.Area switch
    {
        "Registry" => "Icon.Registry",
        "Group policy" => "Icon.Policy",
        "Files" => "Icon.File",
        "Internet" or "Internet or local network" => "Icon.Globe",
        "Local network" => "Icon.Network",
        "Programs" => l.Reach switch { "PowerShell" => "Icon.Script", "code it loads" => "Icon.Code", _ => "Icon.Program" },
        _ => ""
    };

    /// <summary>Group policy: keys under …\Policies\…, the policy files, the policy tools.</summary>
    private static bool IsPolicy(Finding f) =>
        f.Kind is FindingKind.RegistryRead or FindingKind.RegistryWrite && Regex.IsMatch(f.Target, @"(?i)\\Policies\\|^HK\w+ › Policies\\|› SOFTWARE\\Policies|› Software\\Policies")
        || f.Kind is FindingKind.FileRead or FindingKind.FileWrite or FindingKind.FileDelete && Regex.IsMatch(f.Target, @"(?i)GroupPolicy.*Registry\.pol|Registry\.pol")
        || f.Kind is FindingKind.Process or FindingKind.Elevation && f.Program is { } p && PolicyTool.IsMatch(p);

    private static bool IsShare(Finding f) =>
        f.Kind is FindingKind.FileRead or FindingKind.FileWrite or FindingKind.FileDelete or FindingKind.FolderListing
        && (f.Target.StartsWith(@"\\", StringComparison.Ordinal) || f.Target.Contains("network share", StringComparison.OrdinalIgnoreCase));

    private enum NetPlace { Internet, Local, Either }

    private static NetPlace Where(Finding f)
    {
        if (IsShare(f) || f.Kind == FindingKind.Listens || f.Target == CodeScan.OwnComputer) return NetPlace.Local;
        if (f.Kind == FindingKind.Database && f.Scope != Scope.WebService) return NetPlace.Local;
        var host = HostOf(f.Target);
        if (host is null) return NetPlace.Either;
        return IsLocalHost(host) ? NetPlace.Local : NetPlace.Internet;
    }

    private static string? HostOf(string target)
    {
        var url = Regex.Match(target, @"(?i)\b(?:https?|wss?|ftp)://(?<h>\[[^\]]+\]|[^/:\s?#]+)");
        if (url.Success) return url.Groups["h"].Value.Trim('[', ']');
        var bare = Regex.Match(target.Trim(), @"^(?<h>(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}|\d{1,3}(?:\.\d{1,3}){3}|localhost)(?::\d+)?$");
        return bare.Success ? bare.Groups["h"].Value : null;
    }

    /// <summary>Loopback, private ranges (10/8, 172.16/12, 192.168/16, 169.254/16), link-local IPv6, .local and .lan names.</summary>
    private static bool IsLocalHost(string host)
    {
        if (host.Equals("localhost", StringComparison.OrdinalIgnoreCase) || Regex.IsMatch(host, @"(?i)\.(?:local|lan|home|internal|localdomain)$")) return true;
        if (System.Net.IPAddress.TryParse(host, out var ip))
        {
            if (System.Net.IPAddress.IsLoopback(ip)) return true;
            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6) return ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6UniqueLocal;
            var b = ip.GetAddressBytes();
            return b[0] == 10 || b[0] == 172 && b[1] >= 16 && b[1] <= 31 || b[0] == 192 && b[1] == 168 || b[0] == 169 && b[1] == 254;
        }
        return false;
    }

    private static string Hosts(IEnumerable<Finding> found)
    {
        var hosts = found.Select(f => HostOf(f.Target) ?? (f.Target == Finding.NotTraced ? null : ClipWords(f.Target, 60))).Where(h => h is not null).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        // "an address decided while it runs" and "…, ending in /robots.txt": one kind of place, said once.
        foreach (var plain in hosts.ToList())
        {
            var longer = hosts.Where(h => h != plain && h!.StartsWith(plain + ", ", StringComparison.Ordinal)).ToList();
            if (longer.Count == 0 || !plain!.StartsWith("an address", StringComparison.Ordinal)) continue;
            hosts.RemoveAll(h => longer.Contains(h));
            int at = hosts.IndexOf(plain);
            hosts[at] = $"{longer.Count + 1} addresses" + plain["an address".Length..] + " (" + (longer.Count == 1 ? "one " : "") + string.Join("; ", longer.Select(l => l![(plain.Length + 2)..])) + ")";
        }
        return hosts.Count == 0 ? "addresses decided while it runs" : Examples(hosts!);
    }

    /// <summary>"x.io (hidden in the code), api.github.com": each host, marked where the source hides it.</summary>
    private static string MarkedHosts(IEnumerable<Finding> found) =>
        Examples(found.GroupBy(f => HostOf(f.Target) ?? ClipWords(f.Target, 60), StringComparer.OrdinalIgnoreCase)
            .Select(g => g.Key + (g.Any(f => f.Legibility == Legibility.Obscured) ? " (hidden in the code)" : "")).ToList());

    private static string RegistryWords(IReadOnlyList<Finding> found) => Grouped(found.Select(f => KeyWords(f.Target)));

    /// <summary>
    /// "Windows Firewall settings (…\FirewallRules, …\System)": the same plain words once, with their
    /// keys together; the most frequent first.
    /// </summary>
    private static string Grouped(IEnumerable<string> items, int max = 3)
    {
        var pairs = items.Select(i => Regex.Match(i, @"^(?<w>.*?) \((?<k>[^()]*)\)$") is { Success: true } m ? (Words: m.Groups["w"].Value, Key: m.Groups["k"].Value) : (Words: i, Key: ""))
            .ToList();
        var groups = pairs.GroupBy(p => p.Words, StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(g => g.Count()).ThenBy(g => g.Key, StringComparer.Ordinal)
            .Select(g =>
            {
                var keys = g.Select(p => p.Key).Where(k => k.Length > 0).GroupBy(k => k).OrderByDescending(k => k.Count()).Select(k => k.Key).ToList();
                return keys.Count == 0 ? g.Key : Bracket(g.Key, string.Join(", ", keys.Take(2)) + (keys.Count > 2 ? ", …" : ""));
            }).ToList();
        return Examples(groups, max);
    }

    private static string PolicyWords(IReadOnlyList<Finding> found) =>
        Grouped(found.Select(f => f.Program is { } p && PolicyTool.IsMatch(p) ? (ToolWords.TryGetValue(p, out var w) ? w : p) + $" ({p})"
            : f.Kind is FindingKind.FileRead or FindingKind.FileWrite or FindingKind.FileDelete ? "the policy file (Registry.pol)" : KeyWords(f.Target)));

    /// <summary>A registry key in plain words, the key in brackets: "Windows Firewall settings (…\WindowsFirewall)".</summary>
    private static string KeyWords(string target)
    {
        if (Regex.IsMatch(target, @"^(?:HK\w+|a registry hive)$")) return "keys decided while it runs";
        var key = Regex.Replace(target, @"^HK\w+ › ", "");
        key = Regex.Replace(key, @" \(or [^()]*\)", "");
        key = key.Split(" › ")[0];
        string? words =
            Regex.IsMatch(key, @"(?i)WindowsFirewall|FirewallPolicy|SharedAccess") ? "Windows Firewall settings"
            : Regex.IsMatch(key, @"(?i)Windows Defender|Antimalware") ? "Microsoft Defender settings"
            : Regex.IsMatch(key, @"(?i)\\CurrentVersion\\Run") ? "programs that start with Windows"
            : Regex.IsMatch(key, @"(?i)\\Classes\\|^Software\\Classes") ? "file types and protocols"
            : Regex.IsMatch(key, @"(?i)^SYSTEM\\CurrentControlSet\\Services\\") ? "Windows services"
            : Regex.IsMatch(key, @"(?i)\\Policies\\System\\Audit") ? "audit settings"
            : Regex.IsMatch(key, @"(?i)\\Policies\\System|EnableLUA") ? "User Account Control"
            : Regex.IsMatch(key, @"(?i)\\Terminal Server") ? "Remote Desktop settings"
            : Regex.IsMatch(key, @"(?i)\\Uninstall\\?") ? "installed programs"
            : Regex.IsMatch(key, @"(?i)Schedule\\TaskCache") ? "scheduled tasks"
            : null;
        var parts = key.Split('\\', StringSplitOptions.RemoveEmptyEntries);
        var shortKey = parts.Length <= 2 ? key : "…\\" + string.Join("\\", parts[^2..]);
        if (key.Contains("{}", StringComparison.Ordinal) && words is null) return "keys decided while it runs";
        return words is null ? shortKey : Bracket(words, shortKey);
    }

    private static string FileWords(IReadOnlyList<Finding> found) =>
        Grouped(found.SelectMany(f => Regex.Replace(f.Target, @"^\d+ places: ", "").Split("; "))
            .Select(t => t.Trim().TrimEnd('…', ';', ' '))
            .Where(t => t.Length > 0 && !t.StartsWith("nothing", StringComparison.Ordinal))
            .Select(t => t == Finding.NotTraced ? "places the scan didn't trace" : t == Finding.OnlyTestsReach ? "places only tests reach" : t == "what the user types" ? "a path the user types" : ClipWords(t, 70)));

    private static string PowerShellWords(List<Finding> found)
    {
        var commands = found.SelectMany(f => f.Commands).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var scripts = found.Count(f => f.Call.Contains("→ PowerShell", StringComparison.Ordinal));
        // Two counts, two units: "8 scripts with 11 commands: … and 8 more" (the more are commands, not scripts).
        var text = (scripts > 0 ? Plural(scripts, "script") + (commands.Count > 3 ? $" with {commands.Count} commands" : "") + ": " : "") + (commands.Count > 0 ? PowerShellScript.Describe(commands, 3) : "scripts decided while it runs");
        var flags = found.SelectMany(f => f.Notes).Where(n => n.StartsWith("PowerShell ", StringComparison.Ordinal) || n.StartsWith("The script ", StringComparison.Ordinal))
            .Select(n => n[(n.IndexOf(' ') + 1)..].TrimEnd('.')).Where(n => n.Contains('(') && !n.StartsWith("script ", StringComparison.Ordinal)).Distinct().Take(2).ToList();
        return flags.Count > 0 ? text + "; " + string.Join("; ", flags) : text;
    }

    private static string ToolsText(List<Finding> tools) =>
        string.Join(", ", tools.GroupBy(f => f.Program!).Select(g =>
        {
            var plain = g.Select(f => Commands.Describe(f.Target)).FirstOrDefault(d => d is not null);
            var word = plain is null ? (ToolWords.TryGetValue(g.Key, out var w) ? w : null) : char.ToLowerInvariant(plain[0]) + plain[1..];
            return word is null ? g.Key : $"{word} ({g.Key})";
        }).Take(5)) + (tools.Select(f => f.Program).Distinct().Count() > 5 ? ", …" : "");

    /// <summary>
    /// The parts after a place the user chooses, from a target such as "2 places: a path the user types ›
    /// NTUSER-{}.DAT; a path the user types": "NTUSER-{}.DAT" and "" for the bare folder. Null when any place
    /// isn't one the user chooses.
    /// </summary>
    private static List<string>? ChosenPlaces(string target)
    {
        var text = Regex.Replace(target, @"^\d+ places: ", "");
        var result = new List<string>();
        foreach (var place in text.Split("; "))
        {
            var m = Regex.Match(place, @"^(?:a path the user types|a folder the user types|a file or folder the user picks[^›]*?)(?:\s*›\s*(?<rest>.*))?$");
            if (!m.Success) return null;
            result.Add(m.Groups["rest"].Value.Trim());
        }
        return result;
    }

    private static bool MountsHive(Finding f) =>
        f.Kind == FindingKind.NativeCode && !f.Unused && f.Origin == Origin.App
        && (Regex.IsMatch(f.Target, @"›\s*RegLoadKeyW?$") || f.Notes.Any(n => n.StartsWith("Called:", StringComparison.Ordinal) && Regex.IsMatch(n, @"\bRegLoadKeyW? \(")));

    private static readonly Regex NativeStarts = new(@"\bstarts programs\b|Open with dialog", RegexOptions.Compiled);

    private static string OtherText(List<Finding> other) =>
        Examples(other.Select(f => f.Kind == FindingKind.Network ? "opens web pages in the browser"
            : f.Kind == FindingKind.NativeCode ? (f.Notes.Any(n => n.Contains("Open with dialog", StringComparison.Ordinal))
                ? "the app you choose in Windows' Open with dialog" : "programs started through native code (" + f.Target.Split('›')[^1].Trim() + ")")
            : f.Program is { } p ? (ToolWords.TryGetValue(p, out var w) ? $"{w} ({p})" : p)
            : f.Target == Finding.NotTraced ? "programs or files the scan didn't trace" : ClipWords(f.Target, 50)));

    /// <summary>Cut at a word, never inside one: "an address decided while it runs, ending in /robots.txt" stays readable.</summary>
    internal static string ClipWords(string text, int max)
    {
        if (text.Length <= max) return text;
        int cut = text.LastIndexOfAny([' ', '›', ','], max - 1);
        if (cut < max / 2) return Tracer.Clip(text, max);
        // Never leave a bracket open: cut before it instead.
        int open = text.LastIndexOf('(', cut);
        if (open > 0 && text.IndexOf(')', open) > cut && open > max / 3) cut = open;
        return text[..cut].TrimEnd(' ', ',', '›', ';') + " …";
    }

    private static string Examples(IEnumerable<string> items, int max = 3)
    {
        var list = items.Where(i => !string.IsNullOrWhiteSpace(i)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        // "a file the user picks" beside "a file the user picks, or what's found inside it": the wider one says both.
        list = list.Where(i => !list.Any(o => o.Length > i.Length && o.StartsWith(i + ",", StringComparison.OrdinalIgnoreCase))).ToList();
        if (list.Count > max) return string.Join(", ", list.Take(max)) + $" and {list.Count - max} more";
        return list.Count <= 1 ? string.Join("", list) : string.Join(", ", list.Take(list.Count - 1)) + " and " + list[^1];
    }

    /// <summary>
    /// "words (detail)", or "words: detail" when the detail holds brackets itself: no brackets inside
    /// brackets. The plain words stay first either way.
    /// </summary>
    private static string Bracket(string words, string detail) =>
        detail.Contains('(') ? $"{words}: {detail}" : $"{words} ({detail})";

    private static string Plural(int n, string word) => $"{n} {word}{(n == 1 ? "" : "s")}";
}
