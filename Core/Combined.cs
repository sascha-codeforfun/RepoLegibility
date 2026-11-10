using System.Text.RegularExpressions;

namespace RepoLegibility.Core;

/// <summary>How a combination stands against what the repo says about itself.</summary>
public enum DeclarationKind
{
    /// <summary>A labelled line in the README's "Before you build or run it" section.</summary>
    Declared,
    /// <summary>The README or docs mention it somewhere, but not as a declaration.</summary>
    Mentioned,
    /// <summary>Nothing in the README, the docs or the project's description.</summary>
    NotFound,
    /// <summary>Hidden code, or code planted by others: no sentence in a README makes it fine.</summary>
    CantBeDeclared
}

/// <summary>
/// What the README says about a combination. A declaration says the author knew and meant it; it never says
/// it's safe, so it changes how surprising a combination is, not how much it matters.
/// </summary>
public sealed record Declaration(DeclarationKind Kind, string? File = null, int Line = 0, string? Quote = null, string? Word = null)
{
    /// <summary>What the code does that the declared line doesn't name: "audit policy", "Remote Desktop".</summary>
    public IReadOnlyList<string> Gaps { get; init; } = [];

    /// <summary>The repo has no README at all (rather than one without the section).</summary>
    public bool NoReadme { get; init; }

    public string Text => Kind switch
    {
        DeclarationKind.Declared => $"Declared in {File}, line {Line}: \"{Quote}\""
            + (Gaps.Count == 0 ? "" : $" It doesn't name {string.Join(Gaps.Count == 2 ? " or " : ", ", Gaps)}."),
        DeclarationKind.Mentioned => $"{File} mentions {Word} (line {Line}), but doesn't declare it in a \"{Combined.SectionHeading}\" section.",
        DeclarationKind.NotFound => NoReadme ? "The repo has no README." : "Not declared in the README or docs.",
        _ => Quote ?? "Hidden code can't be declared away: read it yourself."
    };
}

/// <summary>
/// Findings that mean more together. Each lists its findings, and says whether the README declares it.
/// A combination claims a flow (fetches and runs, sends what it reads) only where a trace shows it.
/// </summary>
public sealed record Combination(string Rule, string Title, string Sentence, string? Label, IReadOnlyList<Finding> Members, Declaration Declaration, string Check)
{
    /// <summary>"T-…": stays the same for the same rule, like a finding's key.</summary>
    public string Key { get; } = "T-" + Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes("together|" + Rule)))[..6];
    public Scope Scope => Members.Count == 0 ? Scope.App : Members.Max(m => m.Scope);

    /// <summary>Declared in the README, naming everything the code does. Known and meant: not the same as safe.</summary>
    public bool Expected => Declaration.Kind == DeclarationKind.Declared && Declaration.Gaps.Count == 0;

    /// <summary>Only possibly: every member reaches it on one of several paths (a registry helper that writes many keys, one of them a Run key).</summary>
    public bool Maybe { get; init; }

    /// <summary>When it happens: while the app runs, when the repo is built, or in its CI.</summary>
    public bool AtBuild => Rule is "buildsecret" or "ciruns";

    /// <summary>The tag beside it: what the README says, never a verdict.</summary>
    public string Standing => Declaration.Kind switch
    {
        DeclarationKind.Declared when Declaration.Gaps.Count > 0 => "Partly declared",
        DeclarationKind.Declared => "Declared in the README",
        DeclarationKind.Mentioned => "Mentioned, not declared",
        DeclarationKind.NotFound => "Not declared",
        _ => "Can't be declared"
    };

    /// <summary>
    /// The combination as a row of the findings list: its findings stand where a helper's calls do, so
    /// the list, the detail and search work on it as on any finding. Not part of the report's findings.
    /// </summary>
    public Finding AsFinding(int order)
    {
        var first = Members[0];
        return new Finding
        {
            Id = order,
            Key = Key,
            Kind = FindingKind.Combination,
            Scope = Scope,
            Legibility = Members.Max(m => m.Legibility),
            Origin = Origin.App,
            File = first.File,
            Line = first.Line,
            Call = Title,
            Target = Declaration.Text,
            Summary = Sentence,
            Notes = [Check],
            Direction = Members.Aggregate(Direction.None, (d, m) => d | m.Direction),
            Calls = Members.Select(m => new CallSite(m.File, m.Line, m.Legibility, m.Scope,
                $"#{m.Id} [{m.Key}] {Names.Of(m.Kind)} · {m.Target}", m.Summary, [])).ToList()
        };
    }
}

/// <summary>One part of the list for before building: when it runs, and what to read.</summary>
public sealed record CheckGroup(string Heading, IReadOnlyList<string> Items);

public static class Combined
{
    /// <summary>The README section both RepoLegibility and AppConsistency read.</summary>
    public const string SectionHeading = "Before you build or run it";

    /// <summary>What a reader should take from a declaration, said wherever declarations are shown.</summary>
    public const string DeclaredIsNotSafe = "A README tells you the author meant it, not that it's safe.";

    /// <summary>The labels of the section, as AppConsistency checks them.</summary>
    public const string AdminLabel = "Needs administrator rights";

    private static readonly Regex SecurityKey = new(
        @"WindowsFirewall|FirewallPolicy|Windows Defender|Microsoft Antimalware|\\Policies\\System\b|\\Policies\\Microsoft\\Windows\\System\b|EnableLUA|ConsentPromptBehavior|\\Control\\Lsa\b|SecurityProviders|SrpV2|AppLocker|SafeBoot|\\FVE\b|BitLocker|DeviceGuard|SystemRestore|\\Terminal Server\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex SecurityCommand = new(
        @"^(?:Set|Add|Remove|New|Disable|Enable|Rename|Copy)-(?:NetFirewall|Mp|NetIPsec|BitLocker|ExecutionPolicy|ProcessMitigation|AppLocker)", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex RunKey = new(@"\\CurrentVersion\\Run(?:Once|Services|ServicesOnce)?\b|\\Winlogon\b.*\b(?:Shell|Userinit)\b|\\Image File Execution Options\\", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // Calls whose result is something fetched from another computer.
    private static readonly Regex Download = new(
        @"\b(?:GetByteArrayAsync|GetStringAsync|GetStreamAsync|DownloadData(?:TaskAsync)?|DownloadString(?:TaskAsync)?|DownloadFile(?:TaskAsync)?|ReadAsByteArrayAsync|ReadAsStringAsync|ReadAsStreamAsync|Invoke-WebRequest|Invoke-RestMethod)\b",
        RegexOptions.Compiled);
    // The app's own exe: what it copies or registers when it starts itself.
    private static readonly Regex OwnExe = new(@"\bEnvironment\s*\.\s*ProcessPath\b|\bMainModule\s*\??\.\s*FileName\b|\bApplication\s*\.\s*ExecutablePath\b|GetEntryAssembly\(\)\s*\??\.\s*Location\b|\bProcess\s*\.\s*GetCurrentProcess\s*\(\s*\)\s*\.\s*MainModule\b", RegexOptions.Compiled);
    // Places any program running as the user can write to.
    private static readonly Regex WritableCode = new(@"\bGetTempPath\s*\(|\bGetTempFileName\s*\(|SpecialFolder\s*\.\s*(?:ApplicationData|LocalApplicationData|Desktop|DesktopDirectory|MyDocuments|Personal|UserProfile)\b|%(?:TEMP|TMP|APPDATA|LOCALAPPDATA|USERPROFILE)%", RegexOptions.Compiled);
    private static readonly Regex Writable = new(@"^(?:temp folder|user's (?:AppData|Downloads|Desktop|Documents|profile)|HKCU\b)", RegexOptions.Compiled);

    // Words that mention a topic without declaring it. Only phrases that name the thing itself: "extension" or
    // "script" alone turn up in any README (an Explorer extension, a build script) and point at nothing.
    // Order: what's most serious first. Rule names are part of each combination's key: keep them.
    private static readonly (string Rule, string? Label, string[] Words)[] Rules =
    [
        ("plant", null, []),
        ("buildsecret", "Runs code when you build", ["build target", "msbuild", "pre-build", "post-build", "before build", "BeforeTargets", "AfterTargets"]),
        ("hidden", null, []),
        ("security", "Changes security settings",
            ["firewall", "defender", "antivirus", "anti-virus", "UAC", "user account control", "audit", "BitLocker", "security polic", "exclusion"]),
        ("stays", "Starts on its own",
            ["scheduled task", "task scheduler", "schtasks", "startup folder", "at logon", "autostart", "auto-start", "starts with windows", "run key", "windows service", "background service"]),
        ("fetches", "Runs code from outside the app",
            ["downloads code", "downloads and runs", "self-update", "auto-update", "updates itself", "plugin", "plug-in", "loads assemblies"]),
        ("unseen", "Runs code from outside the app",
            ["plugin", "plug-in", "loads assemblies", "runs commands", "runs scripts", "runs a script", "powershell script", "encoded command"]),
        ("builds", "Runs code from outside the app",
            ["builds the repo", "builds a repo", "builds repos", "builds projects", "dotnet publish", "dotnet build", "msbuild", "build targets", "builds it"]),
        ("sends", "Reads or sends personal data",
            ["telemetry", "upload", "analytics", "personal data", "privacy", "collects", "sends"]),
        ("ciruns", "Runs code when you build",
            ["workflow", "github actions", "continuous integration", "install script"]),
    ];

    public static List<Combination> Find(IReadOnlyList<Finding> findings, IReadOnlyList<RepoFile> files)
    {
        // What runs: not test code, and not what's only declared.
        var live = findings.Where(f => f.Origin != Origin.Tests && !f.Unused).ToList();
        var docs = Docs(files);
        bool noReadme = !docs.Any(d => System.IO.Path.GetFileNameWithoutExtension(d.Path).Equals("README", StringComparison.OrdinalIgnoreCase));
        var section = Section(docs);
        var text = new Source(files);
        var flows = Flows(live, text);
        var result = new List<Combination>();
        foreach (var (rule, label, words) in Rules)
        {
            var members = rule switch
            {
                "plant" => Planted(live),
                "buildsecret" => BuildWithSecret(live, text),
                "hidden" => live.Where(f => f.Legibility == Legibility.Obscured).ToList(),
                "security" => live.Where(IsSecurityChange).ToList(),
                "stays" => live.Where(IsPersistence).ToList(),
                "fetches" => flows.SelectMany(x => x.Members).Distinct().ToList(),
                "unseen" => live.Where(f => f.Origin == Origin.App && f.Legibility == Legibility.Opaque && RunsCode(f)
                                            && !flows.Any(x => x.Members.Contains(f))).ToList(),
                "builds" => live.Where(BuildsWhatYouGive).ToList(),
                "sends" => live.Where(f => f.Kind == FindingKind.Network && f.Direction.HasFlag(Direction.Sends) && f.Sends is not null && f.Scope == Scope.WebService).ToList(),
                _ => live.Where(f => f.Origin == Origin.CI && (DownloadsAndRuns(f) || f.Kind == FindingKind.CiAction && f.Legibility == Legibility.Opaque)).ToList()
            };
            if (members.Count == 0) continue;
            if (rule != "buildsecret") members = members.OrderBy(f => f.Id).ToList();
            var declaration = label is null
                ? new Declaration(DeclarationKind.CantBeDeclared, Quote: rule == "plant"
                    ? "A README can't make this safe: whatever another program puts there runs with administrator rights."
                    : "Hidden code can't be declared away: read it yourself.")
                : section.FirstOrDefault(s => s.Label.Equals(label, StringComparison.OrdinalIgnoreCase)) is { File: not null } s
                    ? new Declaration(DeclarationKind.Declared, s.File, s.Line, Tracer.Clip(s.Text, 160)) { Gaps = Gaps(rule, members, s.Text) }
                    : Mention(docs, words.Concat(NamesIn(members)).ToList()) with { NoReadme = noReadme };
            result.Add(new Combination(rule, Title(rule, members, text), Sentence(rule, members, flows, live, text), label, members, declaration, Check(rule, members))
                { Maybe = rule == "stays" && members.All(RunKeyOnAPath) });
        }
        return result;
    }

    public const string ProgramsLabel = "Starts other programs";
    public const string WholeComputerLabel = "Changes the whole computer";
    public const string NetworkLabel = "Talks to other computers";

    /// <summary>The repo has a README (at any depth).</summary>
    public static bool HasReadme(IReadOnlyList<RepoFile> files) => files.Any(f => f.Text is not null
        && f.Extension.Equals(".md", StringComparison.OrdinalIgnoreCase)
        && System.IO.Path.GetFileNameWithoutExtension(f.Path).Equals("README", StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Where the author writes about security, if anywhere: a SECURITY.md (the one nearest the top), or else a README
    /// section headed "Security", "Security model", "Security considerations", "Security notes" or "Threat model".
    /// Only a pointer for the reader: what it says isn't read, judged or counted, and changes no finding. Some
    /// things are only safe because a person decides (what a crawler is aimed at); that can't be seen from outside,
    /// and this is where an author says so.
    /// </summary>
    public static string? SecurityWriting(IReadOnlyList<RepoFile> files)
    {
        var doc = files.Where(f => f.Text is not null
                && System.IO.Path.GetFileName(f.Path).Equals("SECURITY.md", StringComparison.OrdinalIgnoreCase))
            .OrderBy(f => f.Path.Count(c => c is '/' or '\\')).ThenBy(f => f.Path, StringComparer.Ordinal).FirstOrDefault();
        if (doc is not null) return $"The author writes about security in {doc.Path}.";

        foreach (var readme in files.Where(f => f.Text is not null
                     && f.Extension.Equals(".md", StringComparison.OrdinalIgnoreCase)
                     && System.IO.Path.GetFileNameWithoutExtension(f.Path).Equals("README", StringComparison.OrdinalIgnoreCase))
                 .OrderBy(f => f.Path.Count(c => c is '/' or '\\')).ThenBy(f => f.Path, StringComparer.Ordinal))
        {
            var lines = readme.Text!.Split('\n');
            for (int i = 0; i < lines.Length; i++)
                if (SecurityHeading.Match(lines[i].TrimEnd('\r')) is { Success: true } m)
                    return $"The author writes about security in the README's \"{m.Groups[1].Value.Trim()}\" section ({readme.Path}:{i + 1}).";
        }
        return null;
    }

    private static readonly System.Text.RegularExpressions.Regex SecurityHeading = new(
        @"^\s{0,3}#{1,6}\s+((?:security(?:\s+(?:model|considerations|notes))?|threat\s+model))\s*#*\s*$",
        System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.CultureInvariant);

    /// <summary>The labelled line for a label, if the README's section has one: for answers outside the combinations.</summary>
    public static Declaration? Declares(IReadOnlyList<RepoFile> files, string label) =>
        Section(Docs(files)).FirstOrDefault(s => s.Label.Equals(label, StringComparison.OrdinalIgnoreCase)) is { File: not null } s
            ? new Declaration(DeclarationKind.Declared, s.File, s.Line, Tracer.Clip(s.Text, 160)) : null;

    /// <summary>The one sentence on top: what the combinations are and what the README says about them.</summary>
    public static string Headline(IReadOnlyList<Combination> combinations)
    {
        if (combinations.Count == 0) return "Nothing worth knowing together (within what the scan follows).";
        // Short enough to read in one breath: one is named, more are counted; the list below names them.
        var what = combinations.Count == 1 ? combinations[0].Title : $"{combinations.Count} things worth knowing together";
        var declarable = combinations.Where(c => c.Declaration.Kind != DeclarationKind.CantBeDeclared).ToList();
        int cant = combinations.Count - declarable.Count;
        var parts = new List<string>();
        int declared = declarable.Count(c => c.Declaration.Kind == DeclarationKind.Declared);
        int gaps = declarable.Count(c => c.Declaration.Kind == DeclarationKind.Declared && c.Declaration.Gaps.Count > 0);
        if (declarable.Count > 0)
        {
            // "N a README could declare" only where some can't be: otherwise it's all of them.
            string could = cant == 0 ? "" : declarable.Count == 1 ? "1 a README could declare, " : $"{declarable.Count} a README could declare, ";
            int mentioned = declarable.Count(c => c.Declaration.Kind == DeclarationKind.Mentioned);
            string alsoMentioned = mentioned == 0 ? "" : mentioned == declarable.Count && declared == 0
                ? (mentioned == 1 ? ", only mentioned in the README or docs" : mentioned == 2 ? ", both only mentioned in the README or docs" : ", all only mentioned in the README or docs")
                : $", {mentioned} only mentioned";
            if (declarable.Any(c => c.Declaration.NoReadme)) parts.Add(could + (could.Length > 0 ? "but " : "") + "the repo has no README");
            else if (declared == declarable.Count) parts.Add(could + (declarable.Count == 1 ? "declared in the README" : "all declared in the README"));
            else if (declared == 0) parts.Add(could + (declarable.Count == 1 ? "not declared" : "none declared") + alsoMentioned);
            else parts.Add(could + $"{declared} declared" + alsoMentioned);
            if (gaps > 0) parts.Add(gaps == 1 ? "one line doesn't name everything the code does" : $"{gaps} lines don't name everything the code does");
        }
        if (cant > 0) parts.Add(declarable.Count == 0 ? (cant == 1 ? "it can't be declared away" : "none can be declared away")
            : $"plus {cant} that can't be declared away");
        return what + ": " + string.Join("; ", parts) + ".";
    }

    /// <summary>
    /// What to read before building, by when it runs: what runs when you build, what runs in CI, the black boxes
    /// the build uses, and what runs when you start the app.
    /// </summary>
    public static List<CheckGroup> Checklist(ScanReport r)
    {
        var live = r.Findings.Where(f => f.Origin != Origin.Tests && !f.Unused).ToList();
        static string Item(Finding f) => $"{f.Key} ({f.File}:{f.Line}): {f.Summary.TrimEnd('.')}.";
        var groups = new List<CheckGroup>();

        var build = live.Where(f => f.Origin == Origin.Build && f.Kind == FindingKind.BuildStep).Select(Item).ToList();
        if (build.Count > 0) groups.Add(new CheckGroup("Runs when you build", build));

        var ci = live.Where(f => f.Origin == Origin.CI && (f.Legibility >= Legibility.Untraced || DownloadsAndRuns(f))).Select(Item).ToList();
        if (r.Combinations.FirstOrDefault(c => c.Rule == "buildsecret") is { } secret) ci.Add(secret.Check);
        if (ci.Count > 0) groups.Add(new CheckGroup("Runs in CI", ci));

        var boxes = r.BlackBoxes.Select(b => $"{b.Path}: {b.Kind}. Whatever it does is hidden from the scan.").ToList();
        if (boxes.Count > 0) groups.Add(new CheckGroup("Black boxes the build uses", boxes));

        var app = r.Combinations.Where(c => !c.AtBuild).Select(c => c.Check).ToList();
        if (app.Count > 0) groups.Add(new CheckGroup("Runs when you start the app", app));
        return groups;
    }

    // ---- the rules -----------------------------------------------------------------------------

    private static bool RunsCode(Finding f) =>
        f.Kind == FindingKind.LoadsCode || f.Kind is FindingKind.Process or FindingKind.Elevation && f.Direction.HasFlag(Direction.Runs);

    private static bool DownloadsAndRuns(Finding f) =>
        f.Notes.Any(n => n.Contains("downloads code and runs it", StringComparison.Ordinal))
        || f.Reasons.Any(n => n.StartsWith("Downloads a script and runs it", StringComparison.Ordinal))
        || Commands.Describe(f.Target) is "Downloads a script and runs it straight away";

    /// <summary>
    /// The app always runs as administrator (its manifest) and loads or starts code from a place any program
    /// running as the user can write to: the manifest, the read of that file, and the load or start.
    /// </summary>
    /// <summary>
    /// What it starts or loads comes from a place any program can write to. For a program, only the program
    /// counts: dism.exe /MountDir:"%TEMP%\…" mounts into the temp folder, it doesn't run anything from it.
    /// </summary>
    private static bool FromWritable(Finding f)
    {
        if (f.Kind is FindingKind.Process or FindingKind.Elevation && f.Program is { Length: > 0 })
        {
            // The program is the target up to its first switch: "temp folder › x.exe" of "temp folder › x.exe /quiet".
            var programPart = Regex.Match(f.Target, @"^.*?(?=\s+[/-]|\s*$)").Value;
            return Writable.IsMatch(programPart);
        }
        return Writable.IsMatch(f.Target) || f.Trace.Take(4).Any(t => WritableCode.IsMatch(t.Code));
    }

    private static List<Finding> Planted(List<Finding> live)
    {
        var elevated = live.Where(f => f.Kind == FindingKind.Elevation && f.Call.StartsWith("requestedExecutionLevel", StringComparison.Ordinal)
                                       && Regex.IsMatch(f.Call + " " + f.Target, @"requireAdministrator|highestAvailable")).ToList();
        if (elevated.Count == 0) return [];
        var sinks = live.Where(f => f.Origin == Origin.App && RunsCode(f) && FromWritable(f)).ToList();
        if (sinks.Count == 0) return [];
        var reads = live.Where(f => f.Kind == FindingKind.FileRead && sinks.Any(s => s.File == f.File && s.Line == f.Line)).ToList();
        return [.. elevated, .. reads, .. sinks];
    }

    /// <summary>
    /// A build step of the repo's own (an Exec in a target) that CI runs, in a step whose environment holds a
    /// secret: the build target, the CI step, the secret.
    /// </summary>
    private static List<Finding> BuildWithSecret(List<Finding> live, Source text)
    {
        var hooks = live.Where(f => f.Origin == Origin.Build && f.Kind == FindingKind.BuildStep).ToList();
        if (hooks.Count == 0) return [];
        var members = new List<Finding>();
        foreach (var step in live.Where(f => f.Origin == Origin.CI && f.Kind == FindingKind.CiStep
                                             && Regex.IsMatch(f.Target, @"(?i)\b(?:dotnet\s+(?:build|publish|test|pack|run|msbuild)|msbuild)\b")))
        {
            var (from, to) = text.StepRange(step.File, step.Line);
            var secrets = live.Where(f => f.Origin == Origin.CI && f.Kind is FindingKind.Credential or FindingKind.Secret
                                          && f.File == step.File && f.Line >= from && f.Line < to).ToList();
            if (secrets.Count == 0) continue;
            members.Add(step);
            members.AddRange(secrets);
            var names = string.Join(", ", secrets.Select(x => x.Target).Distinct());
            foreach (var hook in hooks)
            {
                var note = $"In CI this runs with {names} in its environment ({step.File}:{secrets[0].Line}).";
                if (!hook.Notes.Contains(note)) hook.Notes = [.. hook.Notes, note];
            }
        }
        return members.Count == 0 ? [] : [.. hooks, .. members.Distinct()];
    }

    private sealed record Flow(Finding Run, Finding? From, string How, List<Finding> Members);

    /// <summary>
    /// A fetch that reaches something that runs: a start or a load whose value the trace shows coming from a
    /// download (directly, or through a file written with what was downloaded), or a script that downloads and
    /// runs. Two findings in the same code without a path between them aren't a flow.
    /// </summary>
    private static List<Flow> Flows(List<Finding> live, Source text)
    {
        var flows = new List<Flow>();
        var app = live.Where(f => f.Origin is not (Origin.CI or Origin.Build)).ToList();
        var downloads = app.Where(f => f.Kind == FindingKind.Network && f.Direction.HasFlag(Direction.Receives)).ToList();
        foreach (var run in app.Where(RunsCode))
        {
            if (DownloadsAndRuns(run)) { flows.Add(new Flow(run, null, "script", [run])); continue; }
            // Directly: Assembly.Load(await http.GetByteArrayAsync(u)), or a value the trace follows back to one.
            var places = run.Trace.Select(t => (t.File, t.Line)).Append((run.File, run.Line)).ToList();
            var direct = places.FirstOrDefault(p => Download.IsMatch(text.Statement(p.File, p.Line)));
            if (direct.File is not null)
            {
                var from = downloads.FirstOrDefault(d => d.File == direct.File && d.Line == direct.Line);
                flows.Add(new Flow(run, from, "direct", from is null ? [run] : [from, run]));
                continue;
            }
            // Through a file: written with downloaded bytes, then started or loaded, the same path both times.
            foreach (var write in app.Where(f => f.Kind == FindingKind.FileWrite || f.Kind == FindingKind.Network && Regex.IsMatch(f.Call, @"DownloadFile")))
            {
                var writePlaces = write.Trace.Select(t => (t.File, t.Line)).ToHashSet();
                // DownloadFile(url, path) and File.WriteAllBytes(path, …) where path was set a few lines up: that line.
                foreach (var at in text.AssignedAt(write.File, write.Line)) writePlaces.Add((write.File, at));
                bool samePath = write.Target == run.Target && write.Target != Finding.NotTraced && !write.Target.StartsWith("not determined", StringComparison.Ordinal)
                                || writePlaces.Count > 0 && places.Any(writePlaces.Contains);
                if (!samePath) continue;
                bool fetched = write.Kind == FindingKind.Network || Download.IsMatch(text.Statement(write.File, write.Line))
                               || text.AssignedFrom(write.File, write.Line, Download);
                if (!fetched) continue;
                var from = write.Kind == FindingKind.Network ? write
                    : downloads.FirstOrDefault(d => d.File == write.File && Math.Abs(d.Line - write.Line) <= 30 && text.Statement(d.File, d.Line).Length > 0
                                                    && (d.Line == write.Line || text.AssignedFrom(write.File, write.Line, Download)));
                flows.Add(new Flow(run, from, "file", from is null || from == write ? [write, run] : [from, write, run]));
                break;
            }
        }
        return flows;
    }

    private static bool IsSecurityChange(Finding f)
    {
        if (f.Kind == FindingKind.RegistryWrite) return SecurityKey.IsMatch(f.Target);
        if (f.Kind is FindingKind.Process or FindingKind.Elevation or FindingKind.BuildStep or FindingKind.CiStep)
        {
            if (f.Commands.Any(c => SecurityCommand.IsMatch(c))) return true;
            var t = f.Target;
            if (f.Program == "netsh" || Regex.IsMatch(t, @"(?i)\bnetsh\b"))
                return Regex.IsMatch(t, @"(?i)\b(?:advfirewall|firewall)\b") && Regex.IsMatch(t, @"(?i)\b(?:set|add|delete|import|reset)\b") || Regex.IsMatch(t, @"(?i)(?:^|\s)-f\s");
            if (f.Program == "auditpol" || Regex.IsMatch(t, @"(?i)\bauditpol\b")) return Regex.IsMatch(t, @"(?i)/(?:set|clear|remove|restore)\b");
            if (Regex.IsMatch(t, @"(?i)\bbcdedit\b")) return !Regex.IsMatch(t, @"(?i)/enum\b");
            if (Regex.IsMatch(t, @"(?i)\bvssadmin\b.*\bdelete\b|\bsecedit\b.*/configure\b")) return true;
            return Commands.Describe(t) is { } d && Regex.IsMatch(d, @"Firewall|Defender|Shadow Copies|recovery|boot configuration|auditing");
        }
        if (f.Kind == FindingKind.Com) return Regex.IsMatch(f.Target, @"(?i)HNetCfg\.Fw|FwPolicy");
        return false;
    }

    /// <summary>The security changes among findings: for answers that count what changes the whole computer.</summary>
    public static bool ChangesSecurity(Finding f) => IsSecurityChange(f);

    /// <summary>A registry write that reaches a Run or RunOnce key on one of its paths, not in its target: a helper that writes many keys.</summary>
    private static bool RunKeyOnAPath(Finding f) =>
        f.Kind == FindingKind.RegistryWrite && !RunKey.IsMatch(f.Target) && f.Notes.Any(n => n.StartsWith("A Run key", StringComparison.Ordinal))
        && !f.Call.Contains("Open", StringComparison.Ordinal);

    private static bool IsPersistence(Finding f)
    {
        if (f.Kind == FindingKind.RegistryWrite) return RunKey.IsMatch(f.Target) || RunKeyOnAPath(f);
        if (f.Kind is FindingKind.FileWrite) return f.Target.Contains("Startup folder", StringComparison.OrdinalIgnoreCase);
        if (f.Kind is FindingKind.Process or FindingKind.Elevation or FindingKind.BuildStep)
        {
            if (f.Commands.Any(c => Regex.IsMatch(c, @"(?i)^(?:Register-ScheduledTask|New-Service|Set-Service)$"))) return true;
            return Regex.IsMatch(f.Target, @"(?i)\bschtasks(?:\.exe)?\b.*\s/create\b|\bsc(?:\.exe)?\s+(?:create|config)\b|\bNew-Service\b|\breg(?:\.exe)?\s+add\b.*\\Run\b");
        }
        if (f.Kind == FindingKind.Com) return Regex.IsMatch(f.Target, @"(?i)Schedule\.Service|TaskScheduler");
        if (f.Kind == FindingKind.Service) return Regex.IsMatch(f.Summary, @"(?i)\b(?:Installs|Creates|Registers)\b");
        return false;
    }

    // dotnet build/publish/run/test/pack, msbuild: what builds a project, and with it runs the project's build steps.
    private static readonly Regex BuildTool = new(@"(?i)^\s*""?(?:[^""\s]*[\\/])?(?:dotnet(?:\.exe)?|msbuild(?:\.exe)?)(?=[\s""]|$)", RegexOptions.Compiled);

    /// <summary>"dotnet publish", "msbuild": the program and, for dotnet, the verb the source shows.</summary>
    private static string BuildVerb(Finding f)
    {
        if (Regex.IsMatch(f.Target, @"(?i)^\s*""?(?:[^""\s]*[\\/])?msbuild")) return "msbuild";
        var said = f.Target + " " + string.Join(" ", f.Trace.SelectMany(t => Regex.Matches(t.Code, @"""(?<w>[^""]*)""").Select(m => m.Groups["w"].Value)));
        var verb = Regex.Match(said, @"(?i)(?:^|[\s""])(?<v>build|publish|run|test|pack)(?=[\s""]|$)");
        return verb.Success ? "dotnet " + verb.Groups["v"].Value.ToLowerInvariant() : "dotnet";
    }

    /// <summary>
    /// It starts dotnet build/publish/run/test/pack or msbuild on a project decided while it runs, not one the repo
    /// names: building runs that project's targets, whatever they are.
    /// </summary>
    private static bool BuildsWhatYouGive(Finding f)
    {
        if (f.Kind != FindingKind.Process || f.Origin != Origin.App || !BuildTool.IsMatch(f.Target)) return false;
        if (BuildVerb(f) == "dotnet") return false;
        // A project the repo itself names (Clear) is the repo's own build; one decided while it runs comes from
        // outside: a folder or zip you give it, or what it finds.
        return f.Legibility != Legibility.Clear;
    }

    // ---- titles, sentences, checks ---------------------------------------------------------------

    private static string Title(string rule, List<Finding> members, Source text) => rule switch
    {
        "plant" => "Runs as administrator code another program can plant",
        "buildsecret" => "Building runs " + (members.Where(f => f.Origin == Origin.Build) is var hooks && hooks.Any(h => h.Legibility == Legibility.Obscured)
                ? (hooks.Any(h => Regex.IsMatch(h.Target, @"(?i)\bpowershell|\bpwsh")) ? "hidden PowerShell" : "hidden code")
                : "commands of its own")
            + " with " + string.Join(", ", members.Where(f => f.Kind is FindingKind.Credential or FindingKind.Secret).Select(f => f.Target).Distinct().Take(2)) + " present in CI",
        "hidden" => "Hidden on purpose",
        "security" => "Changes security settings",
        "stays" when members.All(RunKeyOnAPath) => "May start a program with Windows",
        "stays" => Persistence(members, text).All(p => p.Own) ? "Starts itself with Windows"
            : Persistence(members, text).All(p => p.WithWindows) ? "Starts a program with Windows" : "Starts a program on its own",
        "fetches" => "Fetches code and runs it",
        "unseen" => "Runs code the source doesn't show",
        "sends" => "Sends out what it reads",
        "builds" => "Runs code from the projects it builds",
        _ => "Building runs code from outside the repo"
    };

    private static string Sentence(string rule, List<Finding> members, List<Flow> flows, List<Finding> live, Source text)
    {
        string what = rule switch
        {
            "plant" => PlantSentence(members),
            "buildsecret" => BuildSecretSentence(members, live),
            "hidden" => string.Join("; ", members.Select(f => Lower(f.Summary.TrimEnd('.')) is var what && f.HowHidden is { } how
                ? (what.EndsWith(')') ? $"{what}, hidden as {how}" : $"{what} ({how})") : Lower(f.Summary.TrimEnd('.'))).Distinct()),
            "security" => Join(members.Select(SecurityArea).Distinct()),
            "stays" => Persistence(members, text) is var ways ? Join(ways.Select(w => w.Words).Distinct()) + (ways.Select(w => w.Words).Distinct().Count() > 1 ? $": {ways.Select(w => w.Words).Distinct().Count()} ways" : "") : "",
            "fetches" => Join(flows.Select(FlowWords).Distinct().Take(3)),
            "unseen" => string.Join("; ", members.Select(Unseen).Distinct().Take(4)),
            "sends" => Join(members.Select(f => $"sends {f.Sends} to {Tracer.Clip(f.Target, 50)}").Distinct().Take(3)),
            "builds" => Join(members.Select(f => $"it starts {BuildVerb(f)} on a project decided while it runs ({f.File}:{f.Line})").Distinct().Take(3))
                        + "; building runs that project's own build steps, and a project file can run any command",
            _ => Join(members.Select(f => DownloadsAndRuns(f) ? $"downloads a script and runs it ({Tracer.Clip(f.Target, 50)})"
                : $"uses a third-party action not pinned to a commit ({Tracer.Clip(f.Target, 50)})").Distinct().Take(4))
        };
        return Title(rule, members, text) + ": " + what + ".";
    }

    private static string PlantSentence(List<Finding> members)
    {
        var manifest = members.First(f => f.Kind == FindingKind.Elevation);
        var sinks = members.Where(f => f != manifest && RunsCode(f)).ToList();
        static string Place(Finding s)
        {
            if (Writable.IsMatch(s.Target)) return Tracer.Clip(s.Target, 60);
            var code = string.Join(" ", s.Trace.Take(4).Select(t => t.Code));
            var where = Regex.IsMatch(code, @"GetTemp|%TE?MP%") ? "the temp folder" : Regex.IsMatch(code, @"Desktop") ? "the user's Desktop"
                : Regex.IsMatch(code, @"MyDocuments|Personal") ? "the user's Documents" : Regex.IsMatch(code, @"UserProfile|%USERPROFILE%") ? "the user's profile" : "the user's AppData";
            return $"{Tracer.Clip(s.Target, 40)} in {where}";
        }
        var how = Join(sinks.Select(s => (s.Kind == FindingKind.LoadsCode ? "loads code from " : "starts ") + Place(s)).Distinct());
        return $"it always runs as administrator ({manifest.File}) and {how}: {(sinks.Count == 1 ? "a place" : "places")} any program you run can write to, so whatever is put there runs with administrator rights";
    }

    private static string BuildSecretSentence(List<Finding> members, List<Finding> live)
    {
        var hooks = members.Where(f => f.Origin == Origin.Build).ToList();
        var steps = members.Where(f => f.Kind == FindingKind.CiStep).ToList();
        var secrets = members.Where(f => f.Kind is FindingKind.Credential or FindingKind.Secret).Select(f => f.Target).Distinct().ToList();
        var hookWords = Join(hooks.Select(h => (Regex.Match(h.Summary, @"target (?<t>[\w.-]+)") is { Success: true } m ? $"the {m.Groups["t"].Value} target" : "a build step")
                                             + $" ({h.File}:{h.Line}) runs {Tracer.Clip(h.Target, 50)}").Distinct());
        var step = steps[0];
        var before = live.Where(f => f.Origin == Origin.CI && f.File == step.File && f.Line < step.Line
                                     && (f.Legibility == Legibility.Opaque || DownloadsAndRuns(f))).Select(f => Tracer.Clip(f.Target, 40)).Distinct().ToList();
        return $"{hookWords} on every build, and CI builds with {Tracer.Clip(step.Target, 40)} ({step.File}:{step.Line}) with {string.Join(", ", secrets)} in its environment"
               + (before.Count > 0 ? $"; earlier steps in the same job ({string.Join(", ", before)}) can change what that build runs" : "");
    }

    private static string FlowWords(Flow x) => x.How switch
    {
        "script" => "runs a script that downloads code and runs it (" + Tracer.Clip(x.Run.Target, 50) + ")",
        _ => (x.From is { } d ? "downloads from " + Tracer.Clip(d.Target, 50) + " and " : "downloads code and ")
             + (x.Run.Kind == FindingKind.LoadsCode ? "loads it" : "starts it")
             + (x.How == "file" ? " from the file it wrote" : "") + $" ({x.Run.File}:{x.Run.Line})"
    };

    /// <summary>Who decides, in a few words for a sentence: "how the app is started (its command line or environment)".</summary>
    private static string? Who(Finding f)
    {
        if (f.WhoDecides is not { } w || w.StartsWith("The scan couldn't", StringComparison.Ordinal)) return null;
        var first = w.Split(';')[0].TrimEnd('.').Trim();
        return Lower(first);
    }

    private static string Lower(string s) => s.Length == 0 ? s : char.ToLowerInvariant(s[0]) + s[1..];

    /// <summary>"loads code from temp folder › p.bin: whatever that file holds"; "starts cmd.exe /c, decided by how the app is started …".</summary>
    private static string Unseen(Finding f) =>
        f.Kind == FindingKind.LoadsCode && f.WhoDecides?.StartsWith("Whatever is in the file", StringComparison.Ordinal) == true
            ? $"loads code from {Tracer.Clip(f.Target, 60)}: whatever that file holds when it runs"
            : Lower(f.Summary.TrimEnd('.')) + (Who(f) is { } who ? $", decided by {who}" : "");

    private sealed record Way(string Words, bool Own, bool WithWindows);

    /// <summary>Each way it starts on its own, in words, and whether what starts is the app itself.</summary>
    private static List<Way> Persistence(List<Finding> members, Source text)
    {
        var ways = new List<Way>();
        foreach (var f in members)
        {
            var t = f.Target;
            bool own = OwnExe.IsMatch(text.Statement(f.File, f.Line));
            var task = Regex.Match(t, @"(?i)/tn\s+\\?""(?<n>[^""\\]+)");
            if (Regex.IsMatch(t, @"(?i)schtasks|Schedule\.Service|TaskScheduler") || f.Commands.Any(c => c.Contains("ScheduledTask", StringComparison.OrdinalIgnoreCase)))
                ways.Add(new Way("creates a scheduled task" + (task.Success ? $" (\"{task.Groups["n"].Value}\")" : ""), false, false));
            else if (RunKeyOnAPath(f))
            {
                // Reg.Write(path, …) with path one of many keys, RunOnce among them: one way, said as a possibility.
                var way = new Way($"can add a program to a Run or RunOnce key (through {f.Call}, among the keys it writes)", false, true);
                if (!ways.Contains(way)) ways.Add(way);
            }
            else if (RunKey.IsMatch(t))
            {
                // The key opened for a value set elsewhere in the list: the value says it.
                var value = t.Split('›').Select(x => x.Trim()).ToList();
                bool isValue = f.Kind == FindingKind.RegistryWrite && value.Count > 2;
                if (!isValue && members.Any(o => o != f && o.Target.StartsWith(t, StringComparison.Ordinal) && o.Target.Length > t.Length)) continue;
                ways.Add(new Way((own ? "adds itself to the Run key" : "adds a program to the Run key") + (isValue ? $" ({value[^1]})" : ""), own, true));
            }
            else if (t.Contains("Startup folder", StringComparison.OrdinalIgnoreCase))
                ways.Add(new Way((own ? "copies itself to the Startup folder" : "puts a program in the Startup folder")
                                 + (t.Split('›').Last().Trim() is { Length: > 0 } name && !name.Contains("Startup") ? $" ({name})" : ""), own, true));
            else ways.Add(new Way("creates or changes a Windows service", false, true));
        }
        return ways;
    }

    private static string Check(string rule, List<Finding> members)
    {
        var lead = rule switch
        {
            "plant" => "Read where the code it runs as administrator comes from, and who can write there",
            "buildsecret" => "Read the build targets before you build, and what CI runs while the secret is there",
            "hidden" => "Read the hidden passages yourself",
            "security" => "Read the security settings it changes",
            "stays" => "Read what starts on its own, and when",
            "fetches" => "Read where the code it fetches and runs comes from",
            "unseen" => "Read what decides the code it runs",
            "sends" => "Read what it sends and where",
            "builds" => "Build only repos you'd run yourself: what a project's build does is up to that project",
            _ => "Read what the build fetches and runs"
        };
        // Under "Runs when you start the app", the hidden passages in the app's code: the build step has its own heading.
        var listed = rule == "hidden" && members.Any(f => f.Origin == Origin.App) ? members.Where(f => f.Origin == Origin.App).ToList() : members;
        // Every key: whoever checks the list (a person, or an assistant reading Copy for AI) needs them all.
        return lead + ": " + string.Join(", ", listed.Select(f => $"{f.Key} ({f.File}:{f.Line})")) + ".";
    }

    /// <summary>The repo's text files by path: statements, assignments and workflow steps for the rules.</summary>
    private sealed class Source(IReadOnlyList<RepoFile> files)
    {
        private readonly Dictionary<string, string[]> _lines = files.Where(f => f.Text is not null)
            .GroupBy(f => f.Path, StringComparer.Ordinal).ToDictionary(g => g.Key, g => g.First().Text!.Replace("\r", "").Split('\n'), StringComparer.Ordinal);

        /// <summary>The statement starting on a line, up to its semicolon (a few lines at most).</summary>
        public string Statement(string path, int line)
        {
            if (!_lines.TryGetValue(path, out var lines) || line < 1 || line > lines.Length) return "";
            var sb = new System.Text.StringBuilder();
            for (int i = line - 1; i < Math.Min(lines.Length, line + 5); i++)
            {
                sb.Append(lines[i]).Append('\n');
                if (lines[i].Contains(';')) break;
            }
            return sb.ToString();
        }

        /// <summary>A variable the statement uses was assigned, in the lines just before it, from a call the pattern names.</summary>
        /// <summary>Lines just before a statement where a variable it uses is assigned.</summary>
        public List<int> AssignedAt(string path, int line)
        {
            var found = new List<int>();
            if (!_lines.TryGetValue(path, out var lines)) return found;
            foreach (Match id in Regex.Matches(Statement(path, line), @"\b[a-z_]\w*\b"))
                for (int i = line - 2; i >= Math.Max(0, line - 31); i--)
                    if (Regex.IsMatch(lines[i], $@"\b{Regex.Escape(id.Value)}\s*=(?!=)")) { found.Add(i + 1); break; }
            return found;
        }

        public bool AssignedFrom(string path, int line, Regex from)
        {
            if (!_lines.TryGetValue(path, out var lines)) return false;
            var statement = Statement(path, line);
            foreach (Match id in Regex.Matches(statement, @"\b[a-z_]\w*\b"))
                for (int i = line - 2; i >= Math.Max(0, line - 31); i--)
                    if (Regex.IsMatch(lines[i], $@"\b{Regex.Escape(id.Value)}\s*=(?!=)") && from.IsMatch(lines[i])) return true;
            return false;
        }

        /// <summary>A workflow step's lines: from its "- " line to the next step at the same indent or less.</summary>
        public (int From, int To) StepRange(string path, int line)
        {
            if (!_lines.TryGetValue(path, out var lines) || line < 1 || line > lines.Length) return (line, line + 1);
            int start = line - 1;
            while (start > 0 && !Regex.IsMatch(lines[start], @"^\s*-\s")) start--;
            int indent = lines[start].IndexOf('-');
            int end = start + 1;
            while (end < lines.Length)
            {
                var l = lines[end];
                if (l.Trim().Length > 0)
                {
                    int lead = l.Length - l.TrimStart().Length;
                    if (lead < indent || lead == indent && l.TrimStart().StartsWith('-')) break;
                }
                end++;
            }
            return (start + 1, end + 1);
        }
    }

    // The words a declaration would use for each security area.
    private static readonly Dictionary<string, string> AreaWords = new()
    {
        ["Windows Firewall settings"] = @"firewall", ["Microsoft Defender settings"] = @"defender|antivirus|anti-virus",
        ["audit policy"] = @"audit", ["Remote Desktop"] = @"remote desktop|\bRDP\b", ["User Account Control"] = @"\bUAC\b|user account control",
        ["boot settings"] = @"\bboot", ["restore points"] = @"restore point|shadow cop", ["BitLocker"] = @"bitlocker", ["IPsec rules"] = @"ipsec"
    };

    /// <summary>For a declared security line: the areas the code changes that the line doesn't name.</summary>
    private static List<string> Gaps(string rule, List<Finding> members, string declared) =>
        rule != "security" ? []
            : members.Select(SecurityArea).Distinct()
                .Where(a => AreaWords.TryGetValue(a, out var words) && !Regex.IsMatch(declared, words, RegexOptions.IgnoreCase)).ToList();

    private static string SecurityArea(Finding f)
    {
        var t = f.Target + " " + string.Join(" ", f.Commands);
        if (Regex.IsMatch(t, @"(?i)Windows Defender|Antimalware|-Mp|MpPreference")) return "Microsoft Defender settings";
        if (Regex.IsMatch(t, @"(?i)Firewall|advfirewall|FwPolicy|netsh")) return "Windows Firewall settings";
        if (Regex.IsMatch(t, @"(?i)auditpol|Policies\\System\\Audit")) return "audit policy";
        if (Regex.IsMatch(t, @"(?i)Terminal Server")) return "Remote Desktop";
        if (Regex.IsMatch(t, @"(?i)EnableLUA|ConsentPrompt|Policies\\System")) return "User Account Control";
        if (Regex.IsMatch(t, @"(?i)bcdedit|SafeBoot")) return "boot settings";
        if (Regex.IsMatch(t, @"(?i)vssadmin|SystemRestore")) return "restore points";
        if (Regex.IsMatch(t, @"(?i)BitLocker|\\FVE")) return "BitLocker";
        if (Regex.IsMatch(t, @"(?i)IPsec")) return "IPsec rules";
        return "security settings";
    }

    private static string Join(IEnumerable<string> items)
    {
        var list = items.ToList();
        return list.Count switch { 0 => "", 1 => list[0], _ => string.Join(", ", list.Take(list.Count - 1)) + " and " + list[^1] };
    }

    /// <summary>Program names, commands and key names the findings use: words a README would use for them too.</summary>
    private static IEnumerable<string> NamesIn(List<Finding> members) =>
        members.Select(f => f.Program).Where(p => p is not null && p.Length > 2).Select(p => p!)
            .Concat(members.SelectMany(f => f.Commands))
            .Distinct(StringComparer.OrdinalIgnoreCase);

    // ---- what the repo says about itself -------------------------------------------------------

    private sealed record Doc(string Path, string[] Lines);
    private sealed record Labelled(string Label, string Text, string? File, int Line);

    /// <summary>The README first, then the other Markdown at the top and under docs/, then the projects' Description.</summary>
    private static List<Doc> Docs(IReadOnlyList<RepoFile> files)
    {
        static int Depth(string p) => p.Count(c => c == '/');
        var markdown = files.Where(f => f.Text is not null && f.Extension.Equals(".md", StringComparison.OrdinalIgnoreCase)).ToList();
        var readme = markdown.Where(f => System.IO.Path.GetFileNameWithoutExtension(f.Path).Equals("README", StringComparison.OrdinalIgnoreCase))
            .OrderBy(f => Depth(f.Path)).ThenBy(f => f.Path, StringComparer.Ordinal).FirstOrDefault();
        int top = readme is null ? 0 : Depth(readme.Path);
        var docs = new List<Doc>();
        if (readme is not null) docs.Add(new Doc(readme.Path, Split(readme.Text!)));
        foreach (var f in markdown.Where(f => f != readme && (Depth(f.Path) <= top || Regex.IsMatch(f.Path, @"(?i)(?:^|/)docs/")))
                     .OrderBy(f => f.Path, StringComparer.Ordinal).Take(20))
            docs.Add(new Doc(f.Path, Split(f.Text!)));
        foreach (var p in files.Where(f => f.Text is not null && f.Extension.Equals(".csproj", StringComparison.OrdinalIgnoreCase)).OrderBy(f => f.Path, StringComparer.Ordinal))
        {
            var m = Regex.Match(p.Text!, @"<Description>(?<d>[^<]*)</Description>", RegexOptions.IgnoreCase);
            if (m.Success) docs.Add(new Doc(p.Path, Split(p.Text!)));
        }
        return docs;
    }

    private static string[] Split(string text) => text.Replace("\r", "").Split('\n');

    private static readonly Regex Heading = new(@"^\s{0,3}(?<level>#{1,6})\s+(?<text>.*?)\s*#*\s*$", RegexOptions.Compiled);
    // **Label:** or **Label**: — the colon is required, inside or after the bold, so a bold word isn't taken for a label.
    private static readonly Regex Bullet = new(@"^\s*[-*+]\s+\*\*(?<label>[^*:]+?)\s*(?::\s*\*\*|\*\*\s*:)\s*(?<text>.*)$", RegexOptions.Compiled);

    /// <summary>The labelled lines of the declaration section, in the first file that has one (the README first).</summary>
    private static List<Labelled> Section(List<Doc> docs)
    {
        foreach (var doc in docs.Where(d => d.Path.EndsWith(".md", StringComparison.OrdinalIgnoreCase)))
        {
            bool fence = false;
            for (int i = 0; i < doc.Lines.Length; i++)
            {
                // An example of the section inside a code block isn't a declaration.
                if (doc.Lines[i].TrimStart().StartsWith("```", StringComparison.Ordinal) || doc.Lines[i].TrimStart().StartsWith("~~~", StringComparison.Ordinal)) { fence = !fence; continue; }
                if (fence) continue;
                var h = Heading.Match(doc.Lines[i]);
                if (!h.Success || !h.Groups["text"].Value.TrimEnd(':', '.').Equals(SectionHeading, StringComparison.OrdinalIgnoreCase)) continue;
                int level = h.Groups["level"].Value.Length;
                var lines = new List<Labelled>();
                bool inner = false;
                for (int j = i + 1; j < doc.Lines.Length; j++)
                {
                    if (doc.Lines[j].TrimStart().StartsWith("```", StringComparison.Ordinal) || doc.Lines[j].TrimStart().StartsWith("~~~", StringComparison.Ordinal)) { inner = !inner; continue; }
                    if (inner) continue;
                    var next = Heading.Match(doc.Lines[j]);
                    if (next.Success && next.Groups["level"].Value.Length <= level) break;
                    var b = Bullet.Match(doc.Lines[j]);
                    if (b.Success) lines.Add(new Labelled(b.Groups["label"].Value.Trim().TrimEnd(':'), b.Groups["text"].Value.Trim(), doc.Path, j + 1));
                }
                return lines;
            }
        }
        return [];
    }

    /// <summary>The first line in the README or docs that names one of the words, outside code blocks.</summary>
    private static Declaration Mention(List<Doc> docs, List<string> words)
    {
        foreach (var doc in docs)
        {
            bool fence = false;
            for (int i = 0; i < doc.Lines.Length; i++)
            {
                var line = doc.Lines[i];
                if (line.TrimStart().StartsWith("```", StringComparison.Ordinal)) { fence = !fence; continue; }
                if (fence) continue;
                if (doc.Path.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase) && !line.Contains("<Description>", StringComparison.OrdinalIgnoreCase)) continue;
                foreach (var w in words)
                    if (Regex.IsMatch(line, @"(?i)(?<![\w-])" + Regex.Escape(w) + (Regex.IsMatch(w, @"\w$") ? @"(?:s|es)?(?![\w])" : "")))
                        return new Declaration(DeclarationKind.Mentioned, doc.Path, i + 1, Word: w);
            }
        }
        return new Declaration(DeclarationKind.NotFound);
    }
}
