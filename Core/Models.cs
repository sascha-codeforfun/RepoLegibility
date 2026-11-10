using System.IO;
using System.Text.RegularExpressions;
namespace RepoLegibility.Core;

/// <summary>How far a finding reaches: what it can touch if it does what the code says.</summary>
public enum Scope
{
    /// <summary>The app's own folder and files.</summary>
    App,
    /// <summary>The user's profile, documents, HKCU, the user's credentials, anything the user can reach.</summary>
    User,
    /// <summary>What needs administrator rights: changes to HKLM, HKCR, Program Files or system folders, services, the firewall, elevated starts, reading the SAM or SECURITY hive. A read any user can do is User, however machine-wide the place.</summary>
    Admin,
    /// <summary>Remote endpoints and what is sent to them.</summary>
    WebService
}

/// <summary>How well the source shows what a finding does.</summary>
public enum Legibility
{
    /// <summary>Resolved from the source: what it does and to what.</summary>
    Clear,
    /// <summary>"Run time": the kind of action is known; the target is decided when the app runs (settings, input, command line).</summary>
    PartlyClear,
    /// <summary>The trace didn't reach where the value comes from; the reasons say where it ended. Read it yourself.</summary>
    Untraced,
    /// <summary>The source can't show what happens, by nature: a name computed at run time, code loaded from bytes. Read it.</summary>
    Opaque,
    /// <summary>The source holds it, but written so it can't be read: encoded, built from character codes, fragments. Read these first.</summary>
    Obscured
}

/// <summary>Which way a finding moves things: in from this machine, onto it, out of it, in from outside, or running code.</summary>
[Flags]
public enum Direction
{
    None = 0,
    /// <summary>Takes in from this machine: files, the registry, folders, the environment.</summary>
    Reads = 1,
    /// <summary>Changes this machine: writes, deletes, registry changes, services. Not "Writes", so it isn't
    /// taken for the header's Writes pill, which counts file and registry writes only.</summary>
    Changes = 2,
    /// <summary>Data leaves the machine.</summary>
    Sends = 4,
    /// <summary>Data comes in from outside.</summary>
    Receives = 8,
    /// <summary>Starts or loads code.</summary>
    Runs = 16
}

/// <summary>Where the finding sits: code that ships, its tests, its build, or its CI.</summary>
public enum Origin
{
    App,
    Tests,
    Build,
    CI
}

/// <summary>What kind of action a finding is.</summary>
public enum FindingKind
{
    FileWrite,
    FileDelete,
    FileRead,
    FolderListing,
    RegistryWrite,
    RegistryRead,
    Network,
    Listens,
    Database,
    Process,
    Elevation,
    Identity,
    Credential,
    Secret,
    Reflection,
    LoadsCode,
    NativeCode,
    Com,
    Service,
    Wmi,
    EventLog,
    Environment,
    Clipboard,
    EmbeddedData,
    BuildStep,
    CiStep,
    CiAction,
    /// <summary>Not found in the code itself: findings that mean more together (the window's Together rows).</summary>
    Combination
}

public static class Names
{
    public static string Of(Scope scope) => scope switch
    {
        Scope.App => "App scope",
        Scope.User => "User scope",
        Scope.Admin => "Admin scope",
        _ => "Web service scope"
    };

    public static string Short(Scope scope) => scope switch
    {
        Scope.App => "App",
        Scope.User => "User",
        Scope.Admin => "Admin",
        _ => "Web service"
    };

    public static string Of(Legibility legibility) => legibility switch
    {
        Legibility.Clear => "Clear",
        Legibility.PartlyClear => "Run time",
        Legibility.Untraced => "Untraced",
        Legibility.Obscured => "Obscured",
        _ => "Opaque"
    };

    /// <summary>A legibility in plain words, for someone who doesn't read code.</summary>
    public static string Explain(Legibility legibility) => legibility switch
    {
        Legibility.Clear => "The source shows what happens and where.",
        Legibility.PartlyClear => "The source shows what happens; where exactly is decided while the app runs.",
        Legibility.Untraced => "The scan couldn't follow where this comes from; a person can.",
        Legibility.Obscured => "The source holds this, but written so it can't be read: encoded or pieced together. Read these first.",
        _ => "The source can't show what happens here: it depends on something only known while the app runs."
    };

    /// <summary>What a kind of finding is, in plain words: shown beside it for someone who doesn't read code.</summary>
    public static string Explain(FindingKind kind) => kind switch
    {
        FindingKind.FileWrite => "Creates or changes a file.",
        FindingKind.FileDelete => "Deletes a file or folder.",
        FindingKind.FileRead => "Opens a file and reads what's in it.",
        FindingKind.FolderListing => "Looks at which files are in a folder.",
        FindingKind.RegistryWrite => "Changes a value in the Windows registry, the database where Windows and apps keep their settings.",
        FindingKind.RegistryRead => "Reads a value from the Windows registry, the database where Windows and apps keep their settings.",
        FindingKind.Network => "Talks to another computer, over the local network or the internet.",
        FindingKind.Listens => "Waits for other computers or programs to connect to it.",
        FindingKind.Database => "Connects to a database to read or store data.",
        FindingKind.Process => "Starts another program.",
        FindingKind.Elevation => "Has to do with administrator rights: asking for them or checking for them. A program started as administrator is under Starts a process.",
        FindingKind.Identity => "Acts as, or finds out about, a Windows user account.",
        FindingKind.Credential => "Handles a password, a key or another way to sign in.",
        FindingKind.Secret => "A password, key or token written into the source itself.",
        FindingKind.Reflection => "Reflection: code that looks up parts of a program by name while it runs, instead of naming them in the source. Common for settings, plugins and saving data; also a way to hide what runs.",
        FindingKind.LoadsCode => "Loads program code while it runs, code that isn't part of the app as built.",
        FindingKind.NativeCode => "Calls straight into Windows or another program's machine code, outside C#'s safety checks.",
        FindingKind.Com => "Uses a Windows component by name (COM), such as the firewall or Task Scheduler.",
        FindingKind.Service => "Works with Windows services: programs that run in the background, without a window.",
        FindingKind.Wmi => "Asks Windows about the system, or changes it, through WMI, Windows' management interface.",
        FindingKind.EventLog => "Reads or writes the Windows event logs, where Windows and apps record what happened.",
        FindingKind.Environment => "Reads or sets an environment variable, a named value programs pick up when they start.",
        FindingKind.Clipboard => "Reads or changes what's on the clipboard, what you copied.",
        FindingKind.EmbeddedData => "Data built into the app: a file or a blob carried inside the program.",
        FindingKind.BuildStep => "Runs while the app is being built, on the computer that builds it.",
        FindingKind.CiStep => "Runs on the build server (CI) whenever the code is pushed.",
        FindingKind.CiAction => "Someone else's code that runs on the build server (CI).",
        FindingKind.Combination => "Findings that mean more together than one by one.",
        _ => ""
    };

    public static string Of(Origin origin) => origin switch
    {
        Origin.App => "App code",
        Origin.Tests => "Tests",
        Origin.Build => "Build",
        _ => "CI"
    };

    public static string Of(FindingKind kind) => kind switch
    {
        FindingKind.FileWrite => "File write",
        FindingKind.FileDelete => "File delete",
        FindingKind.FileRead => "File read",
        FindingKind.FolderListing => "Folder listing",
        FindingKind.RegistryWrite => "Registry write",
        FindingKind.RegistryRead => "Registry read",
        FindingKind.Network => "Network",
        FindingKind.Listens => "Listens",
        FindingKind.Database => "Database",
        FindingKind.Process => "Starts a process",
        FindingKind.Elevation => "Elevation",
        FindingKind.Identity => "Identity",
        FindingKind.Credential => "Credential",
        FindingKind.Secret => "Secret in the code",
        FindingKind.Reflection => "Reflection",
        FindingKind.LoadsCode => "Loads code",
        FindingKind.NativeCode => "Native code",
        FindingKind.Com => "COM",
        FindingKind.Service => "Windows service",
        FindingKind.Wmi => "WMI",
        FindingKind.EventLog => "Event log",
        FindingKind.Environment => "Environment",
        FindingKind.Clipboard => "Clipboard",
        FindingKind.EmbeddedData => "Embedded data",
        FindingKind.BuildStep => "Build step",
        FindingKind.CiStep => "CI step",
        FindingKind.Combination => "Together",
        _ => "CI action"
    };

    /// <summary>The direction words, in order: "Reads", "Sends"…</summary>
    public static IEnumerable<string> Of(Direction direction) =>
        Enum.GetValues<Direction>().Where(d => d != Direction.None && direction.HasFlag(d)).Select(d => d.ToString());

    /// <summary>Kinds that change something on disk or in the registry: the Writes and Paths pills.</summary>
    public static bool Writes(FindingKind kind) =>
        kind is FindingKind.FileWrite or FindingKind.FileDelete or FindingKind.RegistryWrite;
}

/// <summary>One hop of a trace: where a value was defined and what it was set to.</summary>
public sealed record TraceStep(string File, int Line, string Code);

/// <summary>Lines of source around a finding. <see cref="Focus"/> is the finding's own line.</summary>
public sealed record Excerpt(int FirstLine, int Focus, IReadOnlyList<string> Lines, string? Member);

public sealed class Finding
{
    public int Id { get; set; }

    /// <summary>A key that stays the same across scans and unrelated code changes: "N-3f2a1c".</summary>
    public string Key { get; set; } = "";
    public required FindingKind Kind { get; init; }
    public required Scope Scope { get; init; }
    public required Legibility Legibility { get; set; }

    /// <summary>What a target the scan couldn't trace is called: "not traced".</summary>
    public const string NotTraced = "not traced";

    /// <summary>The target of code nothing in the app calls, where only tests reach it: "only tests reach it".</summary>
    public const string OnlyTestsReach = "only tests reach it";
    public required Origin Origin { get; init; }
    public required string File { get; init; }
    public required int Line { get; init; }
    /// <summary>The call or construct as written, short: "File.WriteAllText", "[DllImport] user32.dll SendInput".</summary>
    public required string Call { get; init; }
    /// <summary>What it acts on, as far as the source shows: "exe folder › settings.json", "https://api.github.com/…".</summary>
    public required string Target { get; set; }
    /// <summary>One sentence on what it does.</summary>
    public required string Summary { get; init; }
    /// <summary>What decides the target, or where the trace stopped; one reason per line.</summary>
    public IReadOnlyList<string> Reasons { get; init; } = [];
    /// <summary>Notes that don't change legibility: "starts with Windows", "can observe input".</summary>
    public IReadOnlyList<string> Notes { get; set; } = [];
    public IReadOnlyList<TraceStep> Trace { get; init; } = [];
    public Excerpt? Excerpt { get; set; }
    /// <summary>The project the file belongs to, if any.</summary>
    public string? Project { get; init; }
    /// <summary>A key for the Paths pill: the same target written from several places counts once.</summary>
    public string? PathKey { get; init; }
    /// <summary>
    /// When the call sits in a helper that passes its parameter straight on: the helper's calls,
    /// each judged where it is. The finding takes the widest scope and the least legible of them.
    /// </summary>
    public IReadOnlyList<CallSite> Calls { get; init; } = [];

    /// <summary>
    /// The author hid the value: Base64, character codes, fragments, XOR, reversal, encryption,
    /// encoded PowerShell. A strong sign in itself, kept even when the value is worked out.
    /// </summary>
    public bool HiddenOnPurpose { get; set; }

    /// <summary>Declared, looked up or created, but not used in this source: a capability, not an action.</summary>
    public bool Unused { get; set; }

    /// <summary>Which way it moves things; None for what only declares or looks up.</summary>
    public Direction Direction { get; set; }

    /// <summary>The marks beside legibility and scope, in words: for the PDF and the AI export.</summary>
    public IEnumerable<string> Marks()
    {
        if (HiddenOnPurpose) yield return "hidden on purpose" + (HowHidden is null ? "" : $" ({HowHidden})");
        if (Unused) yield return "not used in this source";
        if (NotCalledByApp) yield return "not called by the app";
        foreach (var d in Names.Of(Direction)) yield return d.ToLowerInvariant();
    }

    /// <summary>The program it starts, by name without .exe: "powershell", "netsh". Null when it starts none.</summary>
    public string? Program { get; set; }

    /// <summary>For a PowerShell script: the commands in it that act on the machine, in order.</summary>
    public IReadOnlyList<string> Commands { get; set; } = [];

    /// <summary>What a request sends, when the source shows it: "the Windows user name".</summary>
    public string? Sends { get; set; }

    /// <summary>How it was hidden: "decoded from Base64 at run time, turned from bytes into text at run time".</summary>
    public string? HowHidden { get; set; }

    /// <summary>Who decides what happens, in plain words: "the app's settings", "you", "a server on the internet".</summary>
    public string? WhoDecides { get; set; }

    /// <summary>For reflection and loaded code: how far it can reach, "only the app's own types (Config)".</summary>
    public string? LooksInside { get; set; }

    /// <summary>
    /// Code that ships but that nothing in the app calls: every way to it ends at a method only tests
    /// call. In the shipped app it doesn't run unless something outside the repo calls it.
    /// </summary>
    public bool NotCalledByApp { get; set; }

    /// <summary>
    /// A read of a machine-wide place (HKLM, Program Files, the Windows folder) that any user can make: its scope is User,
    /// since it needs no administrator rights, but the Overview still counts it under the whole computer.
    /// </summary>
    public bool MachineWide { get; set; }

    /// <summary>
    /// A program it starts as administrator (Verb = "runas"): a "Starts a process" finding at Admin scope, not an
    /// Elevation one, since what it does is start that program. The header's Admin pill and the Overview count it.
    /// </summary>
    public bool AsAdministrator { get; set; }

    /// <summary>Calls of the helper that weren't followed (more than the scan follows per finding).</summary>
    public int CallsNotFollowed { get; init; }

    /// <summary>For the Paths pill: the places the helper's calls write to.</summary>
    public IReadOnlyList<string> PathKeys { get; init; } = [];
}

/// <summary>One call of a helper: where it is, and what its value comes to there.</summary>
public sealed record CallSite(string File, int Line, Legibility Legibility, Scope Scope, string Target, string? Reason, IReadOnlyList<string> Via);

public sealed record ProjectInfo(
    string Path,
    string Name,
    string Kind,
    IReadOnlyList<string> Frameworks,
    string Ui,
    bool IsTest,
    int Sloc);

public sealed record PackageInfo(string Name, string Version, string Project, bool TestOnly);

public sealed record ReferenceInfo(string Kind, string Name, string From);

public sealed record BlackBox(string Path, long Bytes, string Kind, string Sha256);

/// <summary>A web address named in the repo; the note says when it was worked out or isn't requested.</summary>
public sealed record Endpoint(string Url, string Host, IReadOnlyList<string> Where, string? Note = null)
{
    public string Display => Note is null ? Url : $"{Url} ({Note})";
}

public sealed record FileSize(string Path, int Sloc);

public sealed record CiAction(string Uses, bool Pinned, string Where);

/// <summary>Facts for judging the repo, no scores.</summary>
public sealed class Metrics
{
    public int Files { get; init; }
    public long Bytes { get; init; }
    public int CsFiles { get; init; }
    public int Sloc { get; init; }
    public int CommentLines { get; init; }
    public int GeneratedFiles { get; init; }
    public int GeneratedSloc { get; init; }
    public int XamlLines { get; init; }
    public int TestSloc { get; init; }
    public IReadOnlyList<(string Extension, int Count)> ByExtension { get; init; } = [];
    public IReadOnlyList<FileSize> Largest { get; init; } = [];
    public int PInvokes { get; init; }
    public int UnsafeBlocks { get; init; }

    /// <summary>Projects that switch on AllowUnsafeBlocks.</summary>
    public IReadOnlyList<string> UnsafeAllowedIn { get; init; } = [];

    /// <summary>Lines of C# outside tests.</summary>
    public int AppSloc => Sloc - TestSloc;

    /// <summary>Reading time for a careful review at 400 and 200 lines an hour.</summary>
    public (double Low, double High) ReviewHours => (Sloc / 400.0, Sloc / 200.0);
}

public sealed class ScanReport
{
    public required string ZipName { get; init; }
    public required string ZipSha256 { get; init; }
    public required long ZipBytes { get; init; }
    public required string RepoName { get; init; }
    public required DateTime ScannedAt { get; init; }
    public TimeSpan Took { get; set; }
    public required string ToolVersion { get; init; }

    public required IReadOnlyList<Finding> Findings { get; init; }
    public required Metrics Metrics { get; init; }
    public required IReadOnlyList<ProjectInfo> Projects { get; init; }
    public required IReadOnlyList<PackageInfo> Packages { get; init; }
    public required IReadOnlyList<ReferenceInfo> References { get; init; }
    public required IReadOnlyList<CiAction> CiActions { get; init; }
    public required IReadOnlyList<BlackBox> BlackBoxes { get; init; }
    public required IReadOnlyList<Endpoint> Endpoints { get; init; }
    /// <summary>What the scan can't see: other languages, files it skipped.</summary>
    public required IReadOnlyList<string> NotCovered { get; init; }

    /// <summary>Findings that mean more together, with what the README says about them. Not counted in the pills.</summary>
    public IReadOnlyList<Combination> Combinations { get; set; } = [];

    /// <summary>The plain-words report: questions, and what it reads and changes, area by area.</summary>
    public Overview? Overview { get; set; }

    /// <summary>Findings that count: everything but the tests.</summary>
    public IEnumerable<Finding> Counted => Findings.Where(f => f.Origin != Origin.Tests);

    public int Opaque => Counted.Count(f => f.Legibility == Legibility.Opaque);
    public int Obscured => Counted.Count(f => f.Legibility == Legibility.Obscured);

    /// <summary>Opaque findings whose hidden value the scan worked out (decoded or assembled).</summary>
    public int Decoded => Counted.Count(f => f.Legibility == Legibility.Obscured && Regex.IsMatch(f.Target, @"\((?:decoded|assembled)\)"));
    public int PartlyClear => Counted.Count(f => f.Legibility == Legibility.PartlyClear);
    public int Untraced => Counted.Count(f => f.Legibility == Legibility.Untraced);
    public int Clear => Counted.Count(f => f.Legibility == Legibility.Clear);
    public int Writes => Counted.Count(f => Names.Writes(f.Kind));
    public int Paths => Counted.Where(f => Names.Writes(f.Kind))
        .SelectMany(f => f.PathKeys.Count > 0 ? f.PathKeys : [f.PathKey ?? f.Target])
        .Distinct(StringComparer.OrdinalIgnoreCase).Count();
    public bool Admin => Counted.Any(f => (f.Kind == FindingKind.Elevation || f.AsAdministrator) && f.Scope == Scope.Admin);

    /// <summary>
    /// How it gets administrator rights, for the header's Admin pill: the manifest asks when it starts, or it
    /// asks mid-way (runas) for a program it starts. Null without elevation.
    /// </summary>
    public string? AdminHow
    {
        get
        {
            var elevations = Counted.Where(f => (f.Kind == FindingKind.Elevation || f.AsAdministrator) && f.Scope == Scope.Admin).ToList();
            if (elevations.Count == 0) return null;
            var manifest = elevations.FirstOrDefault(f => f.Call.StartsWith("requestedExecutionLevel", StringComparison.Ordinal));
            var others = elevations.Where(f => f != manifest).ToList();
            string? runs = null;
            if (others.Count > 0)
            {
                var first = others[0];
                var who = first.Program ?? first.Target;
                if (who.Length > 40) who = who[..39] + "…";
                runs = $"{who} as administrator ({first.File}:{first.Line})" + (others.Count > 1 ? $" and {others.Count - 1} more" : "");
            }
            if (manifest is null) return "Windows asks for administrator rights when it runs " + runs + ".";
            var level = manifest.Call.Contains("highestAvailable", StringComparison.Ordinal)
                ? $"when it can (highestAvailable in {manifest.File})"
                : $"when it starts (requireAdministrator in {manifest.File})";
            // Already elevated: starting a program with runas doesn't make Windows ask again.
            return "Windows asks for administrator rights " + level + (runs is null ? "" : "; it also starts " + runs) + ".";
        }
    }

    public int TestFindings => Findings.Count(f => f.Origin == Origin.Tests);

    /// <summary>Findings in the app's C# (not tests, not build, CI or config files): what the density counts.</summary>
    public int CodeFindings => Counted.Count(f => f.File.EndsWith(".cs", StringComparison.OrdinalIgnoreCase));

    /// <summary>Findings outside tests that sit in build, CI, manifest or config files, counted apart from the C#.</summary>
    public int OtherFindings => Counted.Count() - CodeFindings;

    /// <summary>Findings in the app's C# per 1,000 lines of C# outside tests.</summary>
    public double AppDensity => Metrics.AppSloc == 0 ? 0 : CodeFindings * 1000.0 / Metrics.AppSloc;

    /// <summary>Findings in tests per 1,000 lines of test code.</summary>
    public double TestDensity => Metrics.TestSloc == 0 ? 0 : TestFindings * 1000.0 / Metrics.TestSloc;
}
