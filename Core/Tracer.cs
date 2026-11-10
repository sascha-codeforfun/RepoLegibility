using System.IO;
using System.Text.RegularExpressions;
using CSharpLexing;

namespace RepoLegibility.Core;

/// <summary>Where a value comes from, as far as a trace reached.</summary>
public enum SourceKind
{
    ExeFolder,
    WorkingFolder,
    FolderListing,
    Temp,
    UserFolder,
    MachineFolder,
    UserPicked,
    CommandLine,
    Configuration,
    UserTyped,
    EnvironmentVariable,
    HiveUser,
    HiveMachine,
    NetworkShare,
    FixedPath,
    /// <summary>What the user picks in a list in a window: a selection bound in XAML.</summary>
    ListPick,
    /// <summary>A value read from the registry (key.GetValue): the place is what that value holds when it runs.</summary>
    RegistryValue,
    /// <summary>The names of a key's values or subkeys (GetValueNames, GetSubKeyNames): whatever is there when it runs.</summary>
    RegistryNames,
    /// <summary>What a Windows event says (EventLogReader.ReadEvent, EventLog.Entries): whatever was logged.</summary>
    EventLog,
    /// <summary>What a program it starts prints (StandardOutput.ReadToEnd): whatever that program says.</summary>
    ProgramOutput,
    /// <summary>The drives the machine has (DriveInfo.GetDrives, GetLogicalDrives): which one is decided where it runs.</summary>
    Drives
}

public sealed record Source(SourceKind Kind, string Label, Scope Scope)
{
    /// <summary>A source that leaves the value open at run time: the action is known, the target isn't fixed.</summary>
    public bool Open => Kind is SourceKind.CommandLine or SourceKind.Configuration or SourceKind.UserTyped or SourceKind.FolderListing or SourceKind.RegistryValue or SourceKind.RegistryNames or SourceKind.EventLog or SourceKind.ProgramOutput or SourceKind.Drives
        || (Kind == SourceKind.EnvironmentVariable && Scope == Scope.App);
}

/// <summary>
/// Follows an expression back through the variables, fields, properties, methods and method
/// parameters it is built from, collecting where its parts come from, the literals in it, and what
/// makes it hard to read. Reads the source, runs nothing: what it can't follow is reported as such,
/// never guessed.
/// </summary>
public sealed class Tracer
{
    // Measured on CrawlerSuite: 12 deep resolves what 8 doesn't, for about 5 % more time; going
    // further (24, 64) resolves nothing more. What stays untraced ends at a dead end, not a distance.
    public const int MaxDepth = 12;
    public const int MaxHops = 120;
    private const int MaxCallers = 6;
    private const int MaxDefinitions = 6;
    private const int GlobDepth = 4;
    private const int MaxExpression = 2000;

    private readonly CodeBase _code;
    private readonly HashSet<string> _seen = new(StringComparer.Ordinal);

    public List<Source> Sources { get; } = new();
    private readonly Dictionary<Source, int> _sourceDepth = new();
    private readonly List<(string Text, int Depth)> _literalDepth = new();
    private int _depth;
    /// <summary>Literal contents, holes shown as {}, in the order found (the top expression first).</summary>
    public List<string> Literals { get; } = new();
    public List<TraceStep> Steps { get; } = new();
    public List<string> Unresolved { get; } = new();
    private readonly Dictionary<string, int> _unresolvedDepth = new();
    public List<string> OpaqueReasons { get; } = new();

    /// <summary>Names of settings the value depends on: properties of a type filled from a settings file.</summary>
    private readonly List<string> _settings = new();

    /// <summary>
    /// A property set at run time: when its type is filled from a settings file, say so and where;
    /// otherwise say what's known about it.
    /// </summary>
    private void RunTimeProperty(string name, string otherwise, string? ownerType = null)
    {
        if (_code.SettingOf(name, ownerType) is { } setting)
        {
            if (!_settings.Contains(name)) _settings.Add(name);
            AddUnresolved($"{name}, a setting in {setting.Type}, filled from {setting.Where}", data: true);
        }
        else AddUnresolved($"{name}, {otherwise}", data: true);
    }

    /// <summary>Values the source hides but fixes, worked out: the value and how it was hidden.</summary>
    public List<(string Value, string How)> Decoded { get; } = new();

    /// <summary>A null (or default) was among the values followed: Remember(word, null, []).</summary>
    public bool PassesNull { get; private set; }
    public HashSet<string> Files { get; } = new(StringComparer.OrdinalIgnoreCase);
    public bool DepthExceeded { get; private set; }
    /// <summary>The trace took more steps than it follows; what's listed is what it reached.</summary>
    public bool Stopped { get; private set; }
    public int Hops { get; private set; }

    /// <summary>Where the trace stopped when it ran out of depth or steps.</summary>
    public TraceStep? StoppedAt { get; private set; }

    /// <summary>Local mode only: the method parameters the value reached, not followed to their callers.</summary>
    public List<(CodeFile File, string Method, int Index, int Position, string Name)> ParamHits { get; } = new();

    private readonly bool _local;
    private readonly HashSet<(string File, int CallOpen, int Param)> _lambdasFollowed = new();

    private Tracer(CodeBase code, bool local)
    {
        _code = code;
        _local = local;
    }

    /// <summary>
    /// Follows a value. The same value at the same place gives the same trace, and helpers ask for the
    /// same call sites again and again (four writes in one helper trace its callers four times), so
    /// finished traces are kept per code base. A finished trace is never changed afterwards.
    /// </summary>
    public static Tracer Run(CodeBase code, string expression, CodeFile file, int position) =>
        code.Traces.GetOrAdd((file.Path, position, expression, false), _ =>
        {
            var tracer = new Tracer(code, local: false);
            tracer.Files.Add(file.Path);
            tracer.Follow(expression, file, position, 0);
            return tracer;
        });

    /// <summary>
    /// Follows a value inside a helper as one call of it sees it: the helper's parameters are that call's
    /// arguments. Run(Tool.Schtasks, "/create …") gives schtasks /create, not every tool Run is given.
    /// </summary>
    public static Tracer RunBound(CodeBase code, string expression, CodeFile file, int position,
        string method, List<string> args, CodeFile callFile, int callPosition) =>
        code.Traces.GetOrAdd((file.Path, position, expression + "\u0001" + callFile.Path + ":" + callPosition, false), _ =>
        {
            var tracer = new Tracer(code, local: false);
            tracer.Files.Add(file.Path);
            if (Bind(method, file, position, args, callFile, callPosition) is { } binding) tracer._bindings.Add(binding);
            tracer.Follow(expression, file, position, 0);
            return tracer;
        });

    /// <summary>
    /// Follows a value inside its own method only: method parameters are recorded, not followed to
    /// the callers. A value that is nothing but one parameter of the method around it makes that
    /// method a wrapper of the call.
    /// </summary>
    public static Tracer RunLocal(CodeBase code, string expression, CodeFile file, int position) =>
        code.Traces.GetOrAdd((file.Path, position, expression, true), _ =>
        {
            var tracer = new Tracer(code, local: true);
            tracer.Files.Add(file.Path);
            tracer.Follow(expression, file, position, 0);
            return tracer;
        });

    // Contextual keywords a variable can be named: "ChangeSet set", "var group = …".
    private static readonly HashSet<string> ContextualNames = new(StringComparer.Ordinal)
        { "get", "set", "init", "let", "from", "where", "select", "group", "by", "into", "on", "join", "equals", "record", "required", "scoped", "managed" };

    // Names that belong to the language or the base library: never followed, never "unresolved".
    private static readonly HashSet<string> Keywords = new(StringComparer.Ordinal)
    {
        "var", "new", "string", "null", "true", "false", "this", "base", "await", "return", "nameof", "typeof", "default",
        "int", "uint", "long", "ulong", "short", "ushort", "bool", "object", "char", "byte", "sbyte", "double", "decimal",
        "float", "dynamic", "out", "ref", "in", "is", "as", "when", "and", "or", "not", "using", "static", "const",
        "readonly", "params", "checked", "unchecked", "sizeof", "stackalloc", "switch", "throw", "with", "value", "nint", "nuint",
        "async", "get", "set", "init", "let", "from", "where", "select", "orderby", "group", "by", "into", "on", "equals", "ascending",
        "descending", "join", "global", "scoped", "managed", "unmanaged", "try", "catch", "finally", "if", "else", "for", "foreach",
        "while", "do", "break", "continue", "goto", "lock", "yield", "case", "fixed", "unsafe", "volatile", "event", "operator",
        "implicit", "explicit", "virtual", "override", "abstract", "sealed", "public", "private", "protected", "internal", "extern",
        "void", "class", "struct", "record", "interface", "enum", "namespace", "delegate", "required"
    };

    // Names that are themselves a source: matched by the source patterns, not followed.
    private static readonly HashSet<string> SourceNames = new(StringComparer.Ordinal)
    {
        "BaseDirectory", "ProcessPath", "MainModule", "GetTempPath", "GetTempFileName", "GetFolderPath", "CurrentDirectory",
        "GetCurrentDirectory", "FileName", "FileNames", "SelectedPath", "FolderName", "FolderNames", "GetEnvironmentVariable",
        "ExpandEnvironmentVariables", "GetCommandLineArgs", "CurrentUser", "LocalMachine", "ClassesRoot", "Users", "CurrentConfig",
        "ReadLine", "StartupPath", "ExecutablePath", "Location", "AppSettings", "ConnectionStrings", "Args", "SpecialFolder"
    };

    private static readonly Regex Identifier = new(@"(?<![\w.""@$])(?<dotted>(?:[A-Za-z_]\w*\s*\??\.\s*)*)(?<name>[A-Za-z_]\w*)(?<call>\s*(?:<[^<>()]*>)?\s*\()?", RegexOptions.Compiled);

    private static readonly (Regex Pattern, Func<Match, Source> Make)[] SourcePatterns =
    [
        (new(@"SpecialFolder\.(?<f>ApplicationData|LocalApplicationData|MyDocuments|Personal|Desktop|DesktopDirectory|UserProfile|Startup|Favorites|Recent|SendTo|StartMenu|Programs|MyMusic|MyPictures|MyVideos|Cookies|History|InternetCache|Templates|AdminTools|CDBurning|LocalizedResources)\b", RegexOptions.Compiled),
            m => new Source(SourceKind.UserFolder, "user's " + FolderLabel(m.Groups["f"].Value), Scope.User)),
        (new(@"SpecialFolder\.(?<f>CommonApplicationData|CommonDocuments|CommonDesktopDirectory|CommonStartup|CommonPrograms|CommonStartMenu|CommonTemplates|CommonAdminTools|CommonMusic|CommonPictures|CommonVideos|CommonOemLinks|ProgramFiles|ProgramFilesX86|CommonProgramFiles|CommonProgramFilesX86|Windows|System|SystemX86|Fonts|Resources)\b", RegexOptions.Compiled),
            m => new Source(SourceKind.MachineFolder, FolderLabel(m.Groups["f"].Value), Scope.Admin)),
        // Path.GetPathRoot(Environment.SystemDirectory): the system drive's root, shared by every account on the machine.
        // Only the system drive's: the root of any other path is that path's own business, followed as usual.
        (new(@"\bPath\.GetPathRoot\s*\(\s*(?:Environment\s*\.\s*(?:SystemDirectory\b|GetFolderPath\s*\(\s*(?:Environment\s*\.\s*)?SpecialFolder\s*\.\s*(?:System|SystemX86|Windows)\b|GetEnvironmentVariable\s*\(\s*""(?i:SystemRoot|SystemDrive|windir)""))", RegexOptions.Compiled),
            _ => new Source(SourceKind.MachineFolder, "the drive's root", Scope.Admin)),
        // key.GetValue(name), Registry.LocalMachine.OpenSubKey(…)?.GetValue(…): what the registry holds, not a path
        // made of the key's name. (PropertyInfo.GetValue(obj) is reflection: its receiver isn't a key.)
        (new(@"(?:\b\w*[Kk]ey\b\s*\??|\bRegistry\s*\.\s*\w+(?:\s*\.\s*OpenSubKey\s*\([^()]*\))?\s*\??)\s*\.\s*GetValue\s*\(", RegexOptions.Compiled),
            _ => new Source(SourceKind.RegistryValue, "a value read from the registry", Scope.User)),
        // p.StandardOutput.ReadToEnd(): the text a started program prints; whatever it says when it runs.
        (new(@"\b[A-Za-z_][\w.]*\s*\.\s*Standard(?:Output|Error)\s*\.\s*Read(?:ToEnd|Line)(?:Async)?\s*\(", RegexOptions.Compiled),
            _ => new Source(SourceKind.ProgramOutput, "what a program it starts prints", Scope.User)),
        // reader.ReadEvent(), EventLog.Entries: what an event holds is whatever was logged, not the log's name.
        (new(@"\.\s*ReadEvent\s*\(|\bnew\s+EventLogReader\s*\(|\bnew\s+EventLog\s*\([^()]*\)\s*\.\s*Entries\b|\.\s*EventRecord\b", RegexOptions.Compiled),
            _ => new Source(SourceKind.EventLog, "what a Windows event log entry says", Scope.User)),
        // key.GetValueNames(): like a folder listing, the names are whatever the registry holds when it runs.
        (new(@"\.\s*Get(?:Value|SubKey)Names\s*\(", RegexOptions.Compiled),
            _ => new Source(SourceKind.RegistryNames, "names found in the registry at run time", Scope.User)),
        // DriveInfo.GetDrives(): a drive's root is the place, and which drive is whatever the machine has.
        (new(@"\bDriveInfo\s*\.\s*GetDrives\s*\(|\b(?:Environment|Directory)\s*\.\s*GetLogicalDrives\s*\(", RegexOptions.Compiled),
            _ => new Source(SourceKind.MachineFolder, "a drive's root", Scope.User)),
        (new(@"\bDriveInfo\s*\.\s*GetDrives\s*\(|\b(?:Environment|Directory)\s*\.\s*GetLogicalDrives\s*\(", RegexOptions.Compiled),
            _ => new Source(SourceKind.Drives, "a drive found at run time", Scope.User)),
        (new(@"\bPath\.GetTemp(?:Path|FileName)\s*\(", RegexOptions.Compiled),
            _ => new Source(SourceKind.Temp, "temp folder", Scope.User)),
        (new(@"\bAppContext\.BaseDirectory\b|\bAppDomain\.CurrentDomain\.BaseDirectory\b|\bEnvironment\.ProcessPath\b|\.MainModule\b|\bApplication\.(?:StartupPath|ExecutablePath)\b|GetEntryAssembly\(\)\s*\??\.\s*Location\b|GetExecutingAssembly\(\)\s*\.\s*Location\b", RegexOptions.Compiled),
            _ => new Source(SourceKind.ExeFolder, "exe folder", Scope.App)),
        (new(@"374DE290-123F-4565-9164-39C4925E467B|FOLDERID_Downloads|KnownFolder\w*\.Downloads\b", RegexOptions.Compiled | RegexOptions.IgnoreCase),
            _ => new Source(SourceKind.UserFolder, "user's Downloads", Scope.User)),
        (new(@"\bSHGetKnownFolderPath\s*\(", RegexOptions.Compiled),
            _ => new Source(SourceKind.UserFolder, "a known user folder", Scope.User)),
        (new(@"\bDirectory\.(?:Get|Enumerate)(?:Files|Directories|FileSystemEntries)\s*\(|\.(?:GetFiles|EnumerateFiles|GetDirectories|EnumerateDirectories|GetFileSystemInfos|EnumerateFileSystemInfos)\s*\(", RegexOptions.Compiled),
            _ => new Source(SourceKind.FolderListing, "files found in a folder at run time", Scope.App)),
        (new(@"\bEnvironment\.CurrentDirectory\b|\bDirectory\.GetCurrentDirectory\s*\(", RegexOptions.Compiled),
            _ => new Source(SourceKind.WorkingFolder, "working folder", Scope.App)),
        (new(@"GetEnvironmentVariable\s*\(\s*(?:@|\$)?""(?<v>[^""]+)""|%(?<v>[A-Za-z_][\w()]*)%", RegexOptions.Compiled),
            m => EnvSource(m.Groups["v"].Value)),
        (new(@"\bRegistry\.CurrentUser\b|HKEY_CURRENT_USER|RegistryHive\.CurrentUser\b|\bHKCU\\", RegexOptions.Compiled),
            _ => new Source(SourceKind.HiveUser, "HKCU", Scope.User)),
        (new(@"\bRegistry\.(?:LocalMachine|ClassesRoot|Users|CurrentConfig)\b|HKEY_(?:LOCAL_MACHINE|CLASSES_ROOT|USERS|CURRENT_CONFIG)|RegistryHive\.(?:LocalMachine|ClassesRoot|Users|CurrentConfig)\b|\bHKLM\\", RegexOptions.Compiled),
            m => new Source(SourceKind.HiveMachine, m.Value.Contains("Classes", StringComparison.OrdinalIgnoreCase) || m.Value.Contains("CLASSES") ? "HKCR"
                : m.Value.Contains("Users", StringComparison.OrdinalIgnoreCase) || m.Value.Contains("USERS") ? "HKU" : "HKLM", Scope.Admin)),
        (new(@"\bGetCommandLineArgs\s*\(|\bargs\s*\[|\bArgs\s*\[", RegexOptions.Compiled),
            _ => new Source(SourceKind.CommandLine, "the command line", Scope.User)),
        (new(@"\bConfigurationManager\.|\bIConfiguration\b|\bConfiguration\s*\[|\bGetSection\s*\(|\bGetValue<", RegexOptions.Compiled),
            _ => new Source(SourceKind.Configuration, "configuration", Scope.User)),
        (new(@"\bConsole\.ReadLine\s*\(|\b\w+(?:Box|Input|Field)\.Text\b", RegexOptions.Compiled),
            _ => new Source(SourceKind.UserTyped, "what the user types", Scope.User))
    ];

    // (a, b) =>, (string a, int b) =>, x => — parameters separated by commas, so the pattern can't backtrack.
    private static readonly Regex LambdaParameters = new(
        @"(?:\(\s*(?:(?:[\w<>\[\]?]+\s+)?(?<p>[A-Za-z_]\w*)(?:\s*,\s*(?:[\w<>\[\]?]+\s+)?(?<p>[A-Za-z_]\w*))*)?\s*\)|(?<p>[A-Za-z_]\w*))\s*=>",
        RegexOptions.Compiled);

    private static readonly Regex Fragments = new(
        @"(?:(?:@?""[^""\r\n]{1,3}""|'[^'\r\n]{1,2}')\s*\+\s*){3,}(?:@?""[^""\r\n]{1,3}""|'[^'\r\n]{1,2}')" +
        @"|\b(?:string\.Concat|String\.Concat|string\.Join\s*\(\s*""""\s*,|String\.Join\s*\(\s*""""\s*,)\s*\(?\s*(?:@?""[^""\r\n]{1,3}""\s*,\s*){3,}",
        RegexOptions.Compiled);

    // Anchored at the end of the text before a name: "subject is { } ", "subject is Type ".
    private static readonly Regex IsPattern = new(
        @"(?<subj>[A-Za-z_][\w.?]*(?:\[[^\[\];]*\]|\([^();]*\))?)\s+is\s+(?:not\s+)?(?:\{[^{};]*\}|[\w.<>?\[\]]+(?:\s*\{[^{};]*\})?)\s+$",
        RegexOptions.Compiled | RegexOptions.RightToLeft);

    // Anchored likewise: "receiver.Method(…, out var ", "receiver.Method(…, out Type ".
    private static readonly Regex OutArgument = new(
        @"(?<recv>[A-Za-z_][\w.]*)\s*\??\.\s*[A-Za-z_]\w*\s*\((?:[^;()]|\([^;()]*\))*\bout\s+(?:var|[\w<>\[\]?.]+)\s+$",
        RegexOptions.Compiled | RegexOptions.RightToLeft);

    // The whole call, receiver and all: e.Data.GetData(DataFormats.FileDrop) is the files, not e.
    private static readonly Regex FileDrop = new(@"\b[A-Za-z_][\w.]*\s*\.\s*(?:GetData\s*\([^()]*DataFormats\s*\.\s*FileDrop[^()]*\)|GetFileDropList\s*\(\s*\))", RegexOptions.Compiled);
    private static readonly Regex FileDropAny = new(@"\bDataFormats\s*\.\s*FileDrop\b|\.\s*GetFileDropList\s*\(", RegexOptions.Compiled);
    private static readonly Regex NewGeneric = new(@"\bnew\s+[A-Za-z_][\w.]*\s*<", RegexOptions.Compiled);
    private static readonly Regex ListingCalls = new(@"\b(?:Directory\s*\.\s*)?(?:Get|Enumerate)(?:Files|Directories|FileSystemEntries|FileSystemInfos)\s*\(", RegexOptions.Compiled);
    private static readonly Regex KeyCalls = new(@"\.\s*(?:TryGetValue|GetValueOrDefault|ContainsKey)\s*\(", RegexOptions.Compiled);
    private static readonly Regex FlagCalls = new(@"\b(?:OpenSubKey|CreateSubKey|OpenBaseKey|OpenRemoteBaseKey)\s*\(", RegexOptions.Compiled);

    private static readonly Regex Trivial = new(@"^\s*(?:null|default|""""|string\.Empty|String\.Empty|default\([^()]*\))\s*!?\s*$", RegexOptions.Compiled);

    private static readonly Regex Dialog = new(@"\.\s*(?:FileName|FileNames|SelectedPath|FolderName|FolderNames)\b", RegexOptions.Compiled);

    private static readonly (Regex Pattern, string Reason)[] OpaquePatterns =
    [
        (new(@"\bFromBase64String\s*\(", RegexOptions.Compiled), "decoded from Base64 at run time"),
        (new(@"\bEncoding\s*\.\s*\w+\s*\.\s*GetString\s*\(|\bGetString\s*\(\s*new\s+byte", RegexOptions.Compiled), "turned from bytes into text at run time"),
        (new(@"new\s+string\s*\(\s*new\s*(?:char\s*)?\[|\(\s*char\s*\)\s*[\w(]|\bstring\.Concat\s*\(\s*new\s*(?:char\s*)?\[", RegexOptions.Compiled), "built from character codes"),
        (new(@"[\w)\]'""]\s*\^\s*[\w('(]", RegexOptions.Compiled), "changed with XOR"),
        // Text turned backwards: new string(s.Reverse().ToArray()), string.Concat(s.Reverse()), Array.Reverse(chars) with
        // new string. Not a list of steps undone in reverse order: that's ordering, not hiding.
        (new(@"(?:new\s+string\s*\(|string\s*\.\s*(?:Concat|Join)\s*\(|\.ToCharArray\s*\()[^;]*\bReverse\s*\(|\bReverse\s*\([^;]*(?:new\s+string\s*\(|string\s*\.\s*(?:Concat|Join)\s*\()", RegexOptions.Compiled), "reversed at run time"),
        (new(@"\bDecrypt\w*\s*\(|\.CreateDecryptor\s*\(|\bProtectedData\.Unprotect\s*\(", RegexOptions.Compiled), "decrypted at run time")
    ];

    private void Follow(string expression, CodeFile file, int position, int depth)
    {
        if (Hops >= MaxHops)
        {
            Stopped = true;
            StoppedAt ??= new TraceStep(file.Path, file.LineOf(position), Shorten(expression));
            return;
        }
        if (depth > MaxDepth)
        {
            // SelectedB.Path at the limit: a list the user picks from is an answer, not a dead end.
            var bound = Regex.Match(expression, @"^\s*(?<p>[A-Z]\w*)\s*(?:\??\.\s*\w+\s*)?$");
            if (bound.Success && AddListPick(bound.Groups["p"].Value, file, position, depth)) return;
            DepthExceeded = true;
            StoppedAt ??= new TraceStep(file.Path, file.LineOf(position), Shorten(expression));
            return;
        }
        Hops++;
        Files.Add(file.Path);
        if (Regex.IsMatch(expression, @"^\s*(?:null|default)\s*!?\s*$")) PassesNull = true;

        if (depth > 0)
            Steps.Add(new TraceStep(file.Path, file.LineOf(position), Shorten(expression)));

        // A value this large is a table or a block of data, not a path or an address: say so, don't read it all.
        if (expression.Length > MaxExpression)
        {
            AddUnresolved($"a large value built at {file.Path}:{file.LineOf(position)}", data: true);
            return;
        }

        _depth = depth;
        // const string PathsKey = ExclusionsKey + @"\Paths": constants joined, fixed in the source. The whole
        // value is the literal, in its order, rather than its pieces found one by one.
        // Only names and plain literals: anything else (new string(…), a decode) goes the long way, where hiding is caught.
        if (Fold.SplitTop(expression.Trim(), '+') is { Count: > 1 } joinedTerms && joinedTerms.Any(t => Regex.IsMatch(t.Trim(), @"^[A-Za-z_]"))
            && joinedTerms.All(t => Regex.IsMatch(t.Trim(), @"^(?:[A-Za-z_][\w.]*|@?""[^""]*"")$"))
            && !Fragments.IsMatch(expression) && FixedValues(expression.Trim(), file, position, 4) is [var joined])
        {
            Literals.Add(joined);
            _literalDepth.Add((joined, depth));
            return;
        }
        expression = SelectArm(expression);
        var codeOnly = BlankCondition(CSharpLexer.BlankCommentsAndStrings(expression));
        var chars = codeOnly.ToCharArray();
        foreach (var (pattern, make) in SourcePatterns)
            foreach (Match m in pattern.Matches(expression))
            {
                AddSource(make(m));
                // A source isn't followed any further: blank it out of the names to follow.
                for (int k = m.Index; k < m.Index + m.Length && k < chars.Length; k++)
                    if (chars[k] is not ('\r' or '\n')) chars[k] = ' ';
            }
        // e.Args in OnStartup(StartupEventArgs e), args in Main(string[] args): how the app was started. "Open
        // with", a file dropped onto the exe and a shortcut's arguments all arrive here.
        bool startupFile = file.Masked.Contains("StartupEventArgs", StringComparison.Ordinal);
        bool mainFile = file.Masked.Contains("Main", StringComparison.Ordinal);
        if (startupFile || mainFile)
        foreach (Match m in Regex.Matches(codeOnly, @"\b(?<v>[A-Za-z_]\w*)(?:\s*\.\s*(?<p>Args)\b)?"))
        {
            var v = m.Groups["v"].Value;
            if (m.Groups["p"].Success ? !startupFile : !mainFile) continue;
            bool startup = m.Groups["p"].Success && Regex.IsMatch(file.Masked, $@"\bStartupEventArgs\s+{Regex.Escape(v)}\b");
            bool main = !m.Groups["p"].Success && v.Length > 0 && char.IsLower(v[0])
                        && (m.Index == 0 || codeOnly[m.Index - 1] != '.')
                        && Regex.IsMatch(file.Masked, $@"\bstatic\s+(?:async\s+)?(?:void|int|Task(?:<int>)?)\s+Main\s*\(\s*string\s*\[\s*\]\s+{Regex.Escape(v)}\s*\)");
            if (!startup && !main) continue;
            AddSource(new Source(SourceKind.CommandLine, "the command line", Scope.User));
            for (int k = m.Index; k < m.Index + m.Length && k < chars.Length; k++)
                if (chars[k] is not ('\r' or '\n')) chars[k] = ' ';
        }
        // TxtProgram.Text, where the XAML has <TextBox x:Name="TxtProgram">: what the user types, whatever the name.
        if (_code.TypedControls.Count > 0)
            foreach (Match m in Regex.Matches(expression, @"\b(?<n>[A-Za-z_]\w*)\s*\.\s*(?:Text|Password)\b"))
                if (_code.TypedControls.Contains(m.Groups["n"].Value) && chars[m.Index] != ' ')
                {
                    AddSource(new Source(SourceKind.UserTyped, "what the user types", Scope.User));
                    for (int k = m.Index; k < m.Index + m.Length && k < chars.Length; k++)
                        if (chars[k] is not ('\r' or '\n')) chars[k] = ' ';
                }
        // OpenSubKey(path, writable): only the key path names the place; true/false or a permission
        // after it says how, not where. Their names aren't followed.
        foreach (Match call in FlagCalls.Matches(codeOnly))
        {
            int open = call.Index + call.Length, nesting = 0, k = open;
            bool first = true;
            for (; k < chars.Length; k++)
            {
                char c = chars[k];
                if (c is '(' or '[' or '{') nesting++;
                else if (c is ')' or ']' or '}') { if (nesting-- == 0) break; }
                else if (c == ',' && nesting == 0) { first = false; continue; }
                if (!first && c is not ('\r' or '\n')) chars[k] = ' ';
            }
        }
        // new List<(RegistryHive Hive, string Sub, string Label)>(): type arguments name types and tuple fields,
        // never values. Not followed.
        foreach (Match g in NewGeneric.Matches(codeOnly))
        {
            int k = g.Index + g.Length - 1, level = 0;
            for (; k < chars.Length; k++)
            {
                if (chars[k] == '<') level++;
                else if (chars[k] == '>' && --level == 0) break;
                else if (chars[k] is ';' or '{') break;
            }
            for (int j = g.Index + g.Length; j < k && j < chars.Length; j++)
                if (chars[j] is not ('\r' or '\n')) chars[j] = ' ';
        }
        // data.TryGetValue(k, out var v) ? v : "": k picks the entry, it isn't part of what comes out.
        var keyArgs = new List<(int Start, int End)>();
        foreach (Match call in KeyCalls.Matches(codeOnly))
        {
            int open = call.Index + call.Length, nesting = 0, k = open;
            for (; k < chars.Length; k++)
            {
                char c = chars[k];
                if (c is '(' or '[' or '{') nesting++;
                else if (c is ')' or ']' or '}') { if (nesting-- == 0) break; }
                else if (c == ',' && nesting == 0) break;
                if (c is not ('\r' or '\n')) chars[k] = ' ';
            }
            keyArgs.Add((open, k));
        }
        // Directory.EnumerateFiles(dir, "regdiff_*.hive*"): the second argument is a filter on the names found, not a
        // folder. Kept apart and shown as "matching regdiff_*.hive*".
        foreach (Match call in ListingCalls.Matches(codeOnly))
        {
            int open = call.Index + call.Length, nesting = 0, k = open, second = -1;
            for (; k < chars.Length; k++)
            {
                char c = codeOnly[k];
                if (c is '(' or '[' or '{') nesting++;
                else if (c is ')' or ']' or '}') { if (nesting-- == 0) break; }
                else if (c == ',' && nesting == 0) { if (second < 0) second = k + 1; else break; }
            }
            if (second < 0) continue;
            int end = k;
            var filter = string.Concat(CSharpLexer.Literals(expression).Where(l => l.Start >= second && l.Start < end).Select(l => l.Value(expression)));
            if (filter.Length > 0) _globs.Add((filter, depth));
            for (int j = second; j < end && j < chars.Length; j++) if (chars[j] is not ('\r' or '\n')) chars[j] = ' ';
            keyArgs.Add((second, end));
        }
        // Guid.NewGuid().ToString("N"), stamp.ToString("yyyyMMdd"): a format says how a value is written, it isn't text
        // in the result.
        // Environment.GetEnvironmentVariable("DOTNET_ROOT"): the variable's name says where the value comes from (the
        // source says so); it isn't text in the value.
        foreach (Match call in FormatCalls.Matches(codeOnly).Concat(EnvironmentNames.Matches(codeOnly)))
        {
            int open = call.Index + call.Length, nesting = 0, k = open;
            for (; k < chars.Length; k++)
            {
                char c = codeOnly[k];
                if (c is '(' or '[' or '{') nesting++;
                else if (c is ')' or ']' or '}') { if (nesting-- == 0) break; }
                else if (c == ',' && nesting == 0) break;
            }
            keyArgs.Add((open, k));
        }
        // ResolveTempRoot(out _tempRootIsFallback): what comes back through an out argument is the call's by-product,
        // not part of the value.
        foreach (Match o in OutArgumentInCall.Matches(codeOnly))
            for (int k = o.Index; k < o.Index + o.Length && k < chars.Length; k++)
                if (chars[k] is not ('\r' or '\n')) chars[k] = ' ';
        // ?? throw new InvalidOperationException($"Cannot open {p}…"): what's thrown isn't the value.
        var thrown = new List<(int Start, int End)>();
        foreach (Match t in ThrowExpression.Matches(codeOnly))
        {
            int end = t.Index, level = 0;
            for (; end < codeOnly.Length; end++)
            {
                char c = codeOnly[end];
                if (c is '(' or '[' or '{') level++;
                else if (c is ')' or ']' or '}') { if (--level < 0) break; }
                else if (c is ',' or ';' && level == 0) break;
            }
            thrown.Add((t.Index, end));
            for (int k = t.Index; k < end; k++) if (chars[k] is not ('\r' or '\n')) chars[k] = ' ';
        }
        codeOnly = new string(chars);

        if (_code.HasDialogs && Dialog.IsMatch(expression))
            AddSource(new Source(SourceKind.UserPicked, "a file or folder the user picks", Scope.User));
        // e.Data.GetData(DataFormats.FileDrop), e.Data.GetFileDropList(): files dragged onto the window. You
        // choose them as surely as in a dialog.
        foreach (Match drop in FileDrop.Matches(codeOnly))
        {
            AddSource(new Source(SourceKind.UserPicked, "files the user drops onto the window", Scope.User));
            for (int k = drop.Index; k < drop.Index + drop.Length && k < chars.Length; k++)
                if (chars[k] is not ('\r' or '\n')) chars[k] = ' ';
        }
        if (FileDropAny.IsMatch(expression)) codeOnly = new string(chars);

        var literals = CSharpLexer.Literals(expression);
        var conditions = ConditionRanges(codeOnly);
        foreach (var literal in literals)
        {
            if (thrown.Any(t => literal.Start >= t.Start && literal.Start < t.End)) continue;
            // What a condition compares with isn't a value the expression can be.
            if (conditions.Any(t => literal.Start >= t.Start && literal.Start < t.End)) continue;
            if (keyArgs.Any(t => literal.Start >= t.Start && literal.Start < t.End)) continue;
            var text = literal.Value(expression);
            // $@"{RegProfiles}\{profile}" with RegProfiles a constant and profile one of three names: the
            // holes are fixed in the source, so the value is written out, holes filled where they belong.
            if (literal.IsInterpolated && literal.Parts.Any(p => p.IsHole) && Fill(literal, expression, file, position) is var (filled, done) && done.Count > 0)
            {
                text = filled;
                _filled.Add(text);
                var blank = codeOnly.ToCharArray();
                foreach (var hole in done)
                    for (int k = hole.Start; k < hole.Start + hole.Length && k < blank.Length; k++)
                        if (blank[k] is not ('\r' or '\n')) blank[k] = ' ';
                codeOnly = new string(blank);
            }
            Literals.Add(text);
            // Inside { … } of the expression (new[] { "SOFTWARE", "SYSTEM" }, { ("SAM", …) }): one of several
            // choices, not a part of a path.
            if (_choiceMode > 0 || InsideBraces(codeOnly, literal.Start)) _choices.Add(text);
            if (_webHole == 0) _wholeLiterals.Add(text);
            _literalDepth.Add((text, depth));
            if (Regex.IsMatch(text, @"^\\\\[\w.$-]+\\")) AddSource(new Source(SourceKind.NetworkShare, "network share", Scope.WebService));
            else if (Regex.IsMatch(text, @"^[A-Za-z]:\\(?:Windows|Program Files|ProgramData)\b", RegexOptions.IgnoreCase))
                AddSource(new Source(SourceKind.MachineFolder, "a system folder", Scope.Admin));
            else if (Regex.IsMatch(text, @"^[A-Za-z]:\\?$")) AddSource(new Source(SourceKind.MachineFolder, "the drive's root", Scope.Admin));
            else if (Regex.IsMatch(text, @"^[A-Za-z]:\\")) AddSource(new Source(SourceKind.FixedPath, "a fixed path", Scope.User));
        }
        // "ht" + "tp" + "s:" + "//…": short pieces joined into one value. A list of short words isn't that.
        var hiddenHere = new List<string>();
        if (Fragments.IsMatch(expression)) hiddenHere.Add("assembled from short fragments");
        // The C# that hides, not text that mentions it: a PowerShell script in a string that contains
        // [Convert]::FromBase64String isn't C# decoding anything.
        foreach (var (pattern, reason) in OpaquePatterns)
            if (pattern.IsMatch(codeOnly)) hiddenHere.Add(reason);
        foreach (var reason in hiddenHere) AddOpaque(reason);

        // Hidden, but fixed in the source: work the value out. It stays opaque (the author hid it), but the
        // reader gets what it is. As a literal it's found as an address or a name like any other.
        if (hiddenHere.Count > 0 && Fold.Value(expression) is { } value && !Decoded.Any(d => d.Value == value))
        {
            Decoded.Add((value, string.Join(", ", hiddenHere)));
            Literals.Add(value);
            _literalDepth.Add((value, depth));
        }

        // match.Success ? UrlOf(match) : null: the condition picks a value, it isn't one. Only the branches are followed.
        codeOnly = BlankConditions(codeOnly, literals);
        codeOnly = BlankStartSettings(codeOnly);

        // $"https://www.unicode.org/reports/tr{n}/": what fills a hole of a web address with a fixed host is part of
        // the address, not where it goes. Noted, so the address can still count as shown in the source.
        var webHoles = literals.Where(l => l.IsInterpolated && Regex.IsMatch(l.Text(expression), @"(?i)^https?://[^/{}\s]+/"))
            .SelectMany(l => l.Parts.Where(p => p.IsHole)).ToList();
        bool inWebHole = false;
        int skipTo = -1;   // the arguments of a call that returns only web addresses: part of the address

        // Lambda parameters stand for items of a sequence (f => f.Extension == ".cs"): never followed.
        var lambdaNames = new HashSet<string>(StringComparer.Ordinal);
        foreach (Match lm in LambdaParameters.Matches(codeOnly))
            foreach (Capture cap in lm.Groups["p"].Captures)
                lambdaNames.Add(cap.Value);

        // Inside $"{path}.{number}" the braces are blanked with the text: "path   number" isn't a declaration.
        var holes = literals.SelectMany(l => l.Parts.Where(p => p.IsHole)).ToList();
        foreach (Match id in Identifier.Matches(codeOnly))
        {
            if (inWebHole) _webHole--;
            inWebHole = webHoles.Any(hp => id.Index >= hp.Start && id.Index < hp.Start + hp.Length);
            if (inWebHole) _webHole++;
            if (id.Index < skipTo) continue;
            var name = id.Groups["name"].Value;
            bool isCall = id.Groups["call"].Success;
            var dotted = id.Groups["dotted"].Value;
            // Hash(uri.AbsoluteUri), SHA256.HashData(bytes): a name of fixed shape, made from what's hashed. What goes in
            // changes the name, never where it points, so it isn't followed further: the step is shown instead.
            // new Pin { Path = key, Sha256 = Hash(key) }: another member's value, not this one's.
            if (isCall && Regex.IsMatch(codeOnly[..id.Index], @"[,{]\s*[A-Za-z_]\w*\s*=\s*$") && _code.HashReturnedBy(name, file.TypeAt(position)) is not null) continue;
            if (isCall && (Regex.IsMatch(dotted, @"\b(?:SHA(?:1|256|384|512)|MD5)\s*\.\s*$") && name is "HashData" or "ComputeHash"
                           || (dotted.Length == 0 || char.IsUpper(dotted[0])) && _code.HashReturnedBy(name, dotted.Length == 0 ? file.TypeAt(position) : Regex.Matches(dotted, @"[A-Za-z_]\w*").Select(x => x.Value).Last()) is not null))
            {
                int close = CloseOf(codeOnly, id.Index + id.Length - 1);
                var input = expression.Substring(id.Index + id.Length, Math.Max(0, Math.Min(expression.Length, close) - id.Index - id.Length)).Trim();
                var algorithm = name is "HashData" or "ComputeHash" ? (Regex.Match(dotted, @"SHA(?:1|256|384|512)|MD5").Value is var a && a.StartsWith("SHA") ? "SHA-" + a[3..] : "MD5")
                    : _code.HashReturnedBy(name, dotted.Length == 0 ? file.TypeAt(position) : Regex.Matches(dotted, @"[A-Za-z_]\w*").Select(x => x.Value).Last())!;
                // The whole value, or only a part of it: anything else in the expression is another part of the name.
                var rest = (codeOnly[..id.Index] + " " + (close < codeOnly.Length ? codeOnly[(close + 1)..] : "")).Trim();
                bool whole = !Regex.IsMatch(rest, @"[A-Za-z_]\w*") || Regex.IsMatch(rest, @"^(?:return\s*)?$");
                var hashed = new Hashed(algorithm, Regex.IsMatch(input, @"(?i)ur[il]|address") ? "the address" : Clip(input, 40), whole);
                if (!Hashes.Contains(hashed)) Hashes.Add(hashed);
                skipTo = close;
                continue;
            }
            // UrlOf(match), where every UrlOf returns a fixed-host web address or null: those are the values.
            if (isCall && (dotted.Length == 0 || char.IsUpper(dotted[0]))
                && _code.WebAddressesReturnedBy(name, dotted.Length == 0 ? file.TypeAt(position) : Regex.Matches(dotted, @"[A-Za-z_]\w*").Select(x => x.Value).Last()) is { } webs)
            {
                foreach (var w in webs.Distinct())
                {
                    Literals.Add(w);
                    _wholeLiterals.Add(w);
                    _literalDepth.Add((w, depth + 1));
                }
                skipTo = CloseOf(codeOnly, id.Index + id.Length - 1);
                continue;
            }
            if (Keywords.Contains(name) || lambdaNames.Contains(name)) continue;
            // AppContext.BaseDirectory is a source; AppPaths.BaseDirectory (or BaseDirectory inside AppPaths) is the
            // repo's own property of that name, followed like any other, to the source it wraps.
            if (SourceNames.Contains(name) && !OwnMember(name, dotted, isCall, file, position)) continue;
            // p.ExitCode, list.Count, text.Length: a number about the value, never part of a place.
            if (!isCall && dotted.Length > 0 && name is "ExitCode" or "Count" or "Length" or "HasExited" or "LongLength") continue;
            // new ProcessStartInfo { … }: a type being made, not a value to follow. RegistryKey? key = …: the type
            // of a declaration, likewise.
            if (Regex.IsMatch(codeOnly[..id.Index], @"\bnew\s+$")) continue;
            if (!isCall && !holes.Any(h => id.Index >= h.Start && id.Index < h.Start + h.Length) && Regex.IsMatch(codeOnly[(id.Index + id.Length)..], @"^\s*(?:<[^<>()]*>)?\s*(?:\[\s*\])?\s*\??\s+[A-Za-z_]\w*\s*(?:[=;,)]|$)")) continue;
            // WindowsTools.Tool.PowerShell, BindingFlags.Public: a constant or enum member reached through types.
            // Every part capitalised and the first a type: fixed in the source, nothing to follow.
            if (dotted.Length > 0 && !isCall && char.IsUpper(name[0])
                && Regex.Matches(dotted, @"[A-Za-z_]\w*").All(x => char.IsUpper(x.Value[0]))
                && Regex.Match(dotted, @"^[A-Za-z_]\w*").Value is var head && (_code.DeclaresType(head) || !_code.Declared(head))
                && !_code.Declared(name) && _code.Members(name, false).Count == 0) continue;

            // A name being assigned (an object initializer's Verb = "runas") is set here, not read.
            int after = id.Index + id.Length;
            while (after < codeOnly.Length && codeOnly[after] is ' ' or '\t') after++;
            if (!isCall && after < codeOnly.Length && codeOnly[after] == '=' && (after + 1 >= codeOnly.Length || codeOnly[after + 1] is not ('=' or '>'))) continue;

            // SelectedA, bound to a list's selection in the XAML: what the user picks there.
            if (!isCall && dotted.Length == 0 && char.IsUpper(name[0]) && AddListPick(name, file, position, depth)) continue;

            var receiver = dotted.Length == 0 ? "" : Regex.Match(dotted, @"^[A-Za-z_]\w*").Value;
            // System.IO.Path.Combine, Microsoft.Win32.Registry: the base library spelled out in full, never the repo's own.
            if (receiver is "System" or "Microsoft" or "global" && !_code.DeclaresType(receiver)) continue;
            // Security.DnsHistory.Read: a namespace in front of the repo's own type; the type is the receiver.
            if (receiver.Length > 0 && char.IsUpper(receiver[0]) && !_code.DeclaresType(receiver)
                && Regex.Matches(dotted, @"[A-Za-z_]\w*").Select(x => x.Value).LastOrDefault() is { } last && last != receiver && _code.DeclaresType(last))
                receiver = last;
            string? receiverType = null;
            if (receiver.Length > 0)
            {
                if (lambdaNames.Contains(receiver)) continue;
                // targetUri.Host, context.DnsEndPoint: the value comes off the variable, so follow the variable.
                // The member is looked up by name only when the variable's type is the repo's own:
                // Uri.Host is the framework's, not some other class's Host.
                // ctx.ReportFolder on the repo's own type stays a member lookup: following all of ctx would
                // drag in everything the object holds.
                // SelectedA.Path: a capitalised receiver can be the repo's own property, not a class.
                // set.Folder, group.Items: a contextual keyword before a dot is a variable's name, never the keyword.
                // _output.Text: a field named with a leading underscore is a variable too.
                bool variable = (char.IsLower(receiver[0]) || receiver[0] == '_' && receiver.Length > 1)
                                && (!Keywords.Contains(receiver) || ContextualNames.Contains(receiver)) && receiver is not ("this" or "base");
                bool property = char.IsUpper(receiver[0]) && !_code.DeclaresType(receiver) && _code.Declared(receiver) && DeclaresInScope(receiver, file, position)
                    && Regex.Matches(dotted, @"[A-Za-z_]\w*").Count == 1;
                // SelectedB.Path: the item the user picks in a list; what it holds comes from the list.
                if (property && AddListPick(receiver, file, position, depth)) continue;
                if (variable || property)
                {
                    receiverType = _code.TypeOfVariable(receiver, file, position);
                    bool framework = receiverType is not null && !_code.DeclaresType(receiverType);
                    // Follow the variable when the member is the framework's, or when the repo has no member of
                    // that name at all. bundle.DicFile, where the repo declares a DicFile, stays a member.
                    bool repoMember = _code.Members(name, isCall).Count > 0 || !isCall && (_code.Declared(name) || _code.RecordParameters(name).Count > 0);
                    // cb.Tag on a WPF element: whatever the file put there (new CheckBox { Tag = (hive, sub, label) },
                    // item.Tag = path). A slot the framework only carries.
                    if (!isCall && name == "Tag" && (framework || receiverType is null) && TagValues(file, receiverType ?? PatternTypeOf(receiver, file, position)) is { Count: > 0 } tags)
                    {
                        // cb.Tag is ValueTuple<RegistryHive, string, string> t: only the tuples put there are this one.
                        var tagRead = file.Masked[position..Math.Min(position + expression.Length + 120, file.Masked.Length)];
                        if (Regex.IsMatch(tagRead, @"^[^;]*?\bTag\s+is\s+(?:ValueTuple\s*<|\()"))
                            tags = tags.Where(t => t.Value.StartsWith('(')).ToList();
                        foreach (var (tagValue, at) in tags.Take(MaxDefinitions)) Follow(tagValue, file, at, depth + 1);
                        continue;
                    }
                    if (framework || receiverType is null && !repoMember)
                    {
                        if (variable) { if (_seen.Add($"{receiver}@{file.Path}:{position}")) FollowLocal(receiver, file, position, depth); }
                        else Follow(receiver, file, position, depth + 1);
                        continue;
                    }
                    if (property) receiver = "";   // the member lookup below, on the property's type
                }
                // Path.Combine, string.Join, Math.Max: the base library, not the repo's own Combine.
                if (receiver.Length > 0 && char.IsUpper(receiver[0]) && !_code.DeclaresType(receiver)) continue;
                if (receiver is "string" or "int" or "long" or "double" or "char" or "bool" or "decimal" or "byte" or "object") continue;
            }
            if (!isCall && dotted.Length == 0 && char.IsLower(name[0]))
            {
                // A local is the same name only where it's used: "this.path = path" follows the parameter.
                if (_seen.Add($"{name}@{file.Path}:{position}")) FollowLocal(name, file, position, depth);
                continue;
            }
            // Seen per type where the type is known: AppAudit.FolderPath and AppCandidate.FolderPath are two.
            var knownOwner = receiverType ?? (receiver.Length > 0 && char.IsUpper(receiver[0]) ? receiver : null);
            if (!_seen.Add((isCall ? "()" : "") + (knownOwner is null ? "" : knownOwner + ".") + name)) continue;

            var definitions = _code.Members(name, isCall);
            // m.Label where m is an item of a List<(RegistryHive Hive, string Sub, string Label)>: a field of a tuple,
            // never another class's Label. The value is the tuple's, so follow m.
            if (!isCall && receiver.Length > 0 && char.IsLower(receiver[0]) && !Keywords.Contains(receiver)
                && TupleElementInMember(file, position, name))
            {
                if (_seen.Add($"{receiver}@{file.Path}:{position}")) FollowLocal(receiver, file, position, depth);
                continue;
            }
            // i.ToString() where i's type is unknown or the framework's: the text is the value's, not some override
            // elsewhere in the repo. Follow i.
            if (isCall && name is "ToString" && receiver.Length > 0 && char.IsLower(receiver[0]) && !Keywords.Contains(receiver)
                && (receiverType is null || !definitions.Any(d => CodeBase.OwnerOf(d.File, d.Position) == receiverType)))
            {
                if (_seen.Add($"{receiver}@{file.Path}:{position}")) FollowLocal(receiver, file, position, depth);
                continue;
            }
            // setting.Path where the scan can't tell setting's type and several types have a Path: following
            // all of them is a walk through the repo, not a trace. Say what it is and stop.
            if (receiverType is null && receiver.Length > 0 && char.IsLower(receiver[0])
                && definitions.Select(d => d.File.TypeAt(d.Position)).Distinct().Count() > 2)
            {
                AddUnresolved($"{receiver}.{name}, a property set at run time (several types have a {name}; the source doesn't say which this is)", data: true);
                continue;
            }
            // Shipped code is traced through shipped code: a test's same-named member says nothing about the app.
            if (file.Origin != Origin.Tests && definitions.Any(d => d.File.Origin == Origin.Tests))
                definitions = definitions.Where(d => d.File.Origin != Origin.Tests).ToList();
            // ReportDocument.Build: only the Build that ReportDocument declares, when the repo has it.
            var ownerType = receiverType ?? (receiver.Length > 0 && char.IsUpper(receiver[0]) ? receiver : null);
            if (ownerType is not null && definitions.Count > 0)
            {
                var own = definitions.Where(d => CodeBase.OwnerOf(d.File, d.Position) == ownerType).ToList();
                // candidate.FolderPath on a record AppCandidate: only AppCandidate's own; when it has none with
                // a value (a positional parameter), the record's makers below, not another type's FolderPath.
                if (own.Count > 0) definitions = own;
                else if (receiverType is not null && _code.RecordParameters(name).Any(r => r.Type == receiverType)) definitions = [];
                // tier.ToString() on an enum Tier: object's own member, not another type's override. The text
                // comes from the value, so the value is what to follow.
                else if (receiverType is not null && isCall && name is "ToString" or "ToLowerInvariant" or "ToUpperInvariant" or "Trim")
                {
                    if (receiver.Length > 0 && char.IsLower(receiver[0]) && _seen.Add($"{receiver}@{file.Path}:{position}")) FollowLocal(receiver, file, position, depth);
                    continue;
                }
            }
            // PathOf(…) with no receiver is this type's own (or the file's): another class's PathOf is a stranger.
            if (receiver.Length == 0 && dotted.Length == 0 && definitions.Count > 1)
            {
                var here = file.TypeAt(position);
                var own = definitions.Where(d => d.File == file && (here is null || d.File.TypeAt(d.Position) == here)).ToList();
                if (own.Count == 0) own = definitions.Where(d => here is not null && d.File.TypeAt(d.Position) == here).ToList();
                if (own.Count > 0) definitions = own;
            }
            // config.ProxyUrl: a property of a type the app fills from a settings file. The file is where its value
            // lives; assignments elsewhere (a settings window, copying a config) only edit what ends up there.
            if (!isCall && definitions.Count > 0)
            {
                var declaring = definitions.Select(d => d.File.TypeAt(d.Position)).Where(t => t is not null).Distinct().ToList();
                var declaredIn = ownerType ?? (declaring.Count == 1 ? declaring[0] : null);
                if (_code.SettingOf(name, declaredIn) is not null)
                {
                    RunTimeProperty(name, "a property or field set at run time", declaredIn);
                    continue;
                }
            }
            // ctx.TimeStamp = SnapshotFolder.NewName(): set from outside the type, through a variable. Counted
            // only where the variable is declared as the type that owns the property, or where only one type
            // has a property of that name; otherwise it would be any TimeStamp anywhere.
            if (!isCall)
            {
                var owners = definitions.Select(d => d.File.TypeAt(d.Position)).Where(t => t is not null).Distinct().ToList();
                var owner = ownerType ?? (owners.Count == 1 ? owners[0] : null);
                if (owner is not null)
                    foreach (var a in _code.AssignmentsThrough(name))
                    {
                        if (file.Origin != Origin.Tests && a.File.Origin == Origin.Tests) continue;
                        var type = _code.TypeOfVariable(a.Receiver, a.File, a.Position);
                        if (type == owner || type is null && owners.Count == 1 && owners[0] == owner)
                            definitions = [.. definitions, (a.Expression, a.File, a.Position)];
                    }
            }
            // readonly List<string> _tempDirs = new(), filled with _tempDirs.Add(dest) inside its own type: what it
            // holds is what's added to it.
            if (!isCall && definitions.Count > 0 && definitions.All(d => NewCollection.IsMatch(d.Expression))
                && definitions.Select(d => d.File.TypeAt(d.Position)).Distinct().ToList() is [{ } fieldOwner]
                && _code.AddsTo(name).Where(a => (file.Origin == Origin.Tests || a.File.Origin != Origin.Tests)
                                                 // Only the type's own adds: another type's Rows.Add(…) fills another Rows.
                                                 && a.File.TypeAt(a.Position) == fieldOwner
                                                 && !Regex.IsMatch(a.File.Masked[Math.Max(0, a.Position - 2)..a.Position], @"[\w)\]]\.$")).ToList() is { Count: > 0 } adds)
            {
                foreach (var (addFile, addAt, item) in adds.Take(MaxDefinitions)) Follow(item, addFile, addAt, depth + 1);
                if (adds.Count > MaxDefinitions)
                    AddUnresolved($"{name}, filled in {adds.Count} places; the first {MaxDefinitions} are followed", data: true);
                continue;
            }
            // public string Url { get; set; } = string.Empty: a start value. When the code assigns it elsewhere,
            // those assignments are the answer and the start value is a placeholder; when nothing does, it's
            // filled at run time (settings, a setter, binding).
            if (!isCall && definitions.Count > 0 && definitions.Any(d => Trivial.IsMatch(d.Expression)))
            {
                var real = definitions.Where(d => !Trivial.IsMatch(d.Expression)).ToList();
                if (real.Count == 0)
                {
                    RunTimeProperty(name, "a property or field set at run time (it starts empty)", receiverType);
                    continue;
                }
                definitions = real;
            }
            if (definitions.Count > 0)
            {
                // PathOf(Tool.PowerShell): inside PathOf, its parameter is this call's argument, not whatever
                // every other caller passes. Bind them while following the method.
                var callArgs = isCall ? ArgumentsAt(expression, codeOnly, id.Index + id.Length) : null;
                // return null; × 6, then return path;: what it can be comes before what it is when there's nothing.
                var nullsSeen = definitions.Where(d => Trivial.IsMatch(d.Expression)).ToList();
                foreach (var (definition, defFile, defPos) in definitions.OrderBy(d => Trivial.IsMatch(d.Expression) ? 1 : 0).Take(MaxDefinitions))
                {
                    var binding = callArgs is { Count: > 0 } ? Bind(name, defFile, defPos, callArgs, file, position) : null;
                    if (binding is not null) _bindings.Add(binding);
                    try { Follow(definition, defFile, defPos, depth + 1); }
                    finally { if (binding is not null) _bindings.RemoveAt(_bindings.Count - 1); }
                }
                continue;
            }

            // A positional record's property: record Online(string NotOnlineFile) is set where it's made.
            // Info.Path on a SettingInfo: that record's Path, not the first record with a Path.
            List<(string Type, int Index)> records = isCall ? [] : _code.RecordParameters(name);
            if (records.Count > 0)
            {
                var record = records.FirstOrDefault(r => r.Type == ownerType);
                if (record.Type is null) record = records[0];
                int used = 0;
                // new Verdict(…), and target-typed new(…) where a Verdict is returned or assigned.
                // new Content.OnlineFilter(…): the outer class or namespace in front can be long, so look further back.
                var made = _code.Callers(record.Type).Where(c => Regex.IsMatch(c.File.Masked[Math.Max(0, c.Open - record.Type.Length - 80)..c.Open], @"\bnew\s+[\w.]*$|\bnew\s+[\w.]*\s*\($"))
                    .Concat(_code.TargetTypedNews(record.Type))
                    .Where(c => file.Origin == Origin.Tests || c.File.Origin != Origin.Tests).ToList();
                // A table of hundreds (IReadOnlyList<SettingInfo> All = [ new(…), … ]): the first few show what
                // kind of value it is, not which one this is. Say so, so a sample isn't taken for the answer.
                if (made.Count > MaxCallers)
                    AddUnresolved($"{name}, one of {made.Count} values set where a {record.Type} is made; the first {MaxCallers} are followed", data: true);
                foreach (var (callFile, open) in made.Take(MaxCallers))
                {
                    var args = callFile.Arguments(open);
                    var arg = args.FirstOrDefault(a => a.StartsWith(name + ":", StringComparison.Ordinal))
                              ?? (record.Index < args.Count && !IsNamed(args[record.Index]) ? args[record.Index] : null);
                    if (arg is null) continue;
                    used++;
                    Follow(StripNamed(arg), callFile, open, depth + 1);
                }
                if (used == 0) AddUnresolved($"{name}, set where a {record.Type} is made; the scan didn't find where that is");
                continue;
            }

            // Not defined with a value in the repo. A property or field it declares is set at run time
            // (binding, deserialising, a setter elsewhere); anything else is the base library.
            if (!isCall && _code.Declared(name))
                RunTimeProperty(name, "a property or field set at run time (by binding, deserialising or a setter elsewhere)", receiverType);
            // ctx.SaveDirectory.TrimEnd(…): a member the repo doesn't define, on a chain; the value comes off
            // what's before it, so follow that.
            else if (dotted.Length > 0 && Regex.IsMatch(dotted, @"\.\s*[A-Za-z_]\w*\s*\??\.\s*$"))
                Follow(dotted.TrimEnd().TrimEnd('.').TrimEnd('?').TrimEnd(), file, position, depth + 1);
        }
        if (inWebHole) _webHole--;
    }

    /// <summary>
    /// The conditions of the top-level ?: in an expression, blanked: "a.Ok &amp;&amp; b ? x : y" keeps x and y. Nested
    /// ones (inside brackets) are left to the follow that takes them up.
    /// </summary>
    private static int CloseOf(string code, int open)
    {
        int depth = 0;
        for (int i = open; i < code.Length; i++)
        {
            if (code[i] == '(') depth++;
            else if (code[i] == ')' && --depth == 0) return i;
        }
        return code.Length;
    }

    /// <summary>
    /// new ProcessStartInfo(tool) { StandardOutputEncoding = …, WorkingDirectory = … }: how it's started, not what.
    /// Only FileName, Arguments and Verb say what runs; the other settings of the initializer are blanked.
    /// </summary>
    private static string BlankStartSettings(string code)
    {
        var start = Regex.Match(code, @"\bnew\s+(?:System\.Diagnostics\.)?ProcessStartInfo\s*(?:\((?:[^()]|\([^()]*\))*\))?\s*\{");
        if (!start.Success) return code;
        int open = start.Index + start.Length - 1, depth = 0, close = -1;
        for (int i = open; i < code.Length; i++)
        {
            if (code[i] == '{') depth++;
            else if (code[i] == '}' && --depth == 0) { close = i; break; }
        }
        if (close < 0) return code;
        var chars = code.ToCharArray();
        foreach (Match m in Regex.Matches(code[(open + 1)..close], @"(?<n>[A-Za-z_]\w*)\s*=(?!=)(?<v>(?:[^,{}()]|\([^()]*\)|\{[^{}]*\})*)"))
        {
            if (m.Groups["n"].Value is "FileName" or "Arguments" or "Verb") continue;
            for (int k = open + 1 + m.Index; k < open + 1 + m.Index + m.Length; k++) if (chars[k] is not ('\r' or '\n')) chars[k] = ' ';
        }
        return new string(chars);
    }

    private static string BlankConditions(string code, IReadOnlyList<CSharpLexer.Literal> literals)
    {
        var chars = code.ToCharArray();
        foreach (var (start, to, top) in ConditionRanges(code))
        {
            int from = start;
            // Deeper in, only a comparison with a string (ext == ".xml" ? "tasks" : "registry"): a bare flag can stand
            // for where the value comes from, and blanking it would hide that.
            if (!top && !(Regex.IsMatch(code[from..to], "[=!]=") && literals.Any(l => l.Start >= from && l.Start < to))) continue;
            // Read(path, name) is { Exists: true } v ? v.Data : "": v is what Read returns, and the branches use it.
            // The subject stays; only the test is blanked.
            var pattern = Regex.Match(code[from..to], @"^(?<subject>.*?\S)\s+is\s+(?:not\s+)?[^?]*?\b(?<v>[a-z_]\w*)\s*$", RegexOptions.Singleline);
            if (pattern.Success && Regex.IsMatch(code[to..], $@"\b{pattern.Groups["v"].Value}\s*\??\."))
                from += pattern.Groups["subject"].Index + pattern.Groups["subject"].Length;
            for (int k = from; k < to; k++) if (chars[k] is not ('\r' or '\n')) chars[k] = ' ';
        }
        return new string(chars);
    }

    /// <summary>
    /// The conditions of <c>a ? b : c</c>, at any depth: <c>Path.Combine(dir, ext == ".xml" ? "tasks" : "registry")</c>
    /// picks "tasks" or "registry"; ".xml" only decides which. Strings are masked in <paramref name="code"/>.
    /// </summary>
    private static List<(int Start, int End, bool Top)> ConditionRanges(string code)
    {
        var ranges = new List<(int, int, bool)>();
        var segment = new Stack<int>();
        segment.Push(0);
        for (int i = 0; i < code.Length; i++)
        {
            char c = code[i];
            if (c is '(' or '[' or '{') segment.Push(i + 1);
            else if (c is ')' or ']' or '}') { if (segment.Count > 1) segment.Pop(); }
            else if (c is ':' or ';' or ',') { segment.Pop(); segment.Push(i + 1); }
            else if (c == '=' && i + 1 < code.Length && code[i + 1] == '>') { segment.Pop(); segment.Push(i + 2); }
            else if (c == '?' && i + 1 < code.Length && code[i + 1] is not ('.' or '?' or '[') && (i == 0 || code[i - 1] != '?')
                     && !NullableType(code, i) && ColonAtSameDepth(code, i + 1))
            {
                if (segment.Peek() < i) ranges.Add((segment.Peek(), i, segment.Count == 1));
                segment.Pop(); segment.Push(i + 1);
            }
        }
        return ranges;
    }

    // string? Path { get; init; }, List<int>? x = …: the ? of a type, written against it, before the name it declares.
    private static readonly Regex AfterNullableType = new(@"\G\s+[A-Za-z_]\w*\s*(?:[{;=,)\]]|=>)", RegexOptions.Compiled);

    private static bool NullableType(string code, int at) =>
        at > 0 && (char.IsLetterOrDigit(code[at - 1]) || code[at - 1] is '_' or '>' or ']') && AfterNullableType.IsMatch(code, at + 1);

    private static bool ColonAtSameDepth(string code, int from)
    {
        int level = 0;
        for (int k = from; k < code.Length; k++)
        {
            char c = code[k];
            if (c is '(' or '[' or '{') level++;
            else if (c is ')' or ']' or '}') { if (--level < 0) return false; }
            else if (level == 0 && c is ';' or ',') return false;
            else if (level == 0 && c == ':' && !(k + 1 < code.Length && code[k + 1] == ':')) return true;
        }
        return false;
    }

    /// <summary>
    /// The repo declares <paramref name="name"/> on the type in front of it (AppPaths.BaseDirectory), or, with
    /// nothing in front, on the type the code stands in.
    /// </summary>
    private bool OwnMember(string name, string dotted, bool isCall, CodeFile file, int position)
    {
        var owner = dotted.Length == 0 ? file.TypeAt(position) : Regex.Matches(dotted, @"[A-Za-z_]\w*").Select(x => x.Value).LastOrDefault();
        if (owner is null || !char.IsUpper(owner[0]) || !_code.DeclaresType(owner)) return false;
        return _code.Members(name, isCall).Any(d => d.File.TypeAt(d.Position) == owner);
    }

    private readonly List<string> _listPickPlaces = new();
    private readonly List<string> _listItems = new();
    [ThreadStatic] private static int _nested; // a list's items are traced once, not a list inside a list

    /// <summary>
    /// A property bound to a list's selection in the XAML: the value is what the user picks there. Says so,
    /// with where the list is, and follows what fills the list for where its items come from.
    /// </summary>
    private bool AddListPick(string property, CodeFile file, int position, int depth)
    {
        var picks = _code.ListPicksOf(property);
        if (picks.Count == 0) return false;
        // Text, Name, Value: many types have one, and a binding in some window says nothing about this one.
        if (_code.PropertyOwners(property).Count != 1) return false;
        AddSource(new Source(SourceKind.ListPick, property, Scope.User));
        foreach (var pick in picks)
        {
            var place = $"{property} in {pick.File}:{pick.Line}";
            if (!_listPickPlaces.Contains(place)) _listPickPlaces.Add(place);
            // ItemsSource="{Binding Snapshots}": what the list offers, from what's added to it. Traced on its own,
            // so it doesn't spend this trace's steps; only said when it's plain what it is.
            if (pick.ItemsSource is { } items && !items.Contains('.') && _listItems.Count == 0 && !_local && _nested == 0)
                foreach (var (addFile, addAt, item) in _code.AddsTo(items).Take(2))
                {
                    Tracer sub;
                    _nested++;
                    try { sub = Run(_code, item, addFile, addAt); }
                    finally { _nested--; }
                    var where = $"{addFile.Path}:{addFile.LineOf(addAt)}";
                    if (sub.Sources.Any(x => x.Kind == SourceKind.FolderListing))
                        _listItems.Add($"the list offers what's found in a folder while the app runs ({where})");
                    else if (sub.Unresolved.Count == 0 && sub.Sources.Count == 0 && sub.Literals.Any(l => l.Length > 0))
                        _listItems.Add($"the list offers values written in the source ({where})");
                }
        }
        return true;
    }

    /// <summary>A call's arguments into the method it calls, while the trace is inside that method.</summary>
    private sealed record Binding(string Method, string File, int Declaration, Dictionary<string, string> Arguments, CodeFile CallFile, int CallPosition);

    private readonly List<Binding> _bindings = new();

    /// <summary>The arguments of the call whose "(" ends just before <paramref name="open"/>, as written.</summary>
    private static List<string>? ArgumentsAt(string expression, string codeOnly, int open)
    {
        var args = new List<string>();
        int depth = 0, start = open;
        for (int i = open; i < codeOnly.Length; i++)
        {
            char c = codeOnly[i];
            if (c is '(' or '[' or '{') depth++;
            else if (c is ')' or ']' or '}')
            {
                if (depth-- == 0)
                {
                    var last = expression[start..i].Trim();
                    if (last.Length > 0 || args.Count > 0) args.Add(last);
                    return args;
                }
            }
            else if (c == ',' && depth == 0)
            {
                args.Add(expression[start..i].Trim());
                start = i + 1;
            }
        }
        return null;
    }

    /// <summary>The method's parameter names, paired with the call's arguments (named ones by name).</summary>
    private static Binding? Bind(string method, CodeFile file, int declaration, List<string> args, CodeFile callFile, int callPosition)
    {
        // The position is the method's name for an expression body, or a return statement inside a block
        // body: the parameters are those of the nearest header of this method before it.
        int open = -1;
        var masked = file.Masked;
        foreach (Match h in new Regex($@"\b{Regex.Escape(method)}\s*(?:<[^<>;]*>)?\s*\(", RegexOptions.RightToLeft)
                     .Matches(masked[..Math.Min(masked.Length, declaration + method.Length + 1)]))
        {
            int o = h.Index + h.Length - 1, depth = 0, close = -1;
            for (int k = o; k < masked.Length; k++)
            {
                if (masked[k] == '(') depth++;
                else if (masked[k] == ')' && --depth == 0) { close = k; break; }
            }
            if (close < 0) continue;
            if (!Regex.IsMatch(masked[(close + 1)..Math.Min(masked.Length, close + 200)], @"^\s*(?:where\b[^{;]*)?(?:\{|=>)")) continue;
            open = o;
            break;
        }
        if (open < 0) return null;
        var parameters = file.Arguments(open + 1)
            .Select(p => Regex.Match(p, @"([A-Za-z_]\w*)\s*(?:=[^,]*)?$").Groups[1].Value).ToList();
        if (parameters.Count == 0) return null;
        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        for (int i = 0; i < args.Count; i++)
        {
            var named = Regex.Match(args[i], @"^\s*([A-Za-z_]\w*)\s*:(?!:)\s*(.*)$", RegexOptions.Singleline);
            if (named.Success) map[named.Groups[1].Value] = named.Groups[2].Value;
            else if (i < parameters.Count && parameters[i].Length > 0) map[parameters[i]] = args[i];
        }
        return new Binding(method, file.Path, open, map, callFile, callPosition);
    }

    private (string Argument, CodeFile File, int Position)? BoundArgument(string method, CodeFile file, int position, string parameter)
    {
        for (int i = _bindings.Count - 1; i >= 0; i--)
        {
            var b = _bindings[i];
            if (b.Method == method && b.File == file.Path && Math.Abs(b.Declaration - position) < 400 && b.Arguments.TryGetValue(parameter, out var arg))
                return (arg, b.CallFile, b.CallPosition);
        }
        return null;
    }

    private static readonly Regex SwitchOn = new(@"\b(?<v>[A-Za-z_]\w*)\s+switch\s*\{", RegexOptions.Compiled);

    /// <summary>
    /// tool switch { Tool.Gpupdate => "gpupdate.exe", Tool.PowerShell => …, … } with tool bound to
    /// Tool.PowerShell by the call the trace came through: only that arm is the value.
    /// </summary>
    private string SelectArm(string expression)
    {
        if (_bindings.Count == 0 || !expression.Contains("switch", StringComparison.Ordinal)) return expression;
        var code = CSharpLexer.BlankCommentsAndStrings(expression);
        var m = SwitchOn.Match(code);
        if (!m.Success) return expression;
        var b = _bindings[^1];
        if (!b.Arguments.TryGetValue(m.Groups["v"].Value, out var arg)) return expression;
        // PathOf(tool) inside Run(Tool.Schtasks, …): tool is Run's parameter, so its argument is Run's call's.
        for (int k = _bindings.Count - 2; k >= 0 && Regex.IsMatch(arg.Trim(), @"^[A-Za-z_]\w*$"); k--)
            if (_bindings[k].Arguments.TryGetValue(arg.Trim(), out var outer)) arg = outer;
        var member = Regex.Match(arg.Trim(), @"(?:^|\.)(?<m>[A-Za-z_]\w*)\s*$").Groups["m"].Value;
        if (member.Length == 0) return expression;

        int open = m.Index + m.Length - 1, depth = 0, close = -1;
        for (int i = open; i < code.Length; i++)
        {
            if (code[i] is '(' or '[' or '{') depth++;
            else if (code[i] is ')' or ']' or '}' && --depth == 0) { close = i; break; }
        }
        if (close < 0) return expression;

        int start = open + 1, d = 0;
        string? chosen = null, fallback = null;
        for (int i = open + 1; i <= close; i++)
        {
            char c = code[i];
            if (c is '(' or '[' or '{') d++;
            else if (c is ')' or ']' or '}' && i < close) d--;
            if ((c == ',' && d == 0) || i == close)
            {
                var arm = expression[start..i];
                var split = code[start..i].IndexOf("=>", StringComparison.Ordinal);
                if (split > 0)
                {
                    var pattern = code[start..(start + split)].Trim();
                    var value = arm[(split + 2)..].Trim();
                    if (Regex.IsMatch(pattern, @"(?:^|\.)" + Regex.Escape(member) + @"$")) chosen ??= value;
                    else if (pattern == "_") fallback = value;
                }
                start = i + 1;
            }
        }
        var pick = chosen ?? fallback;
        return pick is null ? expression : expression[..m.Index] + "(" + pick + ")" + expression[(close + 1)..];
    }

    /// <summary>
    /// user ? userPath : sitePath: the value is one of the branches; the condition only picks. Its names
    /// are blanked so the trace doesn't wander off through a bool.
    /// </summary>
    private static string BlankCondition(string code)
    {
        int depth = 0;
        for (int i = 0; i < code.Length; i++)
        {
            char c = code[i];
            if (c is '(' or '[' or '{') depth++;
            else if (c is ')' or ']' or '}') depth--;
            else if (c == '?' && depth == 0)
            {
                char next = i + 1 < code.Length ? code[i + 1] : '\0';
                char prev = i > 0 ? code[i - 1] : '\0';
                if (next is '.' or '?' or '[' or '=' || prev == '?') { i++; continue; }
                // A conditional needs its ':' at the same level after it.
                int d = 0, colon = -1;
                for (int k = i + 1; k < code.Length; k++)
                {
                    if (code[k] is '(' or '[' or '{') d++;
                    else if (code[k] is ')' or ']' or '}') d--;
                    else if (code[k] == ':' && d == 0) { colon = k; break; }
                }
                if (colon < 0) return code;
                // Read(path, name) is { Exists: true } v ? v.Data : "": v is what Read returns, used in the branches.
                var pattern = Regex.Match(code[..i], @"^(?<subject>\s*.*?\S)\s+is\s+(?:not\s+)?[^?]*?\b(?<v>[a-z_]\w*)\s*$", RegexOptions.Singleline);
                if (pattern.Success && Regex.IsMatch(code[i..], $@"\b{pattern.Groups["v"].Value}\s*\??\."))
                {
                    int keep = pattern.Groups["subject"].Length;
                    return code[..keep] + new string(' ', i + 1 - keep) + code[(i + 1)..];
                }
                return new string(' ', i + 1) + code[(i + 1)..];
            }
        }
        return code;
    }

    /// <summary>How many arguments a method takes: its parameters, less those with defaults; any number with params.</summary>
    public static (int Fewest, int Most) Arity(CodeFile file, int position)
    {
        // Only where the origin points just inside the parameter list; otherwise every call counts.
        if (position <= 0 || position > file.Masked.Length || file.Masked[position - 1] != '(') return (0, int.MaxValue);
        int open = position;
        // Split the list again with <> counted as brackets: Action<string, int?> is one parameter.
        var parameters = new List<string>();
        foreach (var part in file.Arguments(open))
        {
            if (parameters.Count > 0 && parameters[^1].Count(c => c == '<') > parameters[^1].Count(c => c == '>'))
                parameters[^1] += "," + part;
            else parameters.Add(part);
        }
        if (parameters.Any(p => Regex.IsMatch(p, @"^(?:\[[^\]]*\]\s*)*params\b"))) return (parameters.Count - 1, int.MaxValue);
        int optional = parameters.Count(p => Regex.IsMatch(p, @"[^=!<>]=[^=>]"));
        bool extension = parameters.Count > 0 && parameters[0].StartsWith("this ", StringComparison.Ordinal);
        int count = parameters.Count - (extension ? 1 : 0);
        return (count - optional, extension ? parameters.Count : count);
    }

    /// <summary>The file declares a property or field of that name: "SnapshotItem? SelectedA { get; set; }".</summary>
    /// <summary>
    /// A capitalised name before a dot is the code's own property or field only where it's in scope: declared by the type
    /// the code sits in (or an outer one, or another part of a partial type). Elsewhere Path.Combine is System.IO.Path,
    /// even when some other class has a property named Path.
    /// </summary>
    private bool DeclaresInScope(string name, CodeFile file, int position)
    {
        var declaration = new Regex(@"[\w>\]?]\s+" + Regex.Escape(name) + @"\s*(?:\{\s*(?:get|set|init|private|protected|internal)\b|=>|=(?!=)|;)");
        foreach (Match m in declaration.Matches(file.Masked))
            if (file.TypeAt(m.Index) is { } owner && file.InsideType(owner, position)) return true;
        if (file.TypeAt(position) is not { } here) return false;
        foreach (var other in _code.Files)
        {
            if (other == file || !other.Masked.Contains(name, StringComparison.Ordinal) || !Regex.IsMatch(other.Masked, @"\bpartial\s+(?:class|struct|record)\s+" + Regex.Escape(here) + @"\b")) continue;
            foreach (Match m in declaration.Matches(other.Masked))
                if (other.TypeAt(m.Index) == here) return true;
        }
        return false;
    }

    /// <summary>A lower-case name: a local before its use, a foreach variable, or a parameter with its callers.</summary>
    private static readonly Regex NewCollection = new(
        @"^\s*(?:new\s*(?:[A-Za-z_][\w.]*\s*(?:<.*>)?)?\s*\([^;]*\)\s*(?:\{.*\})?|new\s*[A-Za-z_][\w.]*\s*<.*>\s*\{.*\}|\[\s*\]|Array\s*\.\s*Empty\s*<[^>]*>\s*\(\s*\))\s*$",
        RegexOptions.Compiled | RegexOptions.Singleline);

    /// <summary>The values put into a collection with Add, AddRange, Insert, Push, Enqueue, TryAdd, within one member.</summary>
    private void FollowFills(string name, CodeFile file, int memberStart, int depth)
    {
        int end = MemberEnd(file, memberStart);
        var fill = new Regex($@"(?<![\w.]){Regex.Escape(name)}\s*\.\s*(?<m>Add|AddRange|Insert|InsertRange|Push|Enqueue|TryAdd|Add(?:First|Last)|Append|AppendLine|AppendFormat)\s*\(");
        int used = 0;
        foreach (Match m in fill.Matches(file.Masked[memberStart..end]))
        {
            if (used >= MaxDefinitions) break;
            int open = memberStart + m.Index + m.Length;
            var args = Fold.SplitTop(ArgumentsAt(file, open), ',') ?? [];
            if (args.Count == 0) continue;
            // Insert(index, item), Add(key, value), TryAdd(key, value): the last argument is what goes in.
            var item = (m.Groups["m"].Value is "Add" or "TryAdd" && args.Count == 2) || m.Groups["m"].Value.StartsWith("Insert", StringComparison.Ordinal)
                ? args[^1] : args[0];
            if (item.Trim().Length == 0) continue;
            // args.Append("publish \"").Append(project.Path): a StringBuilder's written text says what it builds;
            // what else is appended (any text the code has at hand) is followed no further.
            if (m.Groups["m"].Value.StartsWith("Append", StringComparison.Ordinal) && !Regex.IsMatch(item.Trim(), @"^(?:""(?:[^""\\]|\\.)*""|@""(?:[^""]|"""")*"")$")) continue;
            int at = file.Text.IndexOf(item.Trim(), open, StringComparison.Ordinal);
            Follow(item.Trim(), file, at < 0 ? open : at, depth + 1);
            used++;
        }
    }

    /// <summary>The member around <paramref name="position"/> declares a tuple type with an element of that name.</summary>
    private static bool TupleElementInMember(CodeFile file, int position, string name)
    {
        int start = file.MemberStart(position), end = MemberEnd(file, start);
        return Regex.IsMatch(file.Masked[start..Math.Min(end, file.Masked.Length)],
            $@"\(\s*(?:[\w.<>\[\]?]+\s+\w+\s*,\s*)*[\w.<>\[\]?]+\s+{Regex.Escape(name)}\s*(?:,[^()]*)?\)\s*(?:>|\[|\?|\s+\w|\))");
    }

    /// <summary>The type a pattern gave the variable: child is CheckBox cb → CheckBox.</summary>
    private static string? PatternTypeOf(string variable, CodeFile file, int position)
    {
        var m = Regex.Match(file.Masked[file.MemberStart(position)..Math.Min(position, file.Masked.Length)],
            $@"\bis\s+(?<t>[A-Za-z_][\w.]*)\s+{Regex.Escape(variable)}\b");
        return m.Success ? m.Groups["t"].Value : null;
    }

    /// <summary>Every value this file puts into a Tag: Tag = … in an initializer or an assignment.</summary>
    private static List<(string Value, int At)> TagValues(CodeFile file, string? elementType)
    {
        var found = new List<(string, int)>();
        foreach (Match m in Regex.Matches(file.Masked, @"(?<![\w.])(?:[A-Za-z_][\w]*\s*\.\s*)?Tag\s*=(?![=>])\s*"))
        {
            // On a CheckBox, only the Tags given to CheckBoxes: new CheckBox { Tag = … }.
            if (elementType is not null)
            {
                var made = CodeBase.InObjectInitializer(file.Masked, m.Index);
                if (made is { Length: > 0 } && made != elementType) continue;
                if (made is null)
                {
                    // item.Tag = …: only when item is declared or made as that element.
                    var owner = Regex.Match(m.Value, @"^(?<v>[A-Za-z_]\w*)\s*\.").Groups["v"].Value;
                    if (owner.Length == 0 || !Regex.IsMatch(file.Masked, $@"(?:\b{Regex.Escape(elementType)}\s+{Regex.Escape(owner)}\b|\b{Regex.Escape(owner)}\s*=\s*new\s+{Regex.Escape(elementType)}\b)")) continue;
                }
                else if (made.Length == 0) continue;
            }
            int from = m.Index + m.Length, level = 0, k = from;
            for (; k < file.Masked.Length; k++)
            {
                char c = file.Masked[k];
                if (c is '(' or '[' or '{') level++;
                else if (c is ')' or ']' or '}') { if (level-- == 0) break; }
                else if (level == 0 && c is ',' or ';') break;
            }
            var value = file.Text[from..k].Trim();
            if (value.Length > 0 && value != "null") found.Add((value, from));
        }
        return found;
    }

    private static string ArgumentsAt(CodeFile file, int open)
    {
        int level = 0, k = open;
        for (; k < file.Masked.Length; k++)
        {
            char c = file.Masked[k];
            if (c is '(' or '[' or '{') level++;
            else if (c is ')' or ']' or '}') { if (level-- == 0) break; }
        }
        return file.Text[open..Math.Min(k, file.Text.Length)];
    }

    /// <summary>Where the member starting at <paramref name="start"/> ends: its closing brace, or the ; of an expression body.</summary>
    private static int MemberEnd(CodeFile file, int start)
    {
        var m = file.Masked;
        int brace = m.IndexOf('{', start), arrow = m.IndexOf("=>", start, StringComparison.Ordinal), semi = m.IndexOf(';', start);
        if (brace < 0 || (arrow >= 0 && arrow < brace && semi >= 0 && semi < brace)) return semi < 0 ? m.Length : semi + 1;
        int level = 0;
        for (int k = brace; k < m.Length; k++)
        {
            if (m[k] == '{') level++;
            else if (m[k] == '}' && --level == 0) return k + 1;
        }
        return m.Length;
    }

    private void FollowLocal(string name, CodeFile file, int position, int depth)
    {
        // Assignments in this member only: a "file = …" in another method is another variable.
        int memberStart = file.MemberStart(position);
        // A local function sees the locals of the method around it: void CompareOne(int i) { … filesA … }.
        int reach = memberStart;
        for (int k = 0; k < 3 && reach > 0; k++)
        {
            var (outer, isType) = file.Member(reach);
            if (isType || outer >= reach) break;
            reach = outer;
        }
        var all = _code.Locals(name, file).Where(l => l.End <= position).ToList();
        var before = all.Where(l => l.Index >= memberStart).ToList();
        if (before.Count == 0 && reach < memberStart) before = all.Where(l => l.Index >= reach).ToList();
        // Only start values ("", null), or an optional parameter's default: the real value comes from
        // the parameter's callers, so look there first and fall back to the start value.
        bool onlyTrivial = before.Count > 0 && before.All(l => Trivial.IsMatch(l.Expression));
        if (onlyTrivial && Parameters.Find(file, position, name) is Parameters.MethodOrigin)
            before.Clear();
        if (before.Count > 0)
        {
            // The nearest assignment; when that's only a start value (null, "", default), the ones
            // before it as well: string? x = null; if (…) x = Find(); Use(x);
            var nearest = before[^1];
            Follow(nearest.Expression, file, nearest.Index, depth + 1);
            // var files = new List<string>(); … files.Add(path); stack.Push(d): what's in a collection is what's
            // put into it, anywhere in the method (a loop can Pop before the line that Pushes).
            if (NewCollection.IsMatch(nearest.Expression)) FollowFills(name, file, file.MemberStart(nearest.Index), depth);
            if (Trivial.IsMatch(nearest.Expression) || before.Count > 1 && Trivial.IsMatch(before[0].Expression))
                foreach (var other in before.Take(before.Count - 1).Where(l => !Trivial.IsMatch(l.Expression)).TakeLast(4))
                    Follow(other.Expression, file, other.Index, depth + 1);
            return;
        }

        // var (filesA, sidecarsA) = FilesOf(…): the value is part of what the right-hand side gives.
        var tuple = new Regex(@"\((?<list>[^()=;]*\b" + Regex.Escape(name) + @"\b[^()=;]*)\)\s*=(?![=>])\s*(?<expr>[^;]+);");
        var nearestTuple = tuple.Matches(file.Masked[reach..Math.Min(position, file.Masked.Length)])
            .LastOrDefault(d => d.Groups["list"].Value.Contains(','));
        if (nearestTuple is { } d)
        {
            var g = d.Groups["expr"];
            Follow(file.Text.Substring(reach + g.Index, g.Length), file, reach + g.Index, depth + 1);
            return;
        }

        var origin = Parameters.Find(file, position, name);
        switch (origin)
        {
            case Parameters.ForeachOrigin f:
                if (f.Element >= 0 && ElementsOf(f.Collection, f.Element) is { } elements)
                {
                    // foreach (var (label, hive, sub) in new[] { ("SOFTWARE", …), ("SYSTEM", …) }): one of them each time.
                    _choiceMode++;
                    foreach (var element in elements.Take(MaxDefinitions)) Follow(element, file, f.Position, depth + 1);
                    _choiceMode--;
                }
                else Follow(f.Collection, file, f.Position, depth + 1);
                return;
            case Parameters.LambdaOrigin when LambdaSources(file, position, name) is { } sources:
                // files.Where(p => …), Parallel.ForEach(files, file => …), s.Table("11", path => …): the call shows
                // what the lambda is handed, so that's followed instead.
                foreach (var (expression, at, atFile) in sources.Take(MaxDefinitions)) Follow(expression, atFile, at, depth + 1);
                return;
            case Parameters.LambdaOrigin:
                AddUnresolved($"lambda parameter {name} ({file.Path}:{file.LineOf(position)}), set by whoever calls the lambda");
                return;
            case Parameters.MethodOrigin m:
                if (_local)
                {
                    ParamHits.Add((file, m.Method, m.Index, m.Position, name));
                    return;
                }
                // Reached through a call the trace came by: the value is that call's argument.
                if (BoundArgument(m.Method, file, m.Position, name) is { } bound)
                {
                    _seen.Remove(name);
                    Follow(StripNamed(bound.Argument), bound.File, bound.Position, depth + 1);
                    return;
                }
                var callers = _code.CallersOf(m.Method, file, m.Position)
                    // Shipped code is traced through shipped callers; what a test passes in says nothing about the app.
                    .Where(c => file.Origin == Origin.Tests || c.File.Origin != Origin.Tests)
                    .Take(MaxCallers)
                    .ToList();
                // Overloads share a name: a call counts only when its arguments fit this one's parameters.
                var (fewest, most) = Arity(file, m.Position);
                int used = 0;
                foreach (var (callFile, open) in callers)
                {
                    var args = callFile.Arguments(open);
                    if (args.Count < fewest || args.Count > most) continue;
                    var arg = args.FirstOrDefault(a => a.StartsWith(name + ":", StringComparison.Ordinal))
                              ?? (m.Index < args.Count && !IsNamed(args[m.Index]) ? args[m.Index] : null);
                    if (arg is null) continue;
                    used++;
                    _seen.Remove(name); // the same name means something else at the caller
                    Follow(StripNamed(arg), callFile, open, depth + 1);
                }
                // Handed on as a delegate: Change(entry, confirm, DictionaryEditor.Pin) and Change calls op(path, …).
                if (used == 0 && !_local && _code.HandedAsDelegate(m.Method, file, m.Position, m.Index) is { Count: > 0 } handed)
                {
                    foreach (var (handFile, at, argument) in handed.Take(MaxDefinitions))
                    {
                        _seen.Remove(name);
                        Follow(StripNamed(argument), handFile, at, depth + 1);
                    }
                    return;
                }
                if (used == 0) AddUnresolved($"parameter {name} of {m.Method}, {_code.UsageOf(m.Method, file, m.Position)}");
                return;
            case Parameters.OutOrigin:
            case null:
            // Where the name was introduced before its use, nearest first: x is { } name, x is Type name
            // (the value is what was tested), or receiver.TryGetValue(key, out var name) (it comes out of the receiver).
            // Up to the end of the statement: in "d.TryGetValue(k, out var u) ? u : null" the name is introduced after
            // the place the expression starts.
            int statementEnd = file.Masked.IndexOf(';', position) is var semi and >= 0 ? semi : position;
            foreach (var at in _code.Before(name, file, statementEnd).Where(at => at >= memberStart).Take(12))
            {
                int from = Math.Max(0, at - 300);
                var lead = file.Masked[from..at];
                var pattern = IsPattern.Match(lead);
                if (pattern.Success)
                {
                    var g = pattern.Groups["subj"];
                    Follow(file.Text.Substring(from + g.Index, g.Length), file, from + pattern.Index, depth + 1);
                    return;
                }
                var outArg = OutArgument.Match(lead);
                if (outArg.Success)
                {
                    var g = outArg.Groups["recv"];
                    Follow(file.Text.Substring(from + g.Index, g.Length), file, from + outArg.Index, depth + 1);
                    return;
                }
            }

                if (origin is Parameters.OutOrigin)
                {
                    AddUnresolved($"{name}, set by an out argument", data: true);
                    return;
                }
                goto default;
            default:
                // cb.Tag is ValueTuple<RegistryHive, string, string> t: t is what the pattern tested.
                {
                    int from = file.MemberStart(position);
                    var pattern = new Regex($@"(?<subject>[A-Za-z_][\w.]*(?:\([^()]*\))?)\s+is\s+(?:not\s+)?[A-Za-z_][\w.]*(?:\s*<[^;{{}}]*?>)?\??\s+{Regex.Escape(name)}\b");
                    var hit = pattern.Matches(file.Masked[from..Math.Min(position, file.Masked.Length)]).LastOrDefault();
                    if (hit is not null)
                    {
                        var subject = hit.Groups["subject"];
                        Follow(file.Text.Substring(from + subject.Index, subject.Length), file, from + subject.Index, depth + 1);
                        return;
                    }
                }
                // A field used without this., in the type around the use.
                var type = file.TypeAt(position);
                var fields = _code.Members(name, isCall: false).Where(d => d.File.TypeAt(d.Position) == type).ToList();
                if (fields.Count > 0)
                {
                    foreach (var (definition, defFile, defPos) in fields.Take(MaxDefinitions))
                        Follow(definition, defFile, defPos, depth + 1);
                    return;
                }
                if (_code.Declared(name))
                    RunTimeProperty(name, "a property or field set at run time (by binding, deserialising or a setter elsewhere)");
                else
                    AddUnresolved($"{name}, which the scan can't place");
                return;
        }
    }

    /// <summary>Interpolated values whose holes were filled from the source; shown even with spaces in them.</summary>
    private readonly HashSet<string> _filled = new(StringComparer.Ordinal);
    private readonly HashSet<string> _choices = new(StringComparer.Ordinal);

    /// <summary>Texts met as one of several items (a list, an array, the rows of a foreach), not as parts of one value.</summary>
    public IReadOnlySet<string> Choices => _choices;
    // Search patterns, with how deep in the trace the listing was met.
    private readonly List<(string Glob, int Depth)> _globs = [];
    private int _choiceMode;

    private static bool InsideBraces(string code, int index)
    {
        int level = 0;
        for (int k = Math.Min(index, code.Length) - 1; k >= 0; k--)
        {
            if (code[k] == '}') level++;
            else if (code[k] == '{') { if (level == 0) return true; level--; }
        }
        return false;
    }

    private const int MaxChoices = 6;

    /// <summary>
    /// An interpolated literal with the holes the source fixes filled in: constants, a local set once to a
    /// literal, a foreach over a list of literals, the argument of the call the trace came through. One
    /// hole with several values is written as the first and the others: "…\DomainProfile (or
    /// PrivateProfile, PublicProfile)". Returns the text and the holes filled; holes it can't fill stay {}.
    /// </summary>
    private (string Text, List<CSharpLexer.Part> Done) Fill(CSharpLexer.Literal literal, string expression, CodeFile file, int position)
    {
        var values = new List<List<string>?>();
        foreach (var part in literal.Parts)
        {
            if (!part.IsHole) { values.Add(null); continue; }
            var hole = expression.Substring(part.Start, part.Length);
            if (Fold.SplitTop(hole, ',') is { Count: > 0 } split) hole = split[0];   // {x,10}: the alignment isn't the value
            var v = FixedValues(hole, file, position, 4);
            values.Add(v is { Count: > 0 and <= MaxChoices } ? v : null);
        }
        // More than one hole with several values: a table of combinations, not a name. Fill only the single ones.
        int multi = values.Count(v => v is { Count: > 1 });
        var done = new List<CSharpLexer.Part>();
        int choice = -1;
        for (int i = 0; i < literal.Parts.Count; i++)
        {
            var v = values[i];
            if (!literal.Parts[i].IsHole || v is null || v.Count > 1 && multi > 1) continue;
            done.Add(literal.Parts[i]);
            if (v.Count > 1) choice = i;
        }

        // The text with the choosing hole set to one of its values; where that value sits in it.
        (string Text, int Start, int End) Compose(string? pick)
        {
            var sb = new System.Text.StringBuilder();
            int from = 0, to = 0;
            for (int i = 0; i < literal.Parts.Count; i++)
            {
                var part = literal.Parts[i];
                var v = values[i];
                if (!part.IsHole) sb.Append(expression, part.Start, part.Length);
                else if (!done.Contains(part)) sb.Append("{}");
                else if (i == choice) { from = sb.Length; sb.Append(pick); to = sb.Length; }
                else sb.Append(v![0]);
            }
            return (sb.ToString(), from, to);
        }

        if (choice < 0) return (Compose(null).Text, done);
        // The others as the whole piece they make: "DomainProfile (or PrivateProfile, PublicProfile)",
        // "logging droppedconnections (or allowedconnections) enable".
        var (text, start, end) = Compose(values[choice]![0]);
        const string Separators = @"\/ .-:";
        int segStart = start, segEnd = end;
        while (segStart > 0 && !Separators.Contains(text[segStart - 1])) segStart--;
        while (segEnd < text.Length && !Separators.Contains(text[segEnd])) segEnd++;
        var others = values[choice]!.Skip(1).Select(o =>
        {
            var (alt, _, altEnd) = Compose(o);
            return alt[segStart..(altEnd + segEnd - end)];
        });
        text = text[..segEnd] + " (or " + string.Join(", ", others) + ")" + text[segEnd..];
        return (text, done);
    }

    /// <summary>The values a short expression is fixed to in the source, or null when the source doesn't fix it.</summary>
    private List<string>? FixedValues(string expression, CodeFile file, int position, int budget)
    {
        expression = expression.Trim();
        if (budget <= 0 || expression.Length == 0) return null;
        if (Fold.Value(expression) is { } folded) return [folded];
        // ExclusionsKey + @"\Paths": each piece fixed, so the whole is.
        if (Fold.SplitTop(expression, '+') is { Count: > 1 } terms)
        {
            var sb = new System.Text.StringBuilder();
            foreach (var term in terms)
                if (FixedValues(term, file, position, budget - 1) is [var one]) sb.Append(one); else return null;
            return [sb.ToString()];
        }
        if (Regex.IsMatch(expression, @"^@?""[^""]*""$")) return [expression.TrimStart('@')[1..^1]];   // "" and the like
        // p.Key with p an item of a list the source writes out: that element of each item.
        var element = Regex.Match(expression, @"^(?<v>[a-z_]\w*)\s*\.\s*(?<m>[A-Za-z_]\w*)$");
        if (element.Success && !Keywords.Contains(element.Groups["v"].Value))
            return ItemValues(element.Groups["v"].Value, element.Groups["m"].Value, file, position, budget);
        var id = Regex.Match(expression, @"^(?:(?<owner>[A-Z]\w*)\s*\.\s*)?(?<name>[A-Za-z_]\w*)$");
        if (!id.Success) return null;
        var name = id.Groups["name"].Value;
        if (Keywords.Contains(name)) return null;

        if (!id.Groups["owner"].Success && char.IsLower(name[0]))
        {
            int memberStart = file.MemberStart(position);
            var locals = _code.Locals(name, file).Where(l => l.End <= position && l.Index >= memberStart).ToList();
            if (locals.Count > 1) return null;
            // number++, count += 2, Next(ref number): changed in place, so not the value it starts with.
            var body = file.Masked[memberStart..Math.Min(file.Masked.Length, position + 1500)];
            var n = Regex.Escape(name);
            if (Regex.IsMatch(body, $@"(?<![\w.]){n}\s*(?:\+\+|--|[+\-*/%&|^]=|\?\?=)|(?:\+\+|--)\s*{n}\b|\b(?:ref|out)\s+{n}\b")) return null;
            if (locals.Count == 1) return FixedValues(locals[0].Expression, file, locals[0].Index, budget - 1);
            switch (Parameters.Find(file, position, name))
            {
                case Parameters.ForeachOrigin f:
                {
                    var (items, itemsFile, itemsAt) = CollectionItems(f.Collection, f.Element, file, f.Position);
                    if (items is null || items.Count > MaxChoices) return null;
                    var all = new List<string>();
                    foreach (var item in items)
                        if (FixedValues(item, itemsFile, itemsAt, budget - 1) is [var one]) all.Add(one); else return null;
                    return all;
                }
                case Parameters.LambdaOrigin:
                    return ItemValues(name, null, file, position, budget);
                case Parameters.MethodOrigin m when BoundArgument(m.Method, file, m.Position, name) is { } bound:
                    return FixedValues(StripNamed(bound.Argument), bound.File, bound.Position, budget - 1);
                case Parameters.MethodOrigin m:
                {
                    // Read(PolicyRoot, policy, value) called from a few places, each with a value the source fixes.
                    var callers = _code.CallersOf(m.Method, file, m.Position)
                        .Where(c => file.Origin == Origin.Tests || c.File.Origin != Origin.Tests).ToList();
                    if (callers.Count is 0 or > MaxChoices) return null;
                    var (fewest, most) = Arity(file, m.Position);
                    var all = new List<string>();
                    foreach (var (callFile, open) in callers)
                    {
                        var args = callFile.Arguments(open);
                        if (args.Count < fewest || args.Count > most) continue;
                        var arg = args.FirstOrDefault(a => a.StartsWith(name + ":", StringComparison.Ordinal))
                                  ?? (m.Index < args.Count && !IsNamed(args[m.Index]) ? args[m.Index] : null);
                        if (arg is null || FixedValues(StripNamed(arg), callFile, open, budget - 1) is not { } some) return null;
                        all.AddRange(some.Where(v => !all.Contains(v)));
                        if (all.Count > MaxChoices) return null;
                    }
                    return all.Count > 0 ? all : null;
                }
                default:
                    if (!_code.Declared(name)) return null;
                    break;   // a field without this.: below
            }
        }

        return FixedDefinition(expression, file, position) is var (definition, defFile, defPos, _)
            ? FixedValues(definition, defFile, defPos, budget - 1)
            : null;
    }

    /// <summary>
    /// What a constant, a readonly field or a get-only property (Name or Type.Name) is set to, when it's
    /// set once: its one definition and where that is.
    /// </summary>
    private (string Definition, CodeFile File, int Position, string Head)? FixedDefinition(string expression, CodeFile file, int position)
    {
        var id = Regex.Match(expression.Trim(), @"^(?:(?<owner>[A-Z]\w*)\s*\.\s*)?(?<name>[A-Za-z_]\w*)$");
        if (!id.Success) return null;
        var name = id.Groups["name"].Value;
        var definitions = _code.Members(name, isCall: false);
        var owner = id.Groups["owner"].Success ? id.Groups["owner"].Value : file.TypeAt(position);
        var own = definitions.Where(d => d.File.TypeAt(d.Position) == owner).ToList();
        if (own.Count == 0 && !id.Groups["owner"].Success) own = definitions;
        if (own.Count != 1) return null;
        var (definition, defFile, defPos) = own[0];
        int lineStart = defFile.Masked.LastIndexOf('\n', Math.Max(0, defPos - 1)) + 1;
        var head = defFile.Masked[lineStart..defPos];
        bool fixedOnce = Regex.IsMatch(head, @"\b(?:const|readonly)\b")
                         || Regex.IsMatch(defFile.Masked[(defPos + name.Length)..Math.Min(defFile.Masked.Length, defPos + name.Length + 8)], @"^\s*=>");
        if (!fixedOnce || _code.AssignmentsThrough(name).Count > 0) return null;
        return (definition, defFile, defPos, head);
    }

    /// <summary>LINQ and list methods whose lambda's first parameter is an element of what they're called on.</summary>
    private static readonly HashSet<string> ElementLambdas = new(StringComparer.Ordinal)
    {
        "Where", "Select", "SelectMany", "Any", "All", "Count", "LongCount", "First", "FirstOrDefault", "Last", "LastOrDefault",
        "Single", "SingleOrDefault", "OrderBy", "OrderByDescending", "ThenBy", "ThenByDescending", "GroupBy", "ToDictionary",
        "ToLookup", "Sum", "Min", "Max", "Average", "MinBy", "MaxBy", "DistinctBy", "ForEach", "TakeWhile", "SkipWhile",
        "Exists", "Find", "FindAll", "FindIndex", "FindLast", "TrueForAll", "RemoveAll", "ConvertAll", "CountBy", "AggregateBy"
    };

    /// <summary>
    /// What a lambda's parameter is handed, from the call the lambda is an argument of: the collection for LINQ,
    /// List.ForEach and Parallel.ForEach; the key for GetOrAdd and AddOrUpdate; and for the app's own method, what
    /// that method passes when it calls the delegate. Empty when the call doesn't show it.
    /// </summary>
    private List<(string Expression, int Position, CodeFile File)>? LambdaSources(CodeFile file, int position, string name)
    {
        var result = new List<(string, int, CodeFile)>();
        if (Parameters.LambdaCall(file, position, name) is not { } site) return null;
        // Array(p, "u") inside Array(root, "packages").Select(p => …): each lambda's call is followed once per trace.
        if (!_lambdasFollowed.Add((file.Path, site.CallOpen, site.ParamIndex))) return result;
        var args = file.Arguments(site.CallOpen + 1);
        if (site.Method is "ForEach" or "ForEachAsync" && site.Receiver is "Parallel" or "System.Threading.Tasks.Parallel"
            && site.ParamIndex == 0 && site.ArgIndex > 0 && args.Count > 0)
        {
            if (ElementsBase(args[0]) is { } items) result.Add((items, site.CallOpen + 1, file));
            return result.Count > 0 ? result : null;
        }
        if (site.Receiver is { } receiver && site.Receiver is not ("Parallel" or "System.Threading.Tasks.Parallel")
            && ElementLambdas.Contains(site.Method) && site.ParamIndex == 0
            && !(site.Method is "Select" or "Where" or "SelectMany" && site.ArgIndex > 0))
        {
            // targets.Where(…).Where(p => …): the elements are targets' own; a Select in between makes new ones.
            if (ElementsBase(receiver) is { } source) result.Add((source, site.ReceiverPosition, file));
            return result.Count > 0 ? result : null;
        }
        if (site.Method is "GetOrAdd" or "AddOrUpdate" && site.Receiver is not null && site.ParamIndex == 0 && site.ArgIndex > 0 && args.Count > 0)
        {
            result.Add((args[0], site.CallOpen + 1, file));
            return result.Count > 0 ? result : null;
        }
        // Into another method only on a full trace: a local one stays within its method.
        if (!_local && (site.Receiver is null || !ElementLambdas.Contains(site.Method)))
            foreach (var (f, at, argument) in _code.DelegateCalls(site.Method, site.ArgIndex, site.ParamIndex))
                result.Add((argument, at, f));
        return result.Count > 0 ? result : null;
    }

    /// <summary>LINQ calls that hand on the same elements they're given: filters, orders, slices, copies.</summary>
    private static readonly HashSet<string> KeepElements = new(StringComparer.Ordinal)
    {
        "Where", "OrderBy", "OrderByDescending", "ThenBy", "ThenByDescending", "Order", "OrderDescending", "Take", "Skip",
        "TakeWhile", "SkipWhile", "TakeLast", "SkipLast", "Distinct", "DistinctBy", "Reverse", "ToList", "ToArray",
        "ToHashSet", "Cast", "OfType", "AsEnumerable", "AsParallel", "AsOrdered", "AsReadOnly", "WithDegreeOfParallelism", "WithCancellation", "ConfigureAwait"
    };

    /// <summary>
    /// The collection whose elements a chain hands on: targets for targets.Where(…).ToList(); null when a call in
    /// the chain makes new elements (Select, Zip, GroupBy …).
    /// </summary>
    private static string? ElementsBase(string expression)
    {
        var e = expression.Trim();
        for (int guard = 0; guard < 12; guard++)
        {
            var masked = CSharpLexing.CSharpLexer.BlankCommentsAndStrings(e);
            if (!masked.EndsWith(')')) return e;
            int open = -1, depth = 0;
            for (int i = masked.Length - 1; i >= 0; i--)
            {
                if (masked[i] == ')') depth++;
                else if (masked[i] == '(' && --depth == 0) { open = i; break; }
            }
            if (open < 0) return null;
            var call = Regex.Match(masked[..open], @"\.\s*(?<m>[A-Za-z_]\w*)\s*(?:<[^<>()]*>)?\s*$");
            if (!call.Success) return e;
            var name = call.Groups["m"].Value;
            if (name is "Select" or "SelectMany" or "Zip" or "GroupBy" or "Join" or "GroupJoin" or "Chunk" or "Index"
                or "Aggregate" or "ToDictionary" or "ToLookup" or "Keys" or "Values") return null;
            // Anything else ends the chain: Directory.GetFiles(dir) is itself the collection.
            if (!KeepElements.Contains(name)) return e;
            e = e[..call.Index].TrimEnd();
            if (e.EndsWith('?')) e = e[..^1];
        }
        return null;
    }

    private static readonly Regex OutArgumentInCall = new(@"(?<=[(,]\s*)out\s+(?:var\s+|[\w<>\[\]?.]+\s+)?_?[A-Za-z_]\w*(?=\s*[,)])", RegexOptions.Compiled);
    private static readonly Regex FormatCalls = new(@"\.\s*ToString\s*\(", RegexOptions.Compiled);
    private static readonly Regex EnvironmentNames = new(@"\bEnvironment\s*\.\s*(?:GetEnvironmentVariable|ExpandEnvironmentVariables)\s*\(", RegexOptions.Compiled);

    private static readonly Regex LambdaOver = new(
        @"(?<coll>[A-Za-z_][\w.]*)\s*\.\s*(?:All|Any|Select|SelectMany|Where|ForEach|Count|First|FirstOrDefault|Last|LastOrDefault|Single|Sum|Max|Min|OrderBy|ToDictionary|ToList)\s*\(\s*\(?\s*(?<p>[A-Za-z_]\w*)\s*\)?\s*=>",
        RegexOptions.Compiled | RegexOptions.RightToLeft);

    /// <summary>
    /// The values of a foreach variable or a lambda parameter (or one element of it: p.Key) when it goes
    /// over a list the source writes out: ProfileKeys.All(p => …) with ProfileKeys = { "DomainProfile", … }.
    /// </summary>
    private List<string>? ItemValues(string variable, string? member, CodeFile file, int position, int budget)
    {
        string? collection = null;
        int at = position, index = -1;
        switch (Parameters.Find(file, position, variable))
        {
            case Parameters.ForeachOrigin f:
                collection = f.Collection; at = f.Position; index = f.Element;
                break;
            case Parameters.LambdaOrigin:
                int from = Math.Max(0, position - 1500);
                var lead = file.Masked[from..Math.Min(position, file.Masked.Length)];
                var m = LambdaOver.Matches(lead).FirstOrDefault(x => x.Groups["p"].Value == variable);
                if (m is null) return null;
                collection = file.Text.Substring(from + m.Groups["coll"].Index, m.Groups["coll"].Length);
                at = from + m.Index;
                break;
        }
        if (collection is null) return null;
        if (member is not null)
        {
            if (index >= 0) return null;
            index = ElementIndex(collection, member, file, at);
            if (index < 0) return null;
        }
        var (items, itemsFile, itemsAt) = CollectionItems(collection, index, file, at);
        if (items is null || items.Count > MaxChoices) return null;
        var all = new List<string>();
        foreach (var item in items)
            if (FixedValues(item, itemsFile, itemsAt, budget - 1) is [var one]) { if (!all.Contains(one)) all.Add(one); }
            else return null;
        return all;
    }

    /// <summary>Which element Key is in a list of tuples: from (string Label, string Key)[] or from (Label: …, Key: …).</summary>
    private int ElementIndex(string collection, string member, CodeFile file, int position)
    {
        string? items = collection;
        if (FixedDefinition(collection, file, position) is var (definition, _, _, head))
        {
            var type = Regex.Match(head, @"\((?<types>[^()]*)\)\s*\[\s*\]\s*$");
            if (type.Success)
            {
                var names = type.Groups["types"].Value.Split(',').Select(t => Regex.Match(t.Trim(), @"(\w+)$").Value).ToList();
                return names.IndexOf(member);
            }
            items = definition;
        }
        var first = Regex.Match(items, @"\((?<first>[^()]*)\)");
        if (!first.Success || Fold.SplitTop(first.Groups["first"].Value, ',') is not { } parts) return -1;
        return parts.FindIndex(p => Regex.IsMatch(p, $@"^\s*{Regex.Escape(member)}\s*:(?!:)"));
    }

    /// <summary>The items a foreach goes over, when the source writes them out (here or in a fixed field).</summary>
    private (List<string>? Items, CodeFile File, int Position) CollectionItems(string collection, int element, CodeFile file, int position)
    {
        var items = element >= 0 ? ElementsOf(collection, element) : ItemsOf(collection);
        if (items is not null) return (items, file, position);
        if (FixedDefinition(collection, file, position) is var (definition, defFile, defPos, _))
            return (element >= 0 ? ElementsOf(definition, element) : ItemsOf(definition), defFile, defPos);
        return (null, file, position);
    }

    /// <summary>The items of a list written out in the source: new[] { "a", "b" }, ["a", "b"]; null otherwise.</summary>
    private static List<string>? ItemsOf(string collection)
    {
        var m = ArrayLiteral.Match(collection.Trim());
        if (!m.Success || Fold.SplitTop(m.Groups["items"].Value, ',') is not { } items) return null;
        var result = items.Select(i => i.Trim()).Where(i => i.Length > 0).ToList();
        return result.Count > 0 ? result : null;
    }

    private static readonly Regex ThrowExpression = new(@"\bthrow\b(?!\s*;)", RegexOptions.Compiled);

    private static readonly Regex ArrayLiteral = new(@"^(?:new\s*(?:[\w<>(),\s]+?)?\[\s*\]\s*)?(?:\{(?<items>.*)\}|\[(?<items>.*)\])$", RegexOptions.Compiled | RegexOptions.Singleline);

    /// <summary>new[] { ("Domain", "DomainProfile"), … } with element 1: "DomainProfile", …; null when it isn't such a list.</summary>
    private static List<string>? ElementsOf(string collection, int element)
    {
        var m = ArrayLiteral.Match(collection.Trim());
        if (!m.Success || Fold.SplitTop(m.Groups["items"].Value, ',') is not { } items) return null;
        var result = new List<string>();
        foreach (var item in items.Select(i => i.Trim()).Where(i => i.Length > 0))
        {
            if (!(item.StartsWith('(') && item.EndsWith(')')) || Fold.SplitTop(item[1..^1], ',') is not { } parts || element >= parts.Count) return null;
            var part = parts[element].Trim();
            // (Label: "Domain", Key: "DomainProfile"): the value, not the name.
            result.Add(Regex.Replace(part, @"^[A-Za-z_]\w*\s*:(?!:)\s*", ""));
        }
        return result.Count > 0 ? result : null;
    }

    private void AddSource(Source source)
    {
        if (_webHole > 0) _inWebHoles.Add(source.Label);
        else _inWebHoles.Remove(source.Label);
        if (Sources.Contains(source)) return;
        Sources.Add(source);
        _sourceDepth[source] = _depth;
    }

    /// <summary>
    /// The places at the root of the value: the location sources found first, at the shallowest
    /// depth. A trace that wanders into how a file name is configured shouldn't move the folder.
    /// </summary>
    private List<Source> RootSources()
    {
        var places = Sources.Where(s => !s.Open).ToList();
        if (places.Count == 0) return places;
        int min = places.Min(s => _sourceDepth[s]);
        return places.Where(s => _sourceDepth[s] <= min + 1).ToList();
    }

    /// <summary>
    /// A value the trace can't take further. Run-time data (a property set by binding or loading,
    /// an out argument, a large table) is an answer: the value comes from data. Anything else is a
    /// dead end: no caller, a delegate, a lambda, a name the scan can't place.
    /// </summary>
    private void AddUnresolved(string what, bool data = false)
    {
        if (_webHole > 0) _inWebHoles.Add(what);
        else _inWebHoles.Remove(what);
        if (Unresolved.Contains(what)) return;
        Unresolved.Add(what);
        _unresolvedDepth[what] = _depth;
        if (data) _data.Add(what);
    }

    private readonly HashSet<string> _data = new(StringComparer.Ordinal);

    // Inside a hole of a web address with a fixed host: what's met there is part of the address.
    private int _webHole;
    private readonly HashSet<string> _inWebHoles = new(StringComparer.Ordinal);
    private readonly HashSet<string> _wholeLiterals = new(StringComparer.Ordinal);

    /// <summary>Values left open that decide the whole value, not only a part of a web address.</summary>
    public IEnumerable<string> OpenOutsideWebAddresses => Unresolved.Where(u => !_inWebHoles.Contains(u));
    /// <summary>Sources that decide the whole value, not only a part of a web address.</summary>
    public IEnumerable<Source> SourcesOutsideWebAddresses => Sources.Where(x => !_inWebHoles.Contains(x.Label));
    /// <summary>Literals met outside the holes of web addresses: the values the whole can be.</summary>
    public IEnumerable<string> LiteralsOutsideWebAddresses => Literals.Where(_wholeLiterals.Contains);

    private void AddOpaque(string reason)
    {
        if (!OpaqueReasons.Contains(reason)) OpaqueReasons.Add(reason);
    }

    // ---- results ---------------------------------------------------------------------------------

    /// <summary>
    /// How readable the traced value is. Opaque: the code hides it. Untraced: the trace didn't reach
    /// where the value comes from, or the trace ran out of steps; the reasons say where it ended.
    /// Run time (PartlyClear): the place is found, a part of it is decided when the app runs, and the
    /// reasons say by what. Clear: the source shows it, however many steps that takes.
    /// </summary>
    public (Legibility Legibility, List<string> Reasons) Judge()
    {
        var reasons = new List<string>();
        if (OpaqueReasons.Count > 0)
        {
            reasons.AddRange(OpaqueReasons.Select(r => "The value is " + r + "."));
            reasons.InsertRange(0, Decoded.Select(d => $"Hidden on purpose ({d.How}); worked out from the source: {Clip(d.Value, 160)}"));
            return (Legibility.Opaque, reasons);
        }

        var root = RootSources();
        int rootDepth = root.Count > 0 ? root.Min(s => _sourceDepth[s]) : int.MaxValue;

        if (!Determined)
        {
            foreach (var u in Unresolved.Take(3)) reasons.Add("Ends at " + u + ".");
            if (Unresolved.Count > 3) reasons.Add($"Ends at {Unresolved.Count - 3} more values set at run time.");
            if (StoppedAt is { } at)
                reasons.Add((DepthExceeded ? $"Stopped {MaxDepth} steps deep" : $"Stopped after {MaxHops} steps in all")
                            + $" at {at.File}:{at.Line}: {at.Code}");
            if (reasons.Count == 0) reasons.Add("The source doesn't show where this comes from.");
            return (Legibility.Untraced, reasons);
        }

        // Once the place is found, what lies deeper is how the name is made up; only say how long that is.
        // A setting is never just how the name is made up: it can name another file, or another folder altogether
        // (AppPaths.Resolve(bundle.AffFile) under the exe folder, unless the setting is a full path).
        var open = Unresolved.Where(u => rootDepth == int.MaxValue || _unresolvedDepth[u] <= rootDepth + 1
                                         || u.Contains(", a setting in ", StringComparison.Ordinal)).ToList();

        if (_listPickPlaces.Count > 0)
            reasons.Add("Comes from what the user picks in a list in the window: " + string.Join(", ", _listPickPlaces.Take(4))
                        + (_listItems.Count > 0 ? "; " + string.Join("; ", _listItems.Distinct().Take(2)) : "") + ".");
        foreach (var s in Sources.Where(s => s.Open)) reasons.Add("Comes from " + s.Label + ".");
        foreach (var u in open.Take(4)) reasons.Add("Depends on " + u + ".");
        if (open.Count > 4) reasons.Add($"Depends on {open.Count - 4} more values set at run time.");

        // The place is found but the rest of the name lies beyond the steps the scan follows: that's the
        // scan's limit, not something set at run time.
        // When what decides it at run time is already known (settings, input, a file the user picks), that's
        // the answer and the stop is a note; with nothing known, the stop is where the trace ended.
        if ((DepthExceeded || Stopped) && StoppedAt is { } stop)
        {
            bool known = reasons.Count > 0 || UserPicked;
            if (UserPicked && reasons.Count == 0) reasons.Add("Comes from " + PickedLabel + ".");
            reasons.Add((DepthExceeded ? $"Stopped {MaxDepth} steps deep" : $"Stopped after {MaxHops} steps in all")
                        + $" at {stop.File}:{stop.Line}: {stop.Code}. The place is found; the rest of the name lies further on.");
            return (known ? Legibility.PartlyClear : Legibility.Untraced, reasons);
        }
        if (reasons.Count > 0) return (Legibility.PartlyClear, reasons);
        // Fully followed: clear, however long the way. Say how long when it's long.
        if (Hops > 5 || Files.Count > 2)
            reasons.Add($"Followed over {Hops - 1} steps in {Files.Count} file{(Files.Count == 1 ? "" : "s")}.");
        return (Legibility.Clear, reasons);
    }

    /// <summary>
    /// The trace says where the value is: a place, a file the user picks, files found in a folder,
    /// an address, or a literal that names the file.
    /// </summary>
    public bool Determined => !Describe().StartsWith("not determined", StringComparison.Ordinal);

    /// <summary>The widest reach among the sources, or null when the trace found no place.</summary>
    public Scope? Reach()
    {
        if (UserPicked) return Scope.User;
        var root = RootSources();
        if (root.Any(s => s.Scope == Scope.Admin)) return Scope.Admin;
        if (root.Any(s => s.Kind == SourceKind.NetworkShare)) return Scope.WebService;
        if (root.Any(s => s.Scope == Scope.User)) return Scope.User;
        if (root.Any(s => s.Scope == Scope.App)) return Scope.App;
        return null;
    }

    /// <summary>Literals in the value itself or one step away: what the call names, not what the trace met further on.</summary>
    /// <summary>Every literal with how deep in the trace it was found (0 = the expression itself).</summary>
    public IReadOnlyList<(string Text, int Depth)> LiteralDepths => _literalDepth;

    public IEnumerable<string> NearLiterals => _literalDepth.Where(l => l.Depth <= 1 && l.Text.Length > 0).Select(l => l.Text);

    /// <summary>A hash the value is made from: which, of what, and whether it's the whole name or a part of it.</summary>
    public sealed record Hashed(string Algorithm, string Of, bool Whole);

    /// <summary>Hashes the trace passed through.</summary>
    public List<Hashed> Hashes { get; } = new();

    /// <summary>"a name made from a SHA-256 of the address", for the end of a target. Null without a hash.</summary>
    public string? HashWords => Hashes.Count == 0 ? null
        : Hashes.All(h => h.Whole) ? $"a name made from a {Hashes[0].Algorithm} of {Hashes[0].Of}"
        : $"a name that includes a {Hashes[0].Algorithm} of {Hashes[0].Of}";

    /// <summary>Settings the trace met: names of properties filled from a settings file.</summary>
    public IReadOnlyList<string> Settings => _settings;

    public bool UserPicked => Sources.Any(s => s.Kind == SourceKind.UserPicked);

    /// <summary>Set by the scan when the target is a file or folder: hives met on the way aren't part of its place.</summary>
    public bool FilePlace { get; set; }

    /// <summary>"a file or folder the user picks", "files the user drops onto the window", or both, joined with "or".</summary>
    public string PickedLabel => string.Join(" or ", Sources.Where(s => s.Kind == SourceKind.UserPicked).Select(s => s.Label).Distinct());

    /// <summary>True when the trace found nothing at all: no place, no literal, nothing open.</summary>
    public bool Empty => Sources.Count == 0 && Literals.All(l => l.Length == 0) && Unresolved.Count == 0;

    // A piece of a path, a key or a file name: no spaces, no regex or message punctuation.
    private static readonly Regex PathLike = new(@"^(?!(?:[^ ]* ){2})[\w\-.{}\\/:%~@+ ]{1,100}$", RegexOptions.Compiled);

    public IEnumerable<string> Urls => Literals.Where(l => Regex.IsMatch(l, @"^(?:https?|wss?|ftp)://", RegexOptions.IgnoreCase));

    /// <summary>A short description of the place: "exe folder › settings.json", "HKCU › Software\X", a URL.</summary>
    public string Describe(bool path = true)
    {
        var described = DescribeWithoutHash(path);
        if (FilePlace && described == "what the user types") described = "a path the user types";
        // A hash in the name: the place stays what it is; the name is shown for what it is.
        return HashWords is { } words && path && !described.StartsWith("not determined", StringComparison.Ordinal)
            ? Clip(described + " › " + words, 160) : described;
    }

    private string DescribeWithoutHash(bool path)
    {
        // A folder you pick and the folders found inside it (a tree walk): both are yours to choose.
        if (UserPicked)
        {
            // Every way the user hands it a file: "a file or folder the user picks, drops onto the window or opens it with".
            var ways = new List<string>();
            if (Sources.Any(s => s.Label == "a file or folder the user picks")) ways.Add("picks");
            if (Sources.Any(s => s.Label == "files the user drops onto the window")) ways.Add("drops onto the window");
            if (Sources.Any(s => s.Kind == SourceKind.CommandLine)) ways.Add("opens it with (its command line)");
            var label = ways.Count == 0 ? PickedLabel
                : "a file or folder the user " + (ways.Count == 1 ? ways[0] : string.Join(", ", ways.Take(ways.Count - 1)) + " or " + ways[^1]);
            return Sources.Any(s => s.Kind == SourceKind.FolderListing) ? label + ", or what's found inside it" : label;
        }
        if (Sources.Any(s => s.Kind == SourceKind.FolderListing))
        {
            var folder = DescribePlace(path);
            // Picked in a list whose entries were found in a folder: the pick is the answer; the reasons say what the
            // list offers.
            if (folder.StartsWith("picked in a list", StringComparison.Ordinal)) return folder;
            if (folder == "what the user types") folder = "a folder the user types";
            // Directory.EnumerateFiles(dir, "*.csproj") met far down the trace (a project's name read from the project
            // files it found) doesn't say what this path matches: only a pattern near the top does.
            var matching = _globs.Where(g => g.Depth <= GlobDepth).Select(g => g.Glob).Distinct().ToList();
            return "files found at run time in " + (folder.StartsWith("not determined", StringComparison.Ordinal) ? "a folder" : folder)
                   + (matching.Count == 0 ? "" : " matching " + string.Join(" or ", matching.Take(3)));
        }
        return DescribePlace(path);
    }

    private string DescribePlace(bool path)
    {
        // Addresses near the top of the trace only: one found by wandering deep isn't this call's.
        var url = _literalDepth.Where(l => l.Depth <= 3 && Regex.IsMatch(l.Text, @"^(?:https?|wss?|ftp)://", RegexOptions.IgnoreCase))
            .Select(l => l.Text).FirstOrDefault();
        if (url is not null) return Clip(url, 100);

        var root = RootSources();
        // A file's place: a registry hive met on the way (a tuple that carries the hive beside the file name) isn't
        // a folder.
        if (FilePlace) root = root.Where(s => s.Kind is not (SourceKind.HiveMachine or SourceKind.HiveUser)).ToList();
        var labels = root.Where(s => s.Kind is not SourceKind.FixedPath and not SourceKind.UserPicked and not SourceKind.ListPick)
            .Select(s => s.Label).Distinct().ToList();
        // SelectedA and SelectedB: one place, "picked in a list (SelectedA, SelectedB)", in front.
        var picked = Sources.Where(s => s.Kind == SourceKind.ListPick).Select(s => s.Label).Distinct().ToList();
        if (picked.Count > 0) labels.Insert(0, "picked in a list (" + string.Join(", ", picked.Take(3)) + ")");
        int rootDepth = root.Count > 0 ? root.Min(s => _sourceDepth[s]) : int.MaxValue;
        // The pieces nearest the top (the file name end), shown root first: deeper ones to the left,
        // pieces of one expression in the order they're written.
        var pieces = _literalDepth
            .Select((l, i) => (l.Text, l.Depth, Index: i))
            .Where(l => l.Text.Length > 0 && l.Text.Length <= 160 && l.Text != "{}" && (_filled.Contains(l.Text) && PathLike.IsMatch(Regex.Replace(l.Text, @" \(or [^()]*\)", "")) || l.Text.Length <= 120 && PathLike.IsMatch(l.Text)) && !Regex.IsMatch(l.Text, @"^[\s{}.,;:|/\\_-]*$"))
            .Where(l => rootDepth == int.MaxValue || l.Depth <= rootDepth + 2)
            // A drive letter alone ("C:") is the drive's root, already said: it takes no place among the pieces.
            .Where(l => !Regex.IsMatch(l.Text, @"^[A-Za-z]:\\?$"))
            // ToString("yyyyMMdd-HHmmss"), ToString("N"): how a value is written, not a part of the place.
            .Where(l => !Regex.IsMatch(l.Text, @"^(?:[yMdHhmsfFtK]{2,}[-_ .:]?)+$|^[NDXxGgRrCcFfPp]\d?$"))
            .DistinctBy(l => l.Text)
            .ToList();
        // NewFile("failsafe-task", "xml") into $"{name}-{stamp}.{extension}": the arguments are already inside the
        // filled-in name, not folders of their own.
        pieces = pieces.Where(l => !pieces.Any(o => o.Text != l.Text && o.Text.Length > l.Text.Length && _filled.Contains(o.Text)
                                                  && o.Text.Contains(l.Text, StringComparison.Ordinal))).ToList();
        // ("SOFTWARE", …), ("SYSTEM", …), ("SAM", …): plain names met side by side in one list are choices, not
        // folders inside each other. One piece: "SOFTWARE, SYSTEM, SAM or SECURITY".
        foreach (var group in pieces.Where(p => Regex.IsMatch(p.Text, @"^[\w -]+$") && _choices.Contains(p.Text)).GroupBy(p => p.Depth).Where(g => g.Count() >= 3).ToList())
        {
            var names = group.Select(p => p.Text).ToList();
            var first = group.First();
            pieces = pieces.Where(p => !group.Contains(p)).ToList();
            pieces.Add((string.Join(", ", names.Take(names.Count - 1)) + " or " + names[^1], first.Depth, first.Index));
        }
        bool dropped = pieces.Count > 3 && labels.Count > 0;
        var placed = pieces
            .OrderBy(l => l.Depth).ThenBy(l => l.Index)
            .Take(3)
            .OrderByDescending(l => l.Depth).ThenBy(l => l.Index)
            .Select(l => l.Text)
            .ToList();
        // Path.Combine(outDir, "NTUSER.DAT") with outDir typed in a box: the part you decide stays in front,
        // so the name doesn't read like a fixed system file.
        if (path && labels.Count == 0 && placed.Count > 0)
        {
            var decided = Sources.Where(s => s.Kind is SourceKind.UserTyped or SourceKind.CommandLine or SourceKind.Configuration)
                .Select(s => s.Kind == SourceKind.UserTyped ? "a path the user types" : s.Label).Distinct().ToList();
            if (decided.Count > 0) labels.Add(string.Join(" or ", decided.Take(2)));
        }
        if (!path) placed = placed.TakeLast(1).ToList();
        // More pieces than shown: the gap is marked, so the root and the end don't read as next to each other.
        else if (dropped) placed.Insert(0, "…");

        // Several hives from one helper's switch (HKLM, HKU): one place, "HKLM or HKU", and the hive names aren't pieces.
        var hives = labels.Where(l => l is "HKLM" or "HKCU" or "HKU" or "HKCR").ToList();
        if (hives.Count > 1)
        {
            labels = labels.Where(l => !hives.Contains(l)).Prepend(string.Join(" or ", hives)).ToList();
            placed = placed.Where(p => !Regex.IsMatch(p, @"^(?:HKLM|HKCU|HKU|HKCR|HKEY_\w+)$")).ToList();
        }
        // A folder the registry names: "a value read from the registry (…\ProfileList\{} › ProfileImagePath)". The key and
        // the value's name say where it's read, not folders of the path.
        // A path an event names (the Application field of a Security event): the log and the field's name say
        // where it's read, not folders. Only real path parts stay.
        // A path a started program prints (dism's "Mount Dir : …"): the arguments it was started with aren't folders.
        if (path && labels.Count == 0 && Sources.Any(s => s.Kind == SourceKind.ProgramOutput))
            return "a path that a program it starts prints";
        if (path && Sources.Any(s => s.Kind == SourceKind.EventLog))
        {
            var rest = placed.Where(p => Regex.IsMatch(p, @"[\\/.]")).ToList();
            var others = labels.Where(l => l != "what a Windows event log entry says").ToList();
            return Clip(string.Join(" › ", new[] { "a path a Windows event log entry names" }.Concat(rest)) + (others.Count > 0 ? " or " + string.Join(" › ", others) : ""), 140);
        }
        if (path && Sources.Any(s => s.Kind == SourceKind.RegistryValue))
        {
            labels.Remove("a value read from the registry");
            var key = placed.FirstOrDefault(p => Regex.IsMatch(p, @"^(?i:HK\w*|SOFTWARE|SYSTEM)\\"));
            string read = "a value read from the registry";
            if (key is not null)
            {
                int at = placed.IndexOf(key);
                var value = at + 1 < placed.Count && !Regex.IsMatch(placed[at + 1], @"[\\./]") ? placed[at + 1] : null;
                var keyParts = key.Split('\\', StringSplitOptions.RemoveEmptyEntries);
                var shortKey = keyParts.Length <= 3 ? key : keyParts[0] + "\\…\\" + string.Join("\\", keyParts[^2..]);
                read += " (" + shortKey + (value is null ? "" : " › " + value) + ")";
                placed.RemoveAt(at);
                if (value is not null) placed.Remove(value);
            }
            // Other keys read on the way (where the value was looked up) aren't folders either.
            placed.RemoveAll(p => Regex.IsMatch(p, @"^(?i:HK\w*|SOFTWARE|SYSTEM)\\"));
            labels = labels.Where(l => l is not ("HKLM" or "HKCU" or "HKU" or "HKCR")).ToList();
            // Another place beside it (a fallback, C:\Users\Default) is the other branch, not a folder inside it.
            if (labels.Count > 0) return Clip(read + " or " + string.Join(" › ", labels.Concat(placed)), 140);
            labels.Insert(0, read);
        }
        var parts = labels.Concat(placed).ToList();
        // exe folder › a setting (AffFile): the folder is known, a setting names what's in it.
        if (labels.Count > 0 && placed.Count == 0 && _settings.Count > 0 && !Sources.Any(s => s.Kind == SourceKind.FolderListing))
            parts.Add("a setting (" + Clip(string.Join(", ", _settings.Take(2)), 80) + ")");
        if (parts.Count > 0) return Clip(string.Join(" › ", parts), 140);
        // Only fixed text that isn't a path or an address ("Hunter2Pass!", a user name): known, just not a place.
        if (Literals.Any(l => l.Length > 0) && Unresolved.Count == 0 && Sources.Count == 0 && !PassesNull)
            return "a fixed value in the source";
        // Nothing placed, but it's known where it comes from: what the user types, the command line, settings.
        var open = Sources.Where(s => s.Open && s.Kind != SourceKind.FolderListing).Select(s => s.Label).Distinct().ToList();
        if (open.Count > 0) return Clip(string.Join("; ", open.Take(2)), 100);
        var data = Unresolved.Where(_data.Contains).ToList();
        if (_settings.Count > 0 && data.All(d => _settings.Any(n => d.StartsWith(n + ",", StringComparison.Ordinal))))
            return "a setting (" + Clip(string.Join(", ", _settings.Take(2)), 80) + ")";
        if (data.Count > 0) return "a value set at run time (" + Clip(string.Join(", ", data.Take(2).Select(d => d.Split(',')[0])), 80) + ")";
        if (Unresolved.Count > 0) return "not determined (" + Clip(string.Join(", ", Unresolved.Take(2)), 80) + ")";
        // Nothing but null reached: this call passes no file, no address, no name.
        if (PassesNull && Sources.Count == 0 && Literals.Count == 0) return "nothing: null is passed here";
        return "not determined";
    }

    // ---- helpers ---------------------------------------------------------------------------------

    /// <summary>
    /// A named argument ("silent: false"), not a value that merely has a colon in it: the ':' of
    /// "config.UseProxy ? config.ProxyUrl : null" or of "x is { } y ? a : b" doesn't make it named.
    /// </summary>
    public static bool IsNamed(string argument) => Regex.IsMatch(argument, @"^\s*[A-Za-z_]\w*\s*:(?!:)");

    public static string StripNamed(string argument)
    {
        var m = Regex.Match(argument, @"^[A-Za-z_]\w*\s*:(?!:)\s*");
        var rest = m.Success ? argument[m.Length..] : argument;
        return Regex.Replace(rest, @"^(?:ref|out|in)\s+", "");
    }

    public static string Shorten(string code)
    {
        var flat = Regex.Replace(code, @"\s+", " ").Trim();
        return Clip(flat, 160);
    }

    public static string Clip(string text, int max) => text.Length <= max ? text : text[..(max - 1)] + "…";

    private static Source EnvSource(string name)
    {
        var upper = name.ToUpperInvariant();
        return upper switch
        {
            "APPDATA" => new Source(SourceKind.UserFolder, "user's AppData (Roaming)", Scope.User),
            "LOCALAPPDATA" => new Source(SourceKind.UserFolder, "user's AppData (Local)", Scope.User),
            "USERPROFILE" or "HOMEPATH" or "HOME" or "ONEDRIVE" => new Source(SourceKind.UserFolder, "user's profile", Scope.User),
            "TEMP" or "TMP" => new Source(SourceKind.Temp, "temp folder", Scope.User),
            "PROGRAMFILES" or "PROGRAMFILES(X86)" or "PROGRAMW6432" or "COMMONPROGRAMFILES" => new Source(SourceKind.MachineFolder, "Program Files", Scope.Admin),
            "PROGRAMDATA" or "ALLUSERSPROFILE" => new Source(SourceKind.MachineFolder, "ProgramData", Scope.Admin),
            "WINDIR" or "SYSTEMROOT" => new Source(SourceKind.MachineFolder, "Windows folder", Scope.Admin),
            _ => new Source(SourceKind.EnvironmentVariable, "environment variable " + name, Scope.App)
        };
    }

    private static string FolderLabel(string folder) => folder switch
    {
        "ApplicationData" => "AppData (Roaming)",
        "LocalApplicationData" => "AppData (Local)",
        "MyDocuments" or "Personal" => "Documents",
        "DesktopDirectory" => "Desktop",
        "UserProfile" => "profile",
        "Startup" => "Startup folder (starts with Windows)",
        "CommonApplicationData" => "ProgramData",
        "CommonStartup" => "all users' Startup folder (starts with Windows)",
        "ProgramFiles" or "ProgramFilesX86" => "Program Files",
        "CommonProgramFiles" or "CommonProgramFilesX86" => "Common Files",
        "Windows" => "Windows folder",
        "System" or "SystemX86" => "System32",
        _ => Regex.Replace(folder, "(?<=[a-z])(?=[A-Z])", " ")
    };
}

/// <summary>Finds what a lower-case name is when no assignment defines it: a parameter, a foreach or lambda variable, an out argument.</summary>
public static class Parameters
{
    public abstract record Origin;
    public sealed record MethodOrigin(string Method, int Index, int Position) : Origin;
    /// <param name="Element">For foreach (var (a, b) in …): which element of each item the name is.</param>
    public sealed record ForeachOrigin(string Collection, int Position, int Element = -1) : Origin;
    public sealed record LambdaOrigin : Origin;
    public sealed record OutOrigin : Origin;

    private static readonly HashSet<string> Blocks = new(StringComparer.Ordinal)
    {
        "if", "for", "while", "using", "switch", "lock", "fixed", "when", "else", "try", "finally", "do", "unsafe",
        "checked", "unchecked", "get", "set", "init", "add", "remove", "return", "new", "nameof", "typeof", "sizeof", "default"
    };

    public static Origin? Find(CodeFile file, int position, string name)
    {
        var masked = file.Masked;
        var n = Regex.Escape(name);

        // In the statement itself: x => …, (a, x) => …, out var x, out T x.
        var statement = file.Statement(position);
        var mStatement = CSharpLexing.CSharpLexer.BlankCommentsAndStrings(statement);
        if (Regex.IsMatch(mStatement, $@"\bout\s+(?:var|[\w<>\[\]?.,]+)\s+{n}\b")) return new OutOrigin();

        // An expression-bodied member around the position: Name(string p) => …;
        int exprStart = masked.LastIndexOfAny([';', '{', '}'], Math.Max(0, Math.Min(position, masked.Length) - 1)) + 1;
        var exprHead = masked[exprStart..Math.Min(masked.Length, Math.Max(position, exprStart) + 400)];
        var bodied = Regex.Match(exprHead, @"(?<w>[A-Za-z_]\w*)\s*(?:<[^<>]*>)?\s*\((?<ps>[^()]*(?:\([^()]*\)[^()]*)*)\)\s*=>");
        if (bodied.Success && exprStart + bodied.Index <= position + 1 && !Blocks.Contains(bodied.Groups["w"].Value)
            && ParameterIndex(bodied.Groups["ps"].Value, name) is int bi)
            return new MethodOrigin(bodied.Groups["w"].Value, bi, exprStart + bodied.Groups["ps"].Index);

        // A lambda: x => …, (a, x) => … — a parenthesis that doesn't follow a name (that would be a method).
        if (Regex.IsMatch(mStatement, $@"(?:^|[^\w.]){n}\s*=>|(?<![\w>\]]\s*)\([^()]*\b{n}\s*\)\s*=>")) return new LambdaOrigin();

        // foreach (var g in Directory.GetFiles(dir)) File.Delete(g);: a loop whose body is one statement, no braces.
        {
            int stmt = masked.LastIndexOfAny([';', '{', '}'], Math.Max(0, Math.Min(position, masked.Length) - 1)) + 1;
            var loop = Regex.Match(masked[stmt..Math.Min(position, masked.Length)], $@"\bforeach\s*\(\s*(?:var|[\w<>\[\]?.,]+)\s+{n}\s+in\s+");
            if (loop.Success)
            {
                int from = stmt + loop.Index + loop.Length, level = 0, k = from;
                for (; k < masked.Length; k++)
                {
                    if (masked[k] == '(') level++;
                    else if (masked[k] == ')' && level-- == 0) break;
                }
                if (k < position) return new ForeachOrigin(file.Text[from..k].Trim(), masked.IndexOf('(', stmt + loop.Index));
            }
        }

        int depth = 0;
        for (int i = Math.Min(position, masked.Length) - 1; i >= 0; i--)
        {
            char c = masked[i];
            if (c == '}') { depth++; continue; }
            if (c != '{') continue;
            if (depth > 0) { depth--; continue; }

            int headerStart = masked.LastIndexOfAny([';', '{', '}'], Math.Max(0, i - 1)) + 1;
            var header = masked[headerStart..i].TrimEnd();

            if (header.EndsWith("=>", StringComparison.Ordinal))
            {
                if (Regex.IsMatch(header, $@"(?:^|[^\w.]){n}\s*=>\s*$|\([^()]*\b{n}\b[^()]*\)\s*=>\s*$")) return new LambdaOrigin();
                // The parameters of an expression-bodied member whose body holds this lambda.
                var outer = Regex.Match(header, @"(?<w>[A-Za-z_]\w*)\s*(?:<[^<>]*>)?\s*\((?<ps>[^()]*(?:\([^()]*\)[^()]*)*)\)\s*=>");
                if (outer.Success && !Blocks.Contains(outer.Groups["w"].Value) && ParameterIndex(outer.Groups["ps"].Value, name) is int oi)
                    return new MethodOrigin(outer.Groups["w"].Value, oi, headerStart + outer.Groups["ps"].Index);
                continue;
            }

            if (Regex.IsMatch(header, @"\b(?:class|struct|record|interface)\b"))
            {
                // A primary constructor: class Store(string folder).
                var primary = Regex.Match(header, @"\b(?:class|struct|record)\s+(?<type>[A-Za-z_]\w*)\s*(?:<[^<>]*>)?\s*\((?<ps>[^()]*(?:\([^()]*\)[^()]*)*)\)");
                if (primary.Success && ParameterIndex(primary.Groups["ps"].Value, name) is int pi)
                    return new MethodOrigin(primary.Groups["type"].Value, pi, headerStart + primary.Groups["ps"].Index);
                return null;
            }

            if (!header.EndsWith(')')) continue;
            int close = headerStart + header.Length - 1;
            int open = MatchingOpen(masked, close);
            if (open < 0) continue;
            // for (…; …; …) and foreach (var p in new[] { … }): the header holds ; or braces, so it starts
            // before the parenthesis that closes it.
            if (open < headerStart) headerStart = masked.LastIndexOfAny([';', '{', '}'], Math.Max(0, open - 1)) + 1;
            var before = masked[headerStart..open];
            var word = Regex.Match(before, @"(?<w>[A-Za-z_]\w*)\s*(?:<[^<>]*(?:<[^<>]*>[^<>]*)*>)?\s*$").Groups["w"].Value;
            var list = masked[(open + 1)..close];

            if (word == "foreach")
            {
                var fe = Regex.Match(list, $@"\b{n}\s+in\s+(?<src>.+)$", RegexOptions.Singleline);
                if (fe.Success) return new ForeachOrigin(file.Text.Substring(open + 1 + fe.Groups["src"].Index, fe.Groups["src"].Length).Trim(), open);
                // foreach (var (label, profile) in …): one element of each item.
                var tf = Regex.Match(list, @"^\s*var\s*\((?<names>[^()]*)\)\s+in\s+(?<src>.+)$", RegexOptions.Singleline);
                if (tf.Success && tf.Groups["names"].Value.Split(',').Select(x => x.Trim()).ToList() is var names && names.IndexOf(name) is int ti and >= 0)
                    return new ForeachOrigin(file.Text.Substring(open + 1 + tf.Groups["src"].Index, tf.Groups["src"].Length).Trim(), open, ti);
                continue;
            }
            if (word == "catch") { if (Regex.IsMatch(list, $@"\b{n}\s*$")) return new OutOrigin(); continue; }
            if (word.Length == 0 || Blocks.Contains(word)) continue;

            if (ParameterIndex(list, name) is int index) return new MethodOrigin(word, index, open + 1);
            // A local function or lambda inside a method: keep looking outward.
        }

        // An expression-bodied member: Name(string p) => …;
        var expression = Regex.Match(mStatement, $@"(?<w>[A-Za-z_]\w*)\s*\((?<ps>[^()]*)\)\s*=>");
        if (expression.Success && ParameterIndex(expression.Groups["ps"].Value, name) is int ei)
            return new MethodOrigin(expression.Groups["w"].Value, ei, position);

        return null;
    }

    /// <summary>The type a position is declared in: the nearest class, struct, record or interface before it.</summary>
    public static string? DeclaringType(CodeFile file, int position) => file.TypeAt(position);

    /// <summary>The index of a parameter in a parameter list ("string path, int count = 0"), or null.</summary>
    private static int? ParameterIndex(string list, string name)
    {
        var parts = new List<string>();
        int depth = 0, from = 0;
        for (int i = 0; i < list.Length; i++)
        {
            char c = list[i];
            if (c is '(' or '<' or '[') depth++;
            else if (c is ')' or '>' or ']') depth--;
            else if (c == ',' && depth == 0) { parts.Add(list[from..i]); from = i + 1; }
        }
        parts.Add(list[from..]);

        for (int i = 0; i < parts.Count; i++)
        {
            var p = parts[i].Split('=')[0].Trim();
            var m = Regex.Match(p, @"(?<type>[\w<>\[\]?.,*\s]+?)\s+(?<name>[A-Za-z_]\w*)$");
            if (m.Success && m.Groups["name"].Value == name && m.Groups["type"].Value.Trim().Length > 0) return i;
        }
        return null;
    }

    private static int MatchingOpen(string text, int close)
    {
        int depth = 0;
        for (int i = close; i >= 0; i--)
        {
            if (text[i] == ')') depth++;
            else if (text[i] == '(' && --depth == 0) return i;
        }
        return -1;
    }

    /// <summary>
    /// The call a lambda is handed to, for one of its parameters: files.Where(p => …), Parallel.ForEach(files, o, (file, state) => …),
    /// cache.GetOrAdd(key, path => …), s.Table("11", path => …).
    /// </summary>
    /// <param name="CallOpen">The call's opening parenthesis.</param>
    /// <param name="ArgIndex">Which argument of the call the lambda is.</param>
    /// <param name="ParamIndex">Which of the lambda's parameters the name is.</param>
    /// <param name="Receiver">What the method is called on (files in files.Where), or null for a bare call.</param>
    public sealed record LambdaSite(int CallOpen, int ArgIndex, int ParamIndex, string Method, string? Receiver, int ReceiverPosition);

    public static LambdaSite? LambdaCall(CodeFile file, int position, string name)
    {
        var masked = file.Masked;
        int end0 = Math.Min(masked.Length, position + name.Length);
        int from = Math.Max(0, position - 6000);
        var n = Regex.Escape(name);
        var heads = new Regex($@"(?:(?<![\w.])(?<one>{n})|\((?<list>[^()]*\b{n}\b[^()]*)\))\s*=>", RegexOptions.RightToLeft);
        foreach (Match m in heads.Matches(masked[from..end0]))
        {
            int lam = from + m.Index, arrowEnd = from + m.Index + m.Length;
            // The lambda's body has to hold the position.
            int b = arrowEnd;
            while (b < masked.Length && char.IsWhiteSpace(masked[b])) b++;
            int bodyEnd;
            if (b < masked.Length && masked[b] == '{') bodyEnd = file.MatchingBrace(b);
            else
            {
                int level = 0; bodyEnd = masked.Length;
                for (int k = b; k < masked.Length; k++)
                {
                    char c = masked[k];
                    if (c is '(' or '[' or '{') level++;
                    else if (c is ')' or ']' or '}') { if (level-- == 0) { bodyEnd = k; break; } }
                    else if ((c == ',' || c == ';') && level == 0) { bodyEnd = k; break; }
                }
            }
            if (bodyEnd < position) continue;

            int paramIndex = 0;
            if (m.Groups["list"].Success)
            {
                var ps = m.Groups["list"].Value.Split(',').Select(x => Regex.Match(x.Trim(), @"(?<n>[A-Za-z_]\w*)\s*$").Groups["n"].Value).ToList();
                paramIndex = ps.IndexOf(name);
                if (paramIndex < 0) return null;
            }

            // The call around it: the nearest parenthesis the lambda sits in.
            int callOpen = -1, depth = 0;
            for (int k = lam - 1; k >= 0; k--)
            {
                char c = masked[k];
                if (c is ')' or ']' or '}') depth++;
                else if (c is '(' or '[' or '{')
                {
                    if (depth-- > 0) continue;
                    if (c == '(') callOpen = k;
                    break;
                }
                else if (c == ';' && depth == 0) break;
            }
            if (callOpen < 0) return null;
            int argIndex = 0, d2 = 0;
            for (int k = callOpen + 1; k < lam; k++)
            {
                char c = masked[k];
                if (c is '(' or '[' or '{') d2++;
                else if (c is ')' or ']' or '}') d2--;
                else if (c == ',' && d2 == 0) argIndex++;
            }
            var lead = masked[Math.Max(0, callOpen - 200)..callOpen];
            var mm = Regex.Match(lead, @"(?<w>[A-Za-z_]\w*)\s*(?:<[^<>()]*(?:<[^<>()]*>[^<>()]*)*>)?\s*$");
            if (!mm.Success) return null;
            var method = mm.Groups["w"].Value;
            if (Blocks.Contains(method) || method is "foreach" or "catch") return null;
            int wordAt = callOpen - lead.Length + mm.Index;
            // What it's called on: back over the dot, then over one balanced expression.
            int r = wordAt - 1;
            while (r >= 0 && char.IsWhiteSpace(masked[r])) r--;
            if (r >= 1 && masked[r] == '.' && masked[r - 1] == '?') r--;
            if (r < 0 || masked[r] != '.' || (r >= 1 && masked[r - 1] == '.')) return new LambdaSite(callOpen, argIndex, paramIndex, method, null, -1);
            int start = r - 1, lvl = 0;
            for (; start >= 0; start--)
            {
                char c = masked[start];
                if (c is ')' or ']' or '}') { lvl++; continue; }
                if (c is '(' or '[' or '{') { if (lvl == 0) break; lvl--; continue; }
                if (lvl > 0) continue;
                if (char.IsLetterOrDigit(c) || c is '_' or '.' or '?' or '!' or '@') continue;
                if (char.IsWhiteSpace(c))
                {
                    // Whitespace is part of a chain only around a dot: files\n    .Where(…).
                    int p = start; while (p >= 0 && char.IsWhiteSpace(masked[p])) p--;
                    int q = start + 1; while (q < masked.Length && char.IsWhiteSpace(masked[q])) q++;
                    if ((p >= 0 && masked[p] == '.') || (q < masked.Length && masked[q] == '.')) continue;
                }
                break;
            }
            start++;
            var receiver = file.Text[start..r].Trim();
            if (receiver.Length == 0 || Regex.IsMatch(receiver, @"^(?:new|await|return|in|is|as)\b")) receiver = Regex.Replace(receiver, @"^(?:await|return|in)\s+", "");
            return receiver.Length == 0 ? new LambdaSite(callOpen, argIndex, paramIndex, method, null, -1)
                : new LambdaSite(callOpen, argIndex, paramIndex, method, receiver, start + (file.Text[start..r].Length - file.Text[start..r].TrimStart().Length));
        }
        return null;
    }
}
