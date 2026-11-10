using System.IO;
using System.Text.RegularExpressions;

namespace RepoLegibility.Core;

/// <summary>
/// Finds what the C# code does to the world: files, registry, network, processes, identities and
/// credentials, reflection and code loading, native calls, COM, services, WMI, event log,
/// environment, clipboard. Every call is found in masked code (a call written inside a string or a
/// comment isn't a call); its target is followed back with <see cref="Tracer"/>.
/// </summary>
public static class CodeScan
{
    private delegate IEnumerable<Finding> Maker(Hit hit);

    private sealed record Sink(Regex Pattern, Maker Make, Func<CodeFile, bool>? FileHas = null, bool OnText = false);

    /// <summary>The most calls of a helper followed for one finding; the rest are counted.</summary>
    private const int MaxCalls = 30;

    /// <summary>What one scan shares: the code, whether the app runs elevated, and the wrappers still to resolve.</summary>
    private sealed class ScanContext(CodeBase code, bool elevated)
    {
        public CodeBase Code { get; } = code;
        public bool Elevated { get; } = elevated;
        public Queue<Wrapper> Wrappers { get; } = new();
        public List<Root> Roots { get; } = new();

        /// <summary>Calls being followed (findings with helpers left to work through): for the progress.</summary>
        public int OpenRoots { get; set; }

        /// <summary>One helper level of a root is done; the root is done when none are left.</summary>
        public void Done(Root root)
        {
            if (--root.Pending == 0) OpenRoots--;
        }
        // Keyed by the original call too: four calls in one helper, all going out through the same call
        // of it, are four findings, not one.
        private readonly HashSet<(string SinkFile, int SinkPosition, string File, int Position, string Method, int Index)> _seen = new();
        public bool FirstTime((string, int, string, int, string, int) key) { lock (_seen) return _seen.Add(key); }

        /// <summary>
        /// Wrappers found by the work running on this thread. Work runs in parallel; each piece
        /// collects its own, and they're queued in file and call order, so a scan always comes out the same.
        /// </summary>
        [ThreadStatic] public static List<Wrapper>? Pending;

        public void Queue(List<Wrapper> found)
        {
            foreach (var w in found)
            {
                if (ReferenceEquals(w.Hit, w.Root.Sink) && !Roots.Contains(w.Root)) Roots.Add(w.Root);
                w.Root.Chain.Add(w.Method);
                if (w.Root.Pending++ == 0) OpenRoots++;
                Wrappers.Enqueue(w);
            }
        }
    }

    /// <summary>
    /// A call whose value is a parameter of the method around it: that method is a wrapper, and the
    /// value is decided at its calls. The finding stays at the call; the wrapper's calls are judged
    /// one by one and collected here.
    /// </summary>
    private sealed class Root(Hit sink, FindingKind kind, string doing, Func<Hit, IEnumerable<Finding>> remake)
    {
        public Hit Sink { get; } = sink;
        public FindingKind Kind { get; } = kind;
        public string Doing { get; } = doing;
        public Func<Hit, IEnumerable<Finding>> Remake { get; } = remake;
        public List<Finding> Calls { get; } = new();
        public int NotFollowed { get; set; }
        /// <summary>Helper levels still queued for this call; for the progress.</summary>
        public int Pending { get; set; }
        public List<string> Chain { get; } = new();
    }

    /// <summary>A method that passes one of its parameters straight on, at one level of a root's chain.</summary>
    private sealed record Wrapper(Root Root, Hit Hit, int Arg, string Method, int Index, int Position, string Parameter);

    /// <summary>
    /// One place to look at: a match of a sink, or the call of a wrapper that leads to one. A call
    /// of a wrapper keeps the sink's own arguments, with the wrapped one replaced by what the caller passes.
    /// </summary>
    private sealed class Hit
    {
        private readonly Match _match;
        private List<string>? _args;
        private readonly string? _call;

        public Hit(ScanContext context, CodeFile file, Match match)
        {
            Context = context;
            File = file;
            _match = match;
            Position = match.Index;
        }

        private Hit(ScanContext context, CodeFile file, int position, Match match, List<string> args, string call, List<string> via)
        {
            Context = context;
            File = file;
            _match = match;
            Position = position;
            _args = args;
            _call = call;
            Via = via;
        }

        public ScanContext Context { get; }
        public CodeBase Code => Context.Code;
        public bool Elevated => Context.Elevated;
        public CodeFile File { get; }
        public int Position { get; }
        public string G(string group) => _match.Groups[group].Value;
        public int MatchLength => _match.Length;

        /// <summary>The wrappers this call goes through, nearest first: shown as notes.</summary>
        public List<string> Via { get; } = new();

        /// <summary>Set when a wrapper has no callers: the sink is then judged where it stands.</summary>
        public bool NoWrapper { get; set; }

        /// <summary>For a call of a wrapper: the finding its result belongs to.</summary>
        public Root? Root { get; private init; }

        public List<string> Args => _args ??= _match.Value.IndexOf('(') is int open and >= 0
            ? File.Arguments(_match.Index + open + 1)
            : [];

        public string? Arg(int i) => i < Args.Count ? Tracer.StripNamed(Args[i]) : null;

        /// <summary>For a sink inside a helper, seen from one call of it: the helper and that call's arguments.</summary>
        public (string Method, List<string> Args, CodeFile CallFile, int CallPosition)? Binding { get; private init; }

        /// <summary>Where the finding is reported when that isn't the sink itself: the helper's call.</summary>
        public CodeFile? ReportFile { get; private init; }
        public int ReportPosition { get; private init; }

        public Tracer Trace(string expression) => Binding is { } b
            ? Tracer.RunBound(Code, expression, File, Position, b.Method, b.Args, b.CallFile, b.CallPosition)
            : Tracer.Run(Code, expression, File, Position);

        /// <summary>The sink as one call of the helper around it sees it, reported at that call.</summary>
        public Hit BoundAt(CodeFile callFile, int open, string method, List<string> args) =>
            new(Context, File, Position, _match, Args, method + " → " + BaseCall,
                [$"Through {method} ({File.Path}:{File.LineOf(Position)}), which starts the program with this call's arguments."])
            {
                NoWrapper = true,
                Binding = (method, args, callFile, open),
                ReportFile = callFile,
                ReportPosition = Math.Max(0, open - 1)
            };

        public Tracer? TraceArg(int i) => Arg(i) is { Length: > 0 } a ? Trace(a) : null;

        /// <summary>The call as written: "File.WriteAllText", "key.SetValue"; for a wrapper's call, "Wrapper → File.WriteAllText".</summary>
        public string Call
        {
            get
            {
                if (_call is not null) return _call;
                var raw = Regex.Replace(File.Text.Substring(_match.Index, _match.Length), @"\s+", " ").TrimEnd('(', ' ');
                return raw.StartsWith("new ", StringComparison.Ordinal) ? raw : raw.TrimStart('.');
            }
        }

        public Scope DefaultScope => Elevated ? Scope.Admin : Scope.User;

        /// <summary>
        /// The call's result goes into a variable (var fw = Type.GetTypeFromProgID(…)) that the rest of its
        /// member never uses: the code can do this, but in this source doesn't. Null when the result isn't
        /// kept in a variable, or the rest of the member can't be found.
        /// </summary>
        public bool? ResultUnused => VariableAfter() is { } v ? !v.Used : null;

        /// <summary>The variable the result goes into and the code after the statement, for checks like Activator.CreateInstance(fw).</summary>
        public (string Name, bool Used, string After)? VariableAfter()
        {
            var text = File.Masked;
            int statement = text.LastIndexOfAny([';', '{', '}'], Math.Max(0, Position - 1)) + 1;
            var head = Regex.Match(text[statement..Position], @"^\s*(?:using\s+)?(?:(?:var|[A-Za-z_][\w.<>,\[\]?\s]*?)\s+)?(?<v>[A-Za-z_]\w*)\s*=\s*(?:new\s+)?(?:[\w.]+[!?]?\s*\.?\s*)?$");
            if (!head.Success || head.Groups["v"].Value == "_") return null;
            int start = File.MemberStart(Position);
            int open = text.IndexOf('{', start);
            if (open < 0 || open > Position) return null;
            int close = File.MatchingBrace(open);
            if (close < 0) return null;
            int end = text.IndexOf(';', Position);
            if (end < 0 || end > close) return null;
            var rest = text[(end + 1)..close];
            var name = head.Groups["v"].Value;
            return (name, Regex.IsMatch(rest, @"(?<![\w.])" + Regex.Escape(name) + @"\b"), rest);
        }

        /// <summary>
        /// When the argument is nothing but one parameter of the method around the call, that method
        /// is a wrapper: its calls are queued to be judged where they are, and true is returned.
        /// </summary>
        public bool TryWrap(int arg, FindingKind kind, string doing, Func<Hit, IEnumerable<Finding>> remake)
        {
            if (NoWrapper || Via.Count >= 6 || Arg(arg) is not { Length: > 0 } a) return false;
            var local = Tracer.RunLocal(Code, a, File, Position);
            var hits = local.ParamHits.Select(p => (p.File, p.Method, p.Index, p.Position, p.Name)).Distinct().ToList();
            if (hits.Count != 1 || hits[0].File != File) return false;
            if (local.Sources.Count > 0 || local.Unresolved.Count > 0 || local.OpaqueReasons.Count > 0 || local.DepthExceeded || local.Stopped) return false;
            var sink = Root?.Sink ?? this;
            if (!Context.FirstTime((sink.File.Path, sink.Position, File.Path, Position, hits[0].Method, hits[0].Index))) return true;
            var root = Root ?? new Root(this, kind, doing, remake);
            (ScanContext.Pending ??= new()).Add(new Wrapper(root, this, arg, hits[0].Method, hits[0].Index, hits[0].Position, hits[0].Name));
            return true;
        }

        /// <summary>The same sink, seen from a call of the wrapper around it.</summary>
        public Hit AtCall(CodeFile file, int open, string argument, Wrapper wrapper)
        {
            var args = new List<string>(Args);
            while (args.Count <= wrapper.Arg) args.Add("");
            args[wrapper.Arg] = argument;
            var via = new List<string> { $"Through {wrapper.Method} ({File.Path}:{File.LineOf(Position)}), which passes its parameter {wrapper.Parameter} to {BaseCall}." };
            via.AddRange(Via);
            return new Hit(Context, file, Math.Max(0, open - 1), _match, args, wrapper.Method + " → " + BaseCall, via) { Root = wrapper.Root };
        }

        /// <summary>A call of the method around this hit, as a hit of its own: RunPowerShell(script) where a script is passed in.</summary>
        public Hit AtCaller(CodeFile file, int open, string argument, string call) =>
            new(Context, file, Math.Max(0, open - 1), _match, [argument], call, []) { NoWrapper = true };

        /// <summary>The sink's own call, without the wrappers in front of it.</summary>
        public string BaseCall => Call.Contains(" → ") ? Call[(Call.LastIndexOf(" → ", StringComparison.Ordinal) + 3)..] : Call;

        public Finding Make(FindingKind kind, Scope scope, Legibility legibility, string target, string summary,
            IEnumerable<string>? reasons = null, IEnumerable<string>? notes = null, Tracer? trace = null, string? call = null,
            string? pathKey = null)
        {
            // "not determined (…)" is the trace's own wording; the reader sees "not traced", and the reasons
            // say where it stopped. The summary names what kind of thing wasn't traced.
            if (target.StartsWith("not determined", StringComparison.Ordinal))
            {
                summary = summary.Replace(target, Unknown(kind), StringComparison.Ordinal);
                target = Finding.NotTraced;
            }
            bool machineWide = false;
            // Admin is what a standard user can't do. Reading HKLM, Program Files or the Windows folder any user can, so a
            // read there is User however machine-wide the place; only the SAM and SECURITY hives (and their files)
            // need elevation to read.
            if (scope == Scope.Admin && kind is FindingKind.FileRead or FindingKind.FolderListing or FindingKind.RegistryRead
                && !ReadNeedsElevation.IsMatch(target))
            {
                scope = Scope.User;
                machineWide = true;
            }
            // A value the source hides but fixes, worked out: say so in the target.
            var decoded = trace?.Decoded.FirstOrDefault(d => target.Contains(d.Value, StringComparison.Ordinal));
            if (decoded is { Value: not null } d && !target.EndsWith(")", StringComparison.Ordinal))
                target += d.How.Contains("fragments", StringComparison.Ordinal) && !d.How.Contains(',') ? " (assembled)" : " (decoded)";
            return new()
            {
                HiddenOnPurpose = trace?.OpaqueReasons.Count > 0,
                HowHidden = trace is { OpaqueReasons.Count: > 0 } ? string.Join(", ", trace.OpaqueReasons) : null,
                Kind = kind,
                Scope = scope,
                MachineWide = machineWide,
                Legibility = legibility,
                Origin = (ReportFile ?? File).Origin,
                File = (ReportFile ?? File).Path,
                Line = ReportFile is { } report ? report.LineOf(ReportPosition) : File.LineOf(Position),
                Call = call ?? Call,
                Target = target,
                Summary = summary,
                Reasons = reasons?.Distinct().ToList() ?? [],
                Notes = (notes ?? []).Concat(Via).Distinct().ToList(),
                Trace = trace?.Steps.ToList() ?? [],
                Project = (ReportFile ?? File).Project?.Name,
                PathKey = pathKey
            };
        }

        private static string Unknown(FindingKind kind) => kind switch
        {
            FindingKind.Network or FindingKind.Listens => "a host the scan couldn't trace",
            FindingKind.FileWrite or FindingKind.FileRead or FindingKind.FileDelete or FindingKind.FolderListing => "a path the scan couldn't trace",
            FindingKind.RegistryWrite or FindingKind.RegistryRead => "a key the scan couldn't trace",
            FindingKind.Process => "a program the scan couldn't trace",
            FindingKind.Database => "a database the scan couldn't trace",
            _ => "a target the scan couldn't trace"
        };
    }

    private static Regex R(string pattern) => new(pattern, RegexOptions.Compiled);

    /// <summary>A place only an administrator can read: the SAM and SECURITY hives, by key or as files under System32\config.</summary>
    private static readonly Regex ReadNeedsElevation = new(
        @"(?i)(?:^|[\\›,;(]\s*|\bor\s+)(?:SAM|SECURITY)(?=\s*(?:[\\›,;)]|or\b|$))|\bconfig\s*›\s*(?:SAM|SECURITY)\b", RegexOptions.Compiled);

    private static bool Has(CodeFile f, string pattern) => Regex.IsMatch(f.Masked, pattern);

    /// <summary>
    /// The keys a trace reaches as either-or: the nearest literal is a whole key (SOFTWARE\…), and so are
    /// others found as near, through different calls of one helper. Deeper ones are where the trace
    /// wandered, not this call's key.
    /// </summary>
    private static List<string> KeyAlternatives(Tracer t)
    {
        var literals = t.LiteralDepths.Where(l => l.Text.Length > 0 && !l.Text.StartsWith("HKEY_", StringComparison.Ordinal)).ToList();
        if (literals.Count == 0) return [];
        var first = literals.OrderBy(l => l.Depth).First();
        if (!RootedKey.IsMatch(first.Text)) return [];
        var result = new List<string> { first.Text };
        foreach (var l in literals)
            if (l.Depth <= first.Depth + 1 && RootedKey.IsMatch(l.Text) && !l.Text.Contains(" (or ", StringComparison.Ordinal) && !result.Contains(l.Text))
                result.Add(l.Text);
        return result;
    }

    /// <summary>A registry key written from its root: SOFTWARE\…, SYSTEM\…, Control Panel\….</summary>
    private static readonly Regex RootedKey = new(@"^(?:SOFTWARE|SYSTEM|HARDWARE|SECURITY|SAM|Control Panel|Environment|AppEvents|Console|Keyboard Layout|Network|Printers|Volatile Environment|\.DEFAULT)\\", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex StreamLike = R(@"(?i)stream|\bms\b|\bpipe|\.Open\w*\s*\(|\.Create\s*\(\s*\)|Console\.|\bresponse\b|\bnew\s+MemoryStream");

    private static readonly Sink[] Sinks =
    [
        // ---- files ----------------------------------------------------------------------------
        new(R(@"\bFile\.(?:WriteAll(?:Text|Bytes|Lines)(?:Async)?|AppendAll(?:Text|Lines)(?:Async)?|Create(?:Text)?|AppendText|OpenWrite)\s*\("),
            h => FileOp(h, FindingKind.FileWrite, 0, "Writes")),
        new(R(@"\bFile\.(?:Copy|Move|Replace)\s*\("), h => FileOp(h, FindingKind.FileWrite, 1, "Copies or moves a file to")),
        new(R(@"\bDirectory\.(?:CreateDirectory|Move)\s*\("), h => FileOp(h, FindingKind.FileWrite, h.Call.EndsWith("Move") ? 1 : 0, "Creates a folder")),
        new(R(@"\bFile\.Open\s*\("), h => FileOp(h, WritesMode(h.Args) ? FindingKind.FileWrite : FindingKind.FileRead, 0, WritesMode(h.Args) ? "Writes" : "Reads")),
        new(R(@"\bnew\s+(?:System\.IO\.)?FileStream\s*\("), h => FileOp(h, WritesMode(h.Args) ? FindingKind.FileWrite : FindingKind.FileRead, 0, WritesMode(h.Args) ? "Writes" : "Reads")),
        new(R(@"\bnew\s+(?:System\.IO\.)?StreamWriter\s*\("), h => h.Arg(0) is { } a && !StreamLike.IsMatch(a) ? FileOp(h, FindingKind.FileWrite, 0, "Writes") : []),
        new(R(@"\bnew\s+(?:System\.IO\.)?StreamReader\s*\("), h => h.Arg(0) is { } a && !StreamLike.IsMatch(a) ? FileOp(h, FindingKind.FileRead, 0, "Reads") : []),
        new(R(@"\bZipFile\.(?:CreateFromDirectory|ExtractToDirectory)\s*\("), h => FileOp(h, FindingKind.FileWrite, 1, "Writes")),
        new(R(@"\bZipFile\.Open\s*\("), h => h.Args.Count > 1 && Regex.IsMatch(h.Args[1], @"\b(?:Create|Update)\b") ? FileOp(h, FindingKind.FileWrite, 0, "Writes") : FileOp(h, FindingKind.FileRead, 0, "Reads")),
        new(R(@"\.Save(?:As)?\s*\("), h => SaveOp(h)),
        new(R(@"\bFile\.Delete\s*\(|\bDirectory\.Delete\s*\("), h => FileOp(h, FindingKind.FileDelete, 0, "Deletes")),
        new(R(@"\bFile\.(?:ReadAll(?:Text|Bytes|Lines)(?:Async)?|ReadLines(?:Async)?|OpenRead|OpenText)\s*\("), h => FileOp(h, FindingKind.FileRead, 0, "Reads")),
        // Player.Source = new Uri(file) on a MediaElement, player.Open(new Uri(…)) on a MediaPlayer, new SoundPlayer(path):
        // plays a file, or streams a web address.
        new(R(@"\b(?<r>[A-Za-z_]\w*)\s*\.\s*Source\s*=\s*new\s+(?:System\.)?Uri\s*\("), h => h.Code.IsMediaElement(h.G("r"), h.File) ? MediaOp(h) : []),
        new(R(@"\b(?<r>[A-Za-z_]\w*)\s*\.\s*Open\s*\(\s*(?=new\s+(?:System\.)?Uri\b)"), h => h.Code.IsMediaElement(h.G("r"), h.File) ? MediaOp(h) : []),
        new(R(@"\bnew\s+(?:System\.Media\.)?SoundPlayer\s*\((?=\s*\S)(?!\s*\))"), h => MediaOp(h)),
        new(R(@"\bDirectory\.(?:GetFiles|EnumerateFiles|GetDirectories|EnumerateDirectories|GetFileSystemEntries|EnumerateFileSystemEntries)\s*\("),
            h => FileOp(h, FindingKind.FolderListing, 0, "Lists the contents of")),

        // ---- registry -------------------------------------------------------------------------
        new(R(@"\bRegistry\.(?<hive>CurrentUser|LocalMachine|ClassesRoot|Users|CurrentConfig)\s*\.\s*(?<m>OpenSubKey|CreateSubKey|DeleteSubKey|DeleteSubKeyTree|DeleteValue|SetValue|GetValue)\s*\("),
            h => RegistryOp(h, null)),
        new(R(@"\bRegistry\.(?<m>SetValue|GetValue)\s*\("), h => RegistryOp(h, null)),
        new(R(@"\bRegistryKey\.OpenBaseKey\s*\("), h => RegistryOp(h, null, open: true)),
        new(R(@"(?<recv>[A-Za-z_]\w*)\s*\??\.\s*(?<m>SetValue|CreateSubKey|DeleteValue|DeleteSubKey|DeleteSubKeyTree|GetValue|OpenSubKey|GetValueNames|GetSubKeyNames)\s*\("),
            h => h.G("recv") is "Registry" or "CurrentUser" or "LocalMachine" or "ClassesRoot" or "Users" or "CurrentConfig"
                ? []
                : RegistryOp(h, h.G("recv")), f => Has(f, @"\bRegistry(?:Key|Hive)?\b")),

        // ---- network --------------------------------------------------------------------------
        new(R(@"\.(?<m>GetAsync|PostAsync|PutAsync|PatchAsync|DeleteAsync|SendAsync|GetStringAsync|GetByteArrayAsync|GetStreamAsync|GetFromJsonAsync|PostAsJsonAsync|PutAsJsonAsync|PatchAsJsonAsync|DeleteFromJsonAsync)\s*\("),
            h => Http(h), f => Has(f, @"\bHttpClient\b|\bIHttpClientFactory\b|\bHttpMessageInvoker\b")),
        new(R(@"\b(?:Http|Ftp)?WebRequest\.Create(?:Http)?\s*\("), h => Http(h)),
        new(R(@"\.(?<m>DownloadString|DownloadData|DownloadFile|UploadString|UploadData|UploadFile|UploadValues|OpenRead|OpenWrite)(?:Async|TaskAsync)?\s*\("),
            h => Http(h), f => Has(f, @"\bWebClient\b")),
        new(R(@"\bnew\s+(?:[\w.]+\.)?(?<t>TcpClient|UdpClient)\s*\("), h => Connect(h, "Opens a network connection to")),
        new(R(@"\.Connect(?:Async)?\s*\("), h => Connect(h, "Opens a network connection to"), f => Has(f, @"\b(?:TcpClient|UdpClient|Socket|ClientWebSocket)\b")),
        new(R(@"\bnew\s+(?:[\w.]+\.)?SmtpClient\s*\("), h => Connect(h, "Sends e-mail through")),
        // System.Net.Dns only: ctx.Dns.ResolveAsync() is an app's own method on a member named Dns.
        new(R(@"(?:(?<!\w)(?<!(?<!\.)\.)|(?<=\bSystem\.Net\.))Dns\.(?:GetHostAddresses|GetHostEntry|Resolve)(?:Async)?\s*\("), h => Connect(h, "Looks up the address of")),
        new(R(@"\bnew\s+(?:[\w.]+\.)?Ping\s*\("), h => [h.Make(FindingKind.Network, Scope.WebService, Legibility.Clear, "hosts named where it pings", "Pings hosts on the network.")]),
        new(R(@"\bnew\s+(?:[\w.]+\.)?HttpListener\s*\("), h => Listen(h, "Accepts HTTP connections")),
        new(R(@"\bnew\s+(?:[\w.]+\.)?TcpListener\s*\("), h => Listen(h, "Accepts network connections")),
        new(R(@"\bWebApplication\.Create(?:Builder)?\s*\("), h => Listen(h, "Runs a web server")),

        // ---- databases ------------------------------------------------------------------------
        new(R(@"\bnew\s+(?:[\w.]+\.)?(?<t>SqlConnection|NpgsqlConnection|MySqlConnection|OracleConnection|OdbcConnection|OleDbConnection|SqliteConnection|SQLiteConnection)\s*\("),
            h => Database(h)),

        // ---- processes and elevation -----------------------------------------------------------
        new(R(@"\bProcess\.Start\s*\("), h => ProcessOp(h, null)),
        new(R(@"(?<recv>[A-Za-z_]\w*)\s*\??\.\s*Start\s*\(\s*\)"), h => IsProcessVariable(h.File, h.G("recv")) ? ProcessOp(h, h.G("recv")) : []),
        new(R(@"\bWindowsBuiltInRole\.Administrator\b"),
            h => [h.Make(FindingKind.Elevation, Scope.User, Legibility.Clear, "the administrators group", "Checks whether it runs as administrator.")]),
        new(R(@"\bPowerShell\.Create\s*\("), h => [h.Make(FindingKind.Process, h.DefaultScope, Legibility.PartlyClear, "PowerShell inside the app",
            "Runs PowerShell inside the app.", ["What it runs is set by the AddScript or AddCommand calls; each is listed on its own."])]),
        new(R(@"\.(?<m>AddScript|AddCommand)\s*\("), h => PowerShellCommand(h), f => Has(f, @"\bPowerShell\b")),

        // ---- identities and credentials -------------------------------------------------------
        new(R(@"\bnew\s+(?:[\w.]+\.)?NetworkCredential\s*\("), h => NetworkCredential(h)),
        new(R(@"\bUseDefaultCredentials\s*=\s*true\b|\bCredentialCache\.Default(?:Network)?Credentials\b"),
            h => [ToProxy(h)
                ? h.Make(FindingKind.Identity, Scope.WebService, Legibility.Clear, "the proxy",
                    "Signs in to the proxy with the current user's Windows login.")
                : h.Make(FindingKind.Identity, Scope.WebService, Legibility.Clear, "the server it talks to",
                    "Sends the current user's Windows login to the server.")]),
        new(R(@"\bnew\s+(?:[\w.]+\.)?AuthenticationHeaderValue\s*\("), h => Token(h, 1, h.Arg(0) is { } s ? s.Trim('"', '@', '$') : "an")),
        new(R(@"Headers\s*\.\s*(?:Add|TryAddWithoutValidation)\s*\(\s*""(?<h>Authorization|X-Api-Key|Api-Key|ApiKey|X-API-KEY|PRIVATE-TOKEN|X-Auth-Token|Ocp-Apim-Subscription-Key|X-Access-Token)""\s*,"),
            h => Token(h, -1, h.G("h")), OnText: true),
        new(R(@"\b(?<p>UserName|Password|PasswordInClearText|Domain)\s*=(?![=>])"),
            h => h.File.Text.LastIndexOf("StartInfo", h.Position, Math.Min(h.Position, 500), StringComparison.Ordinal) >= 0
                 || h.File.Text.LastIndexOf("ProcessStartInfo", h.Position, Math.Min(h.Position, 500), StringComparison.Ordinal) >= 0
                ? [h.Make(FindingKind.Identity, Scope.Admin, Legibility.Clear, "another Windows account", "Starts a process as another Windows account.", call: h.G("p"))]
                : []),
        new(R(@"\b(?:LogonUser\w*|ImpersonateLoggedOnUser|WindowsIdentity\.RunImpersonated(?:Async)?|\w+\.Impersonate)\s*\("),
            h => IsDeclaration(h) ? [] : [h.Make(FindingKind.Identity, Scope.Admin, Legibility.Clear, "another Windows account", "Acts as another Windows account.")]),
        new(R(@"\bProtectedData\.(?<m>Protect|Unprotect)\s*\("),
            h => [h.Make(FindingKind.Credential, string.Join(",", h.Args).Contains("LocalMachine") ? Scope.Admin : Scope.User, Legibility.Clear, "Windows DPAPI",
                h.G("m") == "Protect" ? "Protects a secret with Windows DPAPI." : "Reads a secret protected with Windows DPAPI.")]),
        new(R(@"\bCred(?:Read|Write|Enumerate|Delete)W?\s*\("),
            h => IsDeclaration(h) ? [] : [h.Make(FindingKind.Credential, Scope.User, Legibility.Clear, "Windows Credential Manager", "Uses Windows Credential Manager.")]),
        new(R(@"\bnew\s+(?:[\w.]+\.)?X509Store\s*\("),
            h => [h.Make(FindingKind.Identity, string.Join(",", h.Args).Contains("LocalMachine") ? Scope.Admin : Scope.User, Legibility.Clear,
                string.Join(",", h.Args).Contains("LocalMachine") ? "the machine's certificate store" : "the user's certificate store", "Opens a certificate store.")]),

        // ---- services, WMI, event log, COM ----------------------------------------------------
        new(R(@":\s*ServiceBase\b"), h => [h.Make(FindingKind.Service, Scope.Admin, Legibility.Clear, "a Windows service",
            "Runs as a Windows service; the account is set when it's installed.", call: "ServiceBase")]),
        new(R(@"\bnew\s+(?:[\w.]+\.)?(?:ServiceProcessInstaller|ServiceInstaller)\b"), h => [h.Make(FindingKind.Service, Scope.Admin, Legibility.Clear, "a Windows service", "Installs a Windows service.")]),
        new(R(@"\bnew\s+(?:[\w.]+\.)?ServiceController\s*\("), h => Named(h, FindingKind.Service, Scope.Admin, "Controls the Windows service")),
        new(R(@"\bnew\s+(?:[\w.]+\.)?(?:ManagementObjectSearcher|ManagementClass|ManagementObject|ManagementScope)\s*\("), h => Wmi(h)),
        new(R(@"\bEventLog\.CreateEventSource\s*\("), h => Named(h, FindingKind.EventLog, Scope.Admin, "Registers an event log source")),
        new(R(@"\.WriteEntry\s*\("), h => [h.Make(FindingKind.EventLog, Scope.User, Legibility.Clear, "the Windows event log", "Writes to the Windows event log.")],
            f => Has(f, @"\bEventLog\b")),
        new(R(@"\bType\.GetTypeFromProgID\s*\("), h => Com(h)),
        new(R(@"\bType\.GetTypeFromCLSID\s*\("), h => [h.Make(FindingKind.Com, h.DefaultScope, Legibility.PartlyClear, h.Arg(0) ?? "a COM class",
            "Creates a COM object by its class ID.", ["A class ID doesn't say which program it is; look it up in the registry."])]),

        // ---- reflection, code loading, native code --------------------------------------------
        new(R(@"\bType\.GetType\s*\("), h => Reflection(h, ReflectionKind.Type)),
        new(R(@"\.(?<m>GetMethod|GetField|GetProperty|GetMember|InvokeMember|GetEvent)\s*\("), h => OnType(h) ? Reflection(h, ReflectionKind.Member) : []),
        new(R(@"\bActivator\.CreateInstance\s*\("), h => Reflection(h, ReflectionKind.Create)),
        new(R(@"\bAssembly\.(?<m>Load|LoadFrom|LoadFile|UnsafeLoadFrom|LoadWithPartialName)\s*\(|\.(?<m>LoadFromAssemblyPath|LoadFromStream|LoadFromAssemblyName)\s*\("),
            h => LoadCode(h)),
        new(R(@"\bNativeLibrary\.(?:Load|TryLoad)\s*\("), h => LoadCode(h)),
        new(R(@"\bMarshal\.GetDelegateForFunctionPointer\b"), h => [h.Make(FindingKind.NativeCode, h.DefaultScope, Legibility.Opaque, "a native function pointer",
            "Calls native code through a function pointer.", ["Which code runs depends on a pointer known only at run time."])]),
        new(R(@"\bnew\s+(?:[\w.]+\.)?DynamicMethod\b|\.GetILGenerator\s*\(|\bAssemblyBuilder\.DefineDynamicAssembly\s*\(|\.DefineDynamicModule\s*\("),
            h => [h.Make(FindingKind.LoadsCode, h.DefaultScope, Legibility.Opaque, "code generated at run time", "Generates code at run time.",
                ["The code that runs is built while the app runs; it isn't in the source."])]),
        // Expression trees: lambda.Compile() turns a tree built in code into code that runs. The tree is in the
        // source, so it can be read; that it becomes code is the point to flag. XPathExpression.Compile(text) and
        // the like take an argument and aren't code.
        new(R(@"\.\s*Compile\s*\(\s*(?:preferInterpretation\s*:\s*\w+\s*|true|false)?\)"),
            h => [h.Make(FindingKind.LoadsCode, h.DefaultScope, Legibility.PartlyClear, "code built from an expression tree", "Turns an expression tree into code at run time.",
                ["The code that runs is built from an expression tree while the app runs; read how the tree is put together."])]),
        new(R(@"\bCSharpScript\.\w+\s*\(|\bCSharpCompilation\.Create\s*\(|\bCodeDomProvider\b|\.CompileAssemblyFromSource\s*\("),
            h => [h.Make(FindingKind.LoadsCode, h.DefaultScope, Legibility.Opaque, "code compiled at run time", "Compiles code at run time.",
                ["The code that runs is compiled while the app runs; follow where its text comes from."])]),

        // ---- environment and clipboard --------------------------------------------------------
        new(R(@"\bEnvironment\.SetEnvironmentVariable\s*\("), h => EnvironmentWrite(h)),
        new(R(@"\bClipboard\.(?<m>SetText|SetData|SetDataObject|SetImage|SetFileDropList|SetAudio)\s*\("),
            h => [h.Make(FindingKind.Clipboard, Scope.User, Legibility.Clear, "the clipboard", "Puts data on the clipboard.")]),
        new(R(@"\bClipboard\.(?<m>GetText|GetData|GetDataObject|GetImage|GetFileDropList|GetAudioStream)\s*\("),
            h => [h.Make(FindingKind.Clipboard, Scope.User, Legibility.Clear, "the clipboard", "Reads the clipboard.")]),
    ];

    public static List<Finding> Scan(CodeBase code, bool elevated, Action<string, int?, int?>? report, List<string>? skipped = null)
    {
        var context = new ScanContext(code, elevated);
        var perFile = new (List<Finding> Found, List<Wrapper> Wrappers, List<string> Skipped)[code.Files.Count];
        int done = 0;
        Parallel.For(0, code.Files.Count, i =>
        {
            var file = code.Files[i];
            var found = new List<Finding>();
            var skippedHere = new List<string>();
            ScanContext.Pending = new List<Wrapper>();
            int n = Interlocked.Increment(ref done);
            if (n % 10 == 0) report?.Invoke("Reading " + file.Path, n, code.Files.Count);
            foreach (var sink in Sinks)
            {
                if (sink.FileHas is not null && !sink.FileHas(file)) continue;
                var haystack = sink.OnText ? file.Text : file.Masked;
                foreach (Match m in sink.Pattern.Matches(haystack))
                {
                    // On Text, the match has to start in code, not inside a string or comment.
                    if (sink.OnText && file.Masked[m.Index] != file.Text[m.Index]) continue;
                    var hit = new Hit(context, file, m);
                    try { found.AddRange(sink.Make(hit).ToList()); }
                    catch (RegexMatchTimeoutException) { skippedHere.Add($"{file.Path}:{file.LineOf(m.Index)}: too complex to follow in time; read it yourself."); }
                }
            }
            perFile[i] = (found, ScanContext.Pending, skippedHere);
            ScanContext.Pending = null;
        });

        var findings = new List<Finding>();
        foreach (var (found, wrappers, skippedHere) in perFile)
        {
            findings.AddRange(found);
            context.Queue(wrappers);
            skipped?.AddRange(skippedHere);
        }

        report?.Invoke("Following helpers to their callers", null, null);
        ResolveWrappers(context, findings, skipped, report);

        return findings
            .GroupBy(f => (f.File, f.Line, f.Kind, f.Call))
            .Select(g => g.First())
            .ToList();
    }

    /// <summary>
    /// Judges every call of every wrapper where the call is. A call that is itself inside a wrapper
    /// queues that one, for the same finding. Then each finding takes its calls: one call gives it
    /// that call's result; several give it the widest scope, the least legible result and the list.
    /// A wrapper that nothing calls is judged where it stands.
    /// </summary>
    private static void ResolveWrappers(ScanContext context, List<Finding> findings, List<string>? skipped, Action<string, int?, int?>? report)
    {
        // Progress by finding, not by helper: the findings that go through helpers are all known before this
        // starts, while helpers behind helpers only turn up on the way. So the bar only moves forward.
        int total = context.OpenRoots, helpers = 0;
        while (context.Wrappers.Count > 0)
        {
            var w = context.Wrappers.Dequeue();
            helpers++;
            try
            {
            var calls = new List<(CodeFile File, int Open, string Arg)>();
            var (fewest, most) = Tracer.Arity(w.Hit.File, w.Position);
            foreach (var (file, open) in context.Code.CallersOf(w.Method, w.Hit.File, w.Position))
            {
                // Shipped code is judged by shipped calls; a test's call says nothing about the app.
                if (w.Root.Sink.File.Origin != Origin.Tests && file.Origin == Origin.Tests) continue;
                var args = file.Arguments(open);
                if (args.Count < fewest || args.Count > most) continue; // another overload
                var arg = args.FirstOrDefault(a => a.StartsWith(w.Parameter + ":", StringComparison.Ordinal))
                          ?? (w.Index < args.Count && !Tracer.IsNamed(args[w.Index]) ? args[w.Index] : null);
                if (arg is not null) calls.Add((file, open, Tracer.StripNamed(arg)));
            }

            if (calls.Count == 0)
            {
                // Nothing calls this level: judge it where it stands, with the reason why.
                w.Hit.NoWrapper = true;
                var here = w.Root.Remake(w.Hit).ToList();
                if (ReferenceEquals(w.Hit, w.Root.Sink)) { findings.AddRange(here); context.Roots.Remove(w.Root); }
                else w.Root.Calls.AddRange(here);
                continue;
            }

            int finished = total - context.OpenRoots;
            report?.Invoke($"Finding {finished + 1} of {total} (helper {helpers}): {w.Root.Doing.ToLowerInvariant()} through {w.Method}, {calls.Count} call{(calls.Count == 1 ? "" : "s")}, in {w.Hit.File.Path}", finished, total);

            int room = Math.Max(0, MaxCalls - w.Root.Calls.Count);
            var follow = calls.Take(room).ToList();
            w.Root.NotFollowed += calls.Count - follow.Count;

            var results = new (List<Finding> Found, List<Wrapper> Wrappers, string? Skipped)[follow.Count];
            Parallel.For(0, follow.Count, i =>
            {
                var (file, open, arg) = follow[i];
                ScanContext.Pending = new List<Wrapper>();
                try { results[i] = (w.Root.Remake(w.Hit.AtCall(file, open, arg, w)).ToList(), ScanContext.Pending, null); }
                catch (RegexMatchTimeoutException) { results[i] = ([], ScanContext.Pending, $"{file.Path}:{file.LineOf(open)}: too complex to follow in time; read it yourself."); }
                ScanContext.Pending = null;
            });
            foreach (var (found, wrappers, skippedHere) in results)
            {
                w.Root.Calls.AddRange(found);
                context.Queue(wrappers);
                if (skippedHere is not null) skipped?.Add(skippedHere);
            }
            }
            finally
            {
                context.Done(w.Root);
            }
        }

        foreach (var root in context.Roots)
            if (root.Calls.Count > 0) findings.Add(Collect(root));
    }

    /// <summary>The finding at the call, from the results at the wrapper's calls.</summary>
    private static Finding Collect(Root root)
    {
        var sink = root.Sink;
        // A call that only tests reach isn't something the app does: when the app has calls of its own, those
        // decide the places and the grade, and the tests' calls are only counted.
        static bool OnlyTests(Finding c) => c.Reasons.FirstOrDefault()?.Contains(CodeBase.OnlyTests, StringComparison.Ordinal) == true;
        int testOnly = root.Calls.Any(c => !OnlyTests(c)) ? root.Calls.Count(OnlyTests) : 0;
        var calls = testOnly > 0 ? root.Calls.Where(c => !OnlyTests(c)).ToList() : root.Calls;
        var helpers = root.Chain.Distinct().ToList();
        var chain = helpers.Count == 1 ? helpers[0]
            : string.Join(", ", helpers.Take(3)) + (helpers.Count > 3 ? $" and {helpers.Count - 3} more" : "");
        var note = (helpers.Count == 1 ? $"{chain} passes the value straight on" : $"The helpers {chain} pass the value straight on")
                   + $"; it's decided at {(calls.Count == 1 && root.NotFollowed == 0 ? "the one call" : "the calls")} listed.";

        var sites = calls.Select(c => new CallSite(c.File, c.Line, c.Legibility, c.Scope, c.Target, c.Reasons.FirstOrDefault(),
            c.Notes.Where(n => n.StartsWith("Through ", StringComparison.Ordinal)).ToList())).ToList();

        if (calls.Count == 1 && root.NotFollowed == 0 && testOnly == 0)
        {
            var only = calls[0];
            var trace = new List<TraceStep> { new(only.File, only.Line, "called here: " + only.Call) };
            trace.AddRange(only.Trace);
            return new Finding
            {
                Kind = only.Kind, Scope = only.Scope, MachineWide = only.MachineWide, Legibility = only.Legibility, Origin = sink.File.Origin,
                File = sink.File.Path, Line = sink.File.LineOf(sink.Position), Call = sink.BaseCall,
                Target = only.Target, Summary = only.Summary, Reasons = only.Reasons,
                Notes = new[] { note }.Concat(only.Notes.Where(n => !n.StartsWith("Through ", StringComparison.Ordinal))).ToList(),
                Trace = trace, Project = sink.File.Project?.Name, PathKey = only.PathKey, Calls = sites
            };
        }

        var worst = calls.Max(c => c.Legibility);
        var scope = root.Kind == FindingKind.Network ? Scope.WebService : calls.Max(c => c.Scope == Scope.WebService ? Scope.User : c.Scope);
        var targets = calls.Select(c => c.Target).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var target = targets.Count == 1 ? targets[0] : $"{targets.Count} places: " + string.Join("; ", targets.Take(2)) + (targets.Count > 2 ? "; …" : "");
        int total = calls.Count + root.NotFollowed + testOnly;

        var counts = string.Join(", ", Enum.GetValues<Legibility>().Reverse()
            .Select(l => (l, n: calls.Count(c => c.Legibility == l))).Where(x => x.n > 0)
            .Select(x => $"{x.n} {Names.Of(x.l).ToLowerInvariant()}"));
        var reasons = new List<string> { $"{total} calls: {counts}"
            + (testOnly > 0 ? $"; {testOnly} more {(testOnly == 1 ? "comes" : "come")} from code only tests call" : "")
            + (root.NotFollowed > 0 ? $"; {root.NotFollowed} more not followed." : ".") };
        // Two examples of the worst, different ones: one call site reached through two helpers says the same twice.
        foreach (var line in calls.Where(c => c.Legibility == worst && c.Legibility != Legibility.Clear)
                     .Select(c => $"At {c.File}:{c.Line}: {c.Reasons.FirstOrDefault() ?? Names.Of(c.Legibility)}").Distinct().Take(2))
            reasons.Add(line);

        return new Finding
        {
            Kind = root.Kind, Scope = scope, MachineWide = scope != Scope.Admin && calls.Any(c => c.MachineWide), Legibility = worst, Origin = sink.File.Origin,
            File = sink.File.Path, Line = sink.File.LineOf(sink.Position), Call = sink.BaseCall,
            Target = target, Summary = $"{root.Doing} through {(helpers.Count == 1 ? chain : helpers[0] + (helpers.Count > 1 ? $" and {helpers.Count - 1} more helper{(helpers.Count == 2 ? "" : "s")}" : ""))}, from {total} calls.",
            Reasons = reasons, Notes = [note], Project = sink.File.Project?.Name,
            PathKeys = targets, Calls = sites, CallsNotFollowed = root.NotFollowed
        };
    }

    // ---- makers ----------------------------------------------------------------------------------

    private static bool WritesMode(List<string> args) =>
        args.Skip(1).Any(a => Regex.IsMatch(a, @"\bFileMode\.(?:Create|CreateNew|OpenOrCreate|Append|Truncate)\b|\bFileAccess\.(?:Write|ReadWrite)\b"));

    private static string Doing(FindingKind kind) => kind switch
    {
        FindingKind.FileWrite => "Writes files",
        FindingKind.FileRead => "Reads files",
        FindingKind.FileDelete => "Deletes files",
        FindingKind.FolderListing => "Lists folders",
        FindingKind.Network => "Sends requests",
        _ => "Acts"
    };

    private static IEnumerable<Finding> FileOp(Hit h, FindingKind kind, int arg, string verb)
    {
        if (h.TryWrap(arg, kind, Doing(kind), x => FileOp(x, kind, arg, verb))) yield break;
        var t = h.TraceArg(arg);
        if (t is null) yield break;

        var (legibility, reasons) = t.Judge();
        var notes = new List<string>();
        var scope = t.Reach();
        // "out.txt" with nothing else: the working folder, which is the exe's folder when started by double-click.
        // Not where something decides the start at run time ("a path the user types › HISTORY"): that isn't relative.
        if (scope is null && t.Unresolved.Count == 0 && !t.Sources.Any(x => x.Open) && t.NearLiterals.Any()
            && t.NearLiterals.All(l => !Regex.IsMatch(l, @"^(?:[A-Za-z]:|\\|/|\w+://)") && !l.Contains("{}")))
        {
            scope = Scope.App;
            notes.Add("A relative path: it lands in the working folder, which is the exe's folder when started by double-click and the shell's folder when started from one.");
        }
        if (scope is null)
        {
            scope = h.DefaultScope;
            notes.Add("Where it is isn't fixed in the source; it can reach whatever the " + (h.Elevated ? "administrator" : "user") + " can.");
        }
        // Under its own folder, but a setting names the rest: a full path there is taken as it is.
        if (scope == Scope.App && legibility != Legibility.Clear && t.Settings.Count > 0)
        {
            scope = h.DefaultScope;
            notes.Add($"Starts in its own folder, but a setting ({string.Join(", ", t.Settings.Take(2))}) names the rest; set to a full path, it can point anywhere the {(h.Elevated ? "administrator" : "user")} can reach.");
        }
        // Its own folder so far, but the trace stopped before it reached all that decides the rest.
        else if (scope == Scope.App && legibility != Legibility.Clear && (t.DepthExceeded || t.Stopped))
        {
            scope = h.DefaultScope;
            notes.Add($"Starts in its own folder as far as the scan followed it; it stopped before it reached all that decides the rest, which can point anywhere the {(h.Elevated ? "administrator" : "user")} can reach.");
        }
        if (t.Sources.Any(s => s.Label.Contains("starts with Windows"))) notes.Add("Starts with Windows.");

        t.FilePlace = true;
        var target = t.Describe();
        var what = kind switch
        {
            FindingKind.FileWrite when verb == "Writes" => "Writes a file: ",
            FindingKind.FileRead when verb == "Plays" => "Plays a media file: ",
            FindingKind.FileRead => "Reads a file: ",
            FindingKind.FileDelete => "Deletes: ",
            _ => verb + ": "
        };
        yield return h.Make(kind, scope.Value, legibility, target, what + target + ".", reasons, notes, t, pathKey: target);
    }

    /// <summary>Plays media: a file it reads, or a web address it streams from.</summary>
    private static IEnumerable<Finding> MediaOp(Hit h)
    {
        var t = h.TraceArg(0);
        if (t is null) yield break;
        var address = t.Describe(path: false);
        if (Regex.IsMatch(address, @"^(?:https?|rtsp|mms)://", RegexOptions.IgnoreCase))
        {
            var (leg, why) = t.Judge();
            yield return h.Make(FindingKind.Network, Scope.WebService, leg, address, "Downloads and plays media from " + address + ".", why, null, t);
            yield break;
        }
        foreach (var f in FileOp(h, FindingKind.FileRead, 0, "Plays")) yield return f;
    }

    /// <summary>obj.Save(path): only when the argument leads to a place or a file name; Save(stream) is no file.</summary>
    private static IEnumerable<Finding> SaveOp(Hit h)
    {
        // The argument that names the file: Save(document, pages, dialog.FileName) saves to the last one.
        int index = h.Args.FindIndex(x => Regex.IsMatch(x, @"(?i)filename|path|\bfile\b|""[^""]*\.\w{2,5}"""));
        if (index < 0) index = 0;
        var a = h.Arg(index);
        if (a is null || StreamLike.IsMatch(a)) yield break;
        var t = h.Trace(a);
        if (t.Sources.Count == 0 && !t.Literals.Any(l => Regex.IsMatch(l, @"\.\w{2,5}$"))) yield break;
        foreach (var f in FileOp(h, FindingKind.FileWrite, index, "Writes")) yield return f;
    }

    private static IEnumerable<Finding> RegistryOp(Hit h, string? receiver, bool open = false)
    {
        var method = h.G("m");
        Tracer? hive = null;
        if (receiver is not null)
        {
            bool typed = Regex.IsMatch(h.File.Masked, $@"\bRegistryKey\??\s+{Regex.Escape(receiver)}\b");
            hive = h.Trace(receiver);
            if (!typed && !hive.Sources.Any(s => s.Kind is SourceKind.HiveUser or SourceKind.HiveMachine)) yield break;
        }

        // The hive and key: from the receiver's trace, the call itself and its first argument.
        var key = h.TraceArg(0);
        var statement = h.File.Text.Substring(h.Position, Math.Min(h.MatchLength + 2, h.File.Text.Length - h.Position));
        var own = h.Trace(statement.TrimEnd('('));

        var sources = (hive?.Sources ?? []).Concat(own.Sources).Concat(key?.Sources ?? []).ToList();
        var scope = sources.Any(s => s.Kind == SourceKind.HiveMachine) ? Scope.Admin
            : sources.Any(s => s.Kind == SourceKind.HiveUser) ? Scope.User
            : h.DefaultScope;

        // A helper's switch over hive names (Split(path): "HKLM" => …, "HKU" => …) gives several: "HKLM or HKU".
        var hiveLabels = sources.Where(s => s.Kind is SourceKind.HiveUser or SourceKind.HiveMachine).Select(s => s.Label).Distinct().ToList();
        var hiveLabel = hiveLabels.Count == 0 ? "a registry hive" : string.Join(" or ", hiveLabels);
        // OpenBaseKey(hive, view): its argument is the hive itself; nothing in it is a key.
        bool baseKey = statement.Contains("OpenBaseKey", StringComparison.Ordinal);
        var allKeyLiterals = (baseKey ? [] : (hive?.Literals ?? []).Concat(key?.Literals ?? []))
            .Where(l => l.Length > 0 && !l.StartsWith("HKEY_", StringComparison.Ordinal) && !Regex.IsMatch(l, @"^(?:HKLM|HKCU|HKU|HKCR)$"))
            // Guid.ToString("N"), ToString("yyyyMMdd"): how a value is written, not a key.
            .Where(l => !Regex.IsMatch(l, @"^(?:[yMdHhmsfFtK]{2,}[-_ .:]?)+$|^[NDXxGgRrCcFfPp]\d?$")).Distinct().ToList();
        var keyLiterals = allKeyLiterals.Take(2).ToList();
        // HKLM\SAM and HKLM\SECURITY: the local accounts' password hashes and the system's secrets.
        var secretHives = allKeyLiterals.Where(l => Regex.IsMatch(l, @"^(?i:SAM|SECURITY)(?:\\|$)")).Select(l => l.Split('\\')[0].ToUpperInvariant()).Distinct().ToList();
        var target = hiveLabel + (keyLiterals.Count > 0 ? " › " + string.Join(" › ", keyLiterals) : "");
        // A registry helper the whole app goes through: many keys, none of them this call's. Say so, not two of them.
        bool manyKeys = hiveLabels.Count > 1 && allKeyLiterals.Count > 3;
        if (manyKeys) target = hiveLabel + " › keys decided while it runs";
        // Delete(SpynetKey, …) and Delete(ExclusionsKey, …) through one helper: two keys, either one, not a
        // path of two. Shown as one key or the others, then the value name.
        var keyTrace = hive is { } && hive.Literals.Any(l => l.Length > 0) ? hive : key;
        var rootedKeys = keyTrace is null ? [] : KeyAlternatives(keyTrace);
        if (rootedKeys.Count >= 2)
        {
            var valueName = hive is null ? null : key?.Literals.FirstOrDefault(l => l.Length > 0 && !RootedKey.IsMatch(l) && !l.Contains('\\'));
            target = hiveLabel + " › " + rootedKeys[0] + " (or " + string.Join(", ", rootedKeys.Skip(1).Take(3)) + (rootedKeys.Count > 4 ? ", …" : "") + ")"
                     + (valueName is null ? "" : " › " + valueName);
            keyLiterals = rootedKeys.Take(2).ToList();
        }

        bool writes = !open && method is "SetValue" or "CreateSubKey" or "DeleteValue" or "DeleteSubKey" or "DeleteSubKeyTree";

        var (legibility, reasons) = Merge(hive, key);
        // A helper the whole app goes through: the trace ran out of steps, but on the way it met the keys the
        // callers pass. Which one is the caller's, at run time; that's known, not a dead end.
        if (manyKeys && legibility == Legibility.Untraced && reasons.Any(r => r.StartsWith("Stopped ", StringComparison.Ordinal)))
        {
            legibility = Legibility.PartlyClear;
            var shown = allKeyLiterals.Where(l => l.Contains('\\')).Select(l => l.TrimEnd('\\')).Distinct()
                .OrderByDescending(l => l.StartsWith("HK", StringComparison.Ordinal)).Take(3).ToList();
            reasons.Insert(0, $"A registry helper the app calls with many keys ({allKeyLiterals.Count} met on the way"
                              + (shown.Count > 0 ? ", such as " + string.Join(", ", shown) : "") + "); which one is up to each caller.");
        }
        var notes = new List<string>();
        var all = string.Join(" ", keyLiterals.Concat(key?.Literals ?? []));
        if (Regex.IsMatch(all, @"CurrentVersion\\\\?Run(?:Once)?\b", RegexOptions.IgnoreCase)) notes.Add("A Run key: starts a program with Windows.");
        if (Regex.IsMatch(all, @"\\Policies\\", RegexOptions.IgnoreCase)) notes.Add("A policy key: changes how Windows or an app behaves.");
        if (Regex.IsMatch(all, @"^Software\\\\?Classes|\\Classes\\", RegexOptions.IgnoreCase)) notes.Add("Under Classes: file types, protocols or COM registrations.");
        if (secretHives.Contains("SAM")) notes.Add("The SAM hive: it holds the local accounts' password hashes.");
        if (secretHives.Contains("SECURITY")) notes.Add("The SECURITY hive: it holds the system's stored secrets (LSA secrets, cached logons).");

        var verb = method switch
        {
            "SetValue" => "Sets a registry value",
            "CreateSubKey" => "Creates or opens a registry key",
            "DeleteValue" => "Deletes a registry value",
            "DeleteSubKey" or "DeleteSubKeyTree" => "Deletes a registry key",
            "GetValueNames" or "GetSubKeyNames" => "Lists a registry key",
            "OpenSubKey" => "Opens a registry key",
            _ => open ? "Opens a registry hive" : "Reads a registry value"
        };

        var kind = writes ? FindingKind.RegistryWrite : FindingKind.RegistryRead;
        yield return h.Make(kind, scope, legibility, target, verb + ": " + target + ".", reasons, notes, key ?? hive, pathKey: target);
    }

    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<CodeBase, List<string>> BaseAddresses = new();

    /// <summary>
    /// Reflection on a type: the receiver is typeof(…), GetType(), a Type variable or a chain ending in
    /// one. JsonElement.GetProperty("x") and the like are no reflection.
    /// </summary>
    private static bool OnType(Hit h)
    {
        if (h.G("m") == "InvokeMember") return true;
        int start = h.File.Masked.LastIndexOfAny([';', '{', '}', '='], Math.Max(0, h.Position - 1)) + 1;
        var before = h.File.Masked[start..h.Position].Trim();
        if (Regex.IsMatch(before, @"(?:typeof\s*\([^()]*\)|GetType\s*\(\s*\)|\.GetType\s*\([^()]*\)|\bType\b|\.(?:GetType|ReflectedType|DeclaringType|BaseType|PropertyType|FieldType)|\bType\s*\.\s*GetType\s*\([^()]*\))\s*[?!]?$")) return true;
        // t!.GetMethod("Start"): the null-forgiving ! doesn't change the receiver.
        var receiver = Regex.Match(before, @"(?<r>[A-Za-z_]\w*)\s*[?!]?$").Groups["r"].Value;
        return receiver.Length > 0 && Regex.IsMatch(h.File.Masked, $@"\bType\??\s+{Regex.Escape(receiver)}\b|\b{Regex.Escape(receiver)}\s*=\s*(?:typeof\s*\(|[\w.]*GetType\s*\()");
    }

    private static IEnumerable<Finding> Http(Hit h)
    {
        if (h.TryWrap(0, FindingKind.Network, "Sends requests", Http)) yield break;
        var t = h.TraceArg(0);
        var (legibility, reasons) = t?.Judge() ?? (Legibility.PartlyClear, new List<string>());
        var notes = new List<string>();
        var url = t?.Urls.FirstOrDefault();
        string target;
        if (url is not null) target = t!.Describe();
        else
        {
            // HttpClient uses BaseAddress only for a relative address; an absolute one replaces it. Join the
            // two only when the source shows a relative path; when it can't tell, say so and don't join.
            var bases = BaseAddressesIn(h.Code);
            var relative = legibility == Legibility.Opaque ? null
                : t?.Literals.FirstOrDefault(l => l.Length > 0 && !l.Contains("://", StringComparison.Ordinal) && Regex.IsMatch(l, @"^/?[\w\-.~%/?=&+]+$"));
            if (bases.Count > 0 && relative is not null)
            {
                target = string.Join(", ", bases.Take(2)) + " + " + Tracer.Clip(relative, 60);
                notes.Add("A relative address, joined to the client's BaseAddress.");
                if (legibility == Legibility.Untraced) legibility = Legibility.PartlyClear;
            }
            else
            {
                target = legibility == Legibility.Opaque ? "an address the code hides" : "an address not shown in the source";
                // A setting, what the user types, a value set at run time: that decides the address, and it's
                // the answer (Run time). Only with nothing known is the address untraced.
                if (legibility == Legibility.PartlyClear && t is not null && t.Determined)
                {
                    // "a setting (Url)", "a value set at run time (…)": where it comes from. A piece of text alone
                    // ("/robots.txt") is part of it, not the address.
                    var from = t.Describe(path: false);
                    target = from.StartsWith("a ", StringComparison.Ordinal) || from.StartsWith("picked in", StringComparison.Ordinal) ? "an address from " + from
                        : from.Contains("{}", StringComparison.Ordinal) ? "an address decided while it runs"
                        : $"an address decided while it runs, ending in {from}";
                }
                else if (legibility is Legibility.Clear or Legibility.PartlyClear)
                {
                    legibility = Legibility.Untraced;
                    reasons.Add("The address isn't in the source.");
                }
                if (bases.Count > 0)
                    notes.Add($"If this address is relative, the client joins it to its BaseAddress ({string.Join(", ", bases.Take(2))}); the source doesn't show which it is.");
            }
        }

        var method = h.G("m");
        var verb = method switch
        {
            "" => "Sends a web request to",
            "DownloadString" or "DownloadData" or "GetStringAsync" or "GetByteArrayAsync" or "GetStreamAsync" or "GetFromJsonAsync" or "GetAsync" or "OpenRead" => "Downloads from",
            "DownloadFile" => "Downloads a file from",
            "UploadString" or "UploadData" or "UploadFile" or "UploadValues" or "OpenWrite" => "Uploads to",
            "PostAsync" or "PostAsJsonAsync" => "Sends data (POST) to",
            "PutAsync" or "PutAsJsonAsync" or "PatchAsync" or "PatchAsJsonAsync" => "Sends data (PUT/PATCH) to",
            "DeleteAsync" or "DeleteFromJsonAsync" => "Sends a DELETE to",
            _ => "Sends a request to"
        };

        if (method == "DownloadFile" && h.TraceArg(1) is { } saved) notes.Add("Saves to " + saved.Describe() + ".");

        // What leaves the machine: the body of a POST, PUT or upload, as far as the source shows it.
        int body = method switch
        {
            "PostAsync" or "PostAsJsonAsync" or "PutAsync" or "PutAsJsonAsync" or "PatchAsync" or "PatchAsJsonAsync" => 1,
            "UploadString" or "UploadData" or "UploadFile" or "UploadValues" => h.Args.Count - 1,
            _ => -1
        };
        string? sends = body > 0 && body < h.Args.Count ? WhatIsSent(h, body) : null;
        if (sends is not null) notes.Insert(0, "Sends: " + sends + ".");
        var finding = h.Make(FindingKind.Network, Scope.WebService, legibility, target, verb + " " + target + ".", reasons, notes, t);
        finding.Sends = sends;
        yield return finding;
    }

    /// <summary>The target of a lookup of the computer's own name.</summary>
    public const string OwnComputer = "this computer's own name";

    private static List<string> BaseAddressesIn(CodeBase code)
    {
        return BaseAddresses.GetValue(code, static c =>
        {
            var found = new List<string>();
            foreach (var file in c.Files)
                foreach (Match m in Regex.Matches(file.Text, @"BaseAddress\s*=\s*new\s+Uri\s*\(\s*@?""(?<u>[^""]+)"""))
                    if (file.Masked[m.Index] == file.Text[m.Index] && !found.Contains(m.Groups["u"].Value)) found.Add(m.Groups["u"].Value);
            return found;
        });
    }

    private static IEnumerable<Finding> Connect(Hit h, string verb)
    {
        // Dns.GetHostAddresses(Dns.GetHostName()): this computer's own name, a known place, not a remote one.
        if (verb.StartsWith("Looks up", StringComparison.Ordinal) && h.Arg(0) is { } own
            && Regex.IsMatch(own, @"^\s*(?:System\.Net\.)?Dns\s*\.\s*GetHostName\s*\(\s*\)\s*$|^\s*(?:System\.)?Environment\s*\.\s*MachineName\s*$"))
        {
            yield return h.Make(FindingKind.Network, Scope.User, Legibility.Clear, OwnComputer,
                "Looks up this computer's own IP addresses.", null, ["Windows answers this from the computer itself, as a rule."]);
            yield break;
        }
        if (h.TryWrap(0, FindingKind.Network, "Opens connections", x => Connect(x, verb))) yield break;
        var t = h.TraceArg(0);
        var (legibility, reasons) = t?.Judge() ?? (Legibility.Untraced, ["The address isn't in the source."]);
        var target = t is null ? "an address not shown in the source" : t.Describe(path: false);
        if (t is not null && t.Literals.Count == 0 && t.Unresolved.Count == 0 && legibility == Legibility.Clear)
        {
            legibility = Legibility.Untraced;
            reasons.Add("The address isn't in the source.");
        }
        yield return h.Make(FindingKind.Network, Scope.WebService, legibility, target, verb + " " + target + ".", reasons, null, t);
    }

    private static IEnumerable<Finding> Listen(Hit h, string verb)
    {
        var prefixes = Regex.Matches(h.File.Text, @"Prefixes\s*\.\s*Add\s*\(\s*@?\$?""(?<p>[^""]+)""")
            .Select(m => m.Groups["p"].Value).Distinct().ToList();
        var args = string.Join(", ", h.Args);
        var notes = new List<string>();
        if (Regex.IsMatch(args + string.Join(" ", prefixes), @"IPAddress\.(?:Any|IPv6Any)|\+:|\*:|0\.0\.0\.0"))
            notes.Add("Listens on every network interface, so other machines can connect.");
        if (prefixes.Any(p => !p.Contains("localhost") && !p.Contains("127.0.0.1")))
            notes.Add("A prefix other than localhost needs a URL reservation, usually made as administrator.");
        var target = prefixes.Count > 0 ? string.Join(", ", prefixes.Take(3)) : args.Length > 0 ? Tracer.Clip(args, 80) : "a port set elsewhere";
        yield return h.Make(FindingKind.Listens, Scope.WebService, Legibility.Clear, target, verb + ": " + target + ".", null, notes);
    }

    private static IEnumerable<Finding> Database(Hit h)
    {
        var t = h.TraceArg(0);
        var (legibility, reasons) = t?.Judge() ?? (Legibility.PartlyClear, ["The connection string isn't in the source."]);
        var conn = t?.Literals.FirstOrDefault(l => l.Contains('=')) ?? "";
        bool local = h.G("t").Contains("ite", StringComparison.OrdinalIgnoreCase)
                     || Regex.IsMatch(conn, @"(?i)(?:server|data source|host)\s*=\s*(?:\.|\(local\)|localhost|127\.0\.0\.1|\(localdb\))");
        var notes = new List<string>();
        if (Regex.IsMatch(conn, @"(?i)integrated security\s*=\s*(?:true|sspi)|trusted_connection\s*=\s*(?:true|yes)"))
            notes.Add("Logs in with the current user's Windows account.");
        else if (Regex.IsMatch(conn, @"(?i)\b(?:user id|uid|username)\s*="))
            notes.Add("Logs in with a database user name and password.");
        if (conn.Length == 0 && legibility == Legibility.Clear)
        {
            legibility = Legibility.PartlyClear;
            reasons.Add("The connection string isn't in the source.");
        }
        var server = Regex.Match(conn, @"(?i)(?:server|data source|host)\s*=\s*(?<s>[^;]+)").Groups["s"].Value;
        var target = server.Length > 0 ? server : h.G("t").Contains("ite", StringComparison.OrdinalIgnoreCase) ? "a local database file" : "a database server";
        yield return h.Make(FindingKind.Database, local ? Scope.User : Scope.WebService, legibility, target,
            "Connects to a database: " + target + ".", reasons, notes, t);
    }

    private static readonly Regex AdminTools = R(@"(?i)^(?:schtasks|sc|netsh|bcdedit|icacls|takeown|vssadmin|wevtutil|diskpart|dism|msiexec|shutdown|net|net1|reg|pnputil|fsutil|auditpol|secedit|gpupdate|wusa|sfc)(?:\.exe)?$");
    private static readonly Regex Shells = R(@"(?i)^(?:cmd|powershell|pwsh|wscript|cscript|mshta|bash|sh|wsl|rundll32|regsvr32)(?:\.exe)?$");

    private static bool IsProcessVariable(CodeFile file, string name) =>
        Regex.IsMatch(file.Masked, $@"\bProcess\??\s+{Regex.Escape(name)}\b|\b{Regex.Escape(name)}\s*=\s*new\s+Process\b");

    /// <summary>
    /// Process.Start in a helper whose program and arguments are its parameters (Run(tool, args)): the
    /// calls of the helper, each with its arguments. Null when it isn't such a helper, has no calls or
    /// too many, or passes a script on encoded (that's handled as PowerShell scripts).
    /// </summary>
    private static (string Method, List<(CodeFile File, int Open, List<string> Args)> Calls)? ProcessHelper(Hit h)
    {
        if (h.Args.Count == 0) return null;
        var local = Tracer.RunLocal(h.Code, string.Join(", ", h.Args.Select(Tracer.StripNamed)), h.File, h.Position);
        var hits = local.ParamHits.Select(p => (p.File, p.Method, p.Position)).Distinct().ToList();
        if (hits.Count == 0 || hits.Select(x => x.Method).Distinct().Count() != 1 || hits.Any(x => x.File != h.File)) return null;
        if (local.Literals.Any(l => Regex.IsMatch(l, @"(?i)(?:^|\s)-(?:e|en|enc|encodedcommand)\s"))) return null;
        var method = hits[0].Method;
        var calls = h.Code.CallersOf(method, h.File, hits[0].Position)
            .Where(c => h.File.Origin == Origin.Tests || c.File.Origin != Origin.Tests).ToList();
        if (calls.Count is 0 or > MaxScripts) return null;
        return (method, calls.Select(c => (c.File, c.Open, c.File.Arguments(c.Open))).ToList());
    }

    private static IEnumerable<Finding> ProcessOp(Hit h, string? receiver)
    {
        if (receiver is null && h.Binding is null && !h.NoWrapper && ProcessHelper(h) is var (helper, helperCalls))
        {
            foreach (var (file, open, args) in helperCalls)
                foreach (var f in ProcessOp(h.BoundAt(file, open, helper, args), null))
                    yield return f;
            yield break;
        }
        Tracer t;
        if (receiver is not null) t = h.Trace(receiver);
        else if (h.Args.Count == 0) yield break;
        else t = h.Trace(string.Join(", ", h.Args.Select(Tracer.StripNamed)));

        var (legibility, reasons) = t.Judge();
        var notes = new List<string>();
        var literals = t.Literals.Where(l => l.Length > 0).ToList();

        // Opens in the browser only where the source shows it: every value the trace found is a web address
        // and nothing is left open, or the code checks for http or https before it starts. A name like "url"
        // proves nothing: Windows opens whatever it's given, a program or another kind of link included.
        var urls = t.Urls.Distinct().ToList();
        var notWeb = t.LiteralsOutsideWebAddresses.Where(l => l.Length > 0).Where(NotWeb).ToList();
        foreach (var d in literals.Where(l => RiskyScheme.IsMatch(l)).Distinct().Take(2))
            notes.Add($"Names {RiskyScheme.Match(d).Value}, a kind of link Windows hands to a program of its own; links of this kind have been used to run code (ms-msdt, \"Follina\", 2022).");
        bool proven = urls.Count > 0 && notWeb.Count == 0 && !t.OpenOutsideWebAddresses.Any() && !t.SourcesOutsideWebAddresses.Any();
        var checkedAt = WebCheck(h);
        if (urls.Count > 0 && notWeb.Count == 0 && (proven || checkedAt is not null))
        {
            var hosts = urls.Select(HostOf).Where(x => x.Length > 0).Distinct().ToList();
            var shown = urls.Count == 1 ? Tracer.Clip(urls[0], 100) : Tracer.Clip(string.Join(", ", hosts.Take(4)) + (hosts.Count > 4 ? " …" : ""), 100);
            if (checkedAt is not null) notes.Add($"The code checks it's an http or https address before it opens it ({checkedAt}).");
            yield return h.Make(FindingKind.Network, Scope.WebService, legibility, shown,
                "Opens " + (urls.Count == 1 ? shown : "web pages on " + shown) + " in the browser.", reasons, notes, t);
            yield break;
        }
        if (checkedAt is not null && notWeb.Count == 0)
        {
            notes.Add($"The code checks it's an http or https address before it opens it ({checkedAt}).");
            if (t.Settings.Count > 0)
                notes.Add($"Whoever can edit the settings ({string.Join(", ", t.Settings.Take(2))}) decides which page it opens.");
            yield return h.Make(FindingKind.Network, Scope.WebService, legibility, t.Describe(path: false),
                "Opens a web address in the browser: " + t.Describe(path: false) + ".", reasons, notes, t);
            yield break;
        }

        // The program: the first literal naming one.
        // A file name first (sc.exe), a bare word only when none: Arguments = "start TermService" isn't the program
        // "start" when FileName names sc.exe.
        string? program = null;
        foreach (bool strict in new[] { true, false })
        {
            foreach (var l in literals)
            {
                var first = l.Trim().Split(' ', 2)[0].Trim('"');
                var name = FileNameOf(first);
                if (Regex.IsMatch(name, @"(?i)\.(?:exe|cmd|bat|ps1|com|msc|cpl|vbs|js|msi)$") || (!strict || l.Trim() == first) && (AdminTools.IsMatch(name) || Shells.IsMatch(name))
                    || !strict && Regex.IsMatch(name, @"(?i)^(?:explorer|notepad|git|dotnet|winget|choco|code|start)$"))
                {
                    program = name;
                    break;
                }
            }
            if (program is not null) break;
        }

        // runas: in the value itself (new ProcessStartInfo { Verb = "runas" }), or set on the variable passed in.
        var passed = receiver ?? (h.Args.Count == 1 && Regex.IsMatch(h.Args[0], @"^[A-Za-z_]\w*$") ? h.Args[0] : null);
        bool runas = literals.Any(l => l.Equals("runas", StringComparison.OrdinalIgnoreCase))
                     || (passed is not null && Regex.IsMatch(h.File.Text, $@"\b{Regex.Escape(passed)}\s*\.\s*(?:StartInfo\s*\.\s*)?Verb\s*=\s*""runas""", RegexOptions.IgnoreCase));
        literals.RemoveAll(l => l.Equals("runas", StringComparison.OrdinalIgnoreCase) || l.Equals("open", StringComparison.OrdinalIgnoreCase));

        var scope = h.DefaultScope;
        if (program is not null && AdminTools.IsMatch(program))
        {
            scope = Scope.Admin;
            notes.Add(program + " changes machine settings; most of what it does needs administrator rights.");
        }

        var all = string.Join(" ", literals);
        bool encodedPowerShell = false;
        // -EncodedCommand {encoded} with encoded = Convert.ToBase64String(…(script)): the code encodes a script it
        // builds or is given, to pass it to PowerShell intact. That's transport, not hiding: say where the
        // script comes from instead.
        // "-EncodedCommand", encoded as an argument of its own (an argument list), or "-enc {}" in one string.
        bool encodesHere = (Regex.IsMatch(all, @"(?i)(?:^|\s)-(?:e|en|enc|encodedcommand)\s+\{\}")
                            || literals.Any(l => Regex.IsMatch(l.Trim(), @"(?i)^-(?:e|en|enc|encodedcommand)$"))
                            || h.Binding is { } eb && eb.Args.Any(x => Regex.IsMatch(x, @"(?i)""-(?:e|en|enc|encodedcommand)""")))
                           && (t.Steps.Any(s => s.Code.Contains("ToBase64String", StringComparison.Ordinal))
                               || EncodesInMember(h));
        var flags = program is not null && Regex.IsMatch(program, @"(?i)^(?:powershell|pwsh)(?:\.exe)?$") ? PowerShellScript.Flags(all) : [];
        if (encodesHere)
        {
            var scripts = ScriptCallers(h);
            notes.Add("Encodes a PowerShell script at run time (-EncodedCommand) to pass it on intact; the script itself is in the source"
                      + (scripts.Length > 0 ? ": it comes from " + scripts + ". Each script is a finding of its own." : "."));
            flags.RemoveAll(f => f.Contains("-EncodedCommand", StringComparison.Ordinal));
            foreach (var script in ScriptFindings(h, flags)) yield return script;
        }
        else if (Regex.IsMatch(all, @"(?i)(?:^|\s)-(?:e|en|enc|encodedcommand)\s"))
        {
            legibility = Legibility.Opaque;
            reasons.Add(Fold.PowerShell(all) is { } ps
                ? $"Hidden on purpose (encoded PowerShell); worked out from the source: {Tracer.Clip(ps, 160)}"
                : "Runs an encoded PowerShell command: the command can't be read in the source.");
            encodedPowerShell = true;
        }
        else if (program is not null && Shells.IsMatch(program) && (t.Unresolved.Count > 0 || t.Sources.Any(s => s.Open) || literals.Any(l => l.Contains("{}"))))
        {
            legibility = Legibility.Opaque;
            reasons.Add("Runs a shell command assembled at run time.");
        }

        // What it's told to do first: dotnet's "publish", git's "clone"; then the rest in the order the trace met it.
        // A name the code looks something up by (GetValue("InstallLocation"), GetEnvironmentVariable("DOTNET_ROOT")) isn't
        // something the program is told.
        bool Lookup(string l) => t.Steps.Any(st => Regex.IsMatch(st.Code,
            @"\b(?:GetValue|GetEnvironmentVariable)\s*\(\s*""" + Regex.Escape(l) + @""""));
        // "publish \"" before a path: a quote left open by the split isn't part of what's said.
        static string Tidy(string l) { l = l.Trim(); return l.Count(c => c == '"') % 2 == 1 && l.EndsWith('"') ? l[..^1].TrimEnd() : l; }
        var told = literals.Select(Tidy).Where(l => l.Length > 0).Distinct()
            .Where(l => !l.Contains(program ?? "\u0000", StringComparison.OrdinalIgnoreCase) && !Lookup(l))
            .OrderBy(l => Regex.IsMatch(l.TrimStart(), @"(?i)^(?:restore|build|publish|run|test|pack|tool|workload|clone|fetch|pull|push|install|uninstall|start|stop|config|create|delete|add|remove|set|query)\b") ? 0
 : 1)
            .ToList();
        var target = (program is not null
            ? Tracer.Clip(program + (literals.Count > 1 ? " " + string.Join(" ", told.Take(2)) : ""), 120)
            : t.Describe(path: false)).Trim();
        // Run(item, SystemTools.Reg, new[] { "delete", Reg.ForRegExe(s.Key!), "/f" }): the program is fixed, the
        // arguments are listed where the call writes them out. What isn't written out is decided while it runs.
        if (program is not null && !encodesHere && h.Binding is { } call
            && call.Args.Select(x => Regex.Match(x.Trim(), @"^new\s*(?:string\s*)?\[\s*\]\s*\{(?<items>.*)\}$", RegexOptions.Singleline)).FirstOrDefault(m => m.Success) is { } array)
        {
            var items = Fold.SplitTop(array.Groups["items"].Value, ',') ?? [];
            var shown = items.Select(i => i.Trim()).Where(i => i.Length > 0)
                .Select(i => Regex.IsMatch(i, @"^@?""[^""{}]*""$") ? i.TrimStart('@').Trim('"') : "{}").ToList();
            var open = items.Select(i => i.Trim()).Where(i => i.Length > 0 && !Regex.IsMatch(i, @"^@?""[^""{}]*""$")).ToList();
            target = Tracer.Clip(program + " " + string.Join(" ", shown), 120);
            if (open.Count > 0)
            {
                if (legibility == Legibility.Clear) { legibility = Legibility.PartlyClear; reasons.RemoveAll(r => r.StartsWith("Followed over", StringComparison.Ordinal)); }
                reasons.Add($"The program is fixed ({program}); {(open.Count == 1 ? "one argument is" : $"{open.Count} arguments are")} decided while it runs: {Tracer.Clip(string.Join(", ", open), 120)}.");
            }
            all = string.Join(" ", new[] { program }.Concat(shown));
        }
        string? opens = null;
        if (program is null && legibility is Legibility.Clear or Legibility.PartlyClear && literals.Count == 0)
        {
            // Process.Start(Environment.ProcessPath): the app's own exe, started again.
            if (target == "exe folder" && t.Steps.Any(s => OwnExe.IsMatch(s.Code)))
            {
                target = "its own exe";
                opens = "Starts the app itself again (its own exe)";
                notes.Add("A restart: the program it starts is this app's own exe, found while it runs (Environment.ProcessPath and the like).");
            }
            // new ProcessStartInfo(path) { UseShellExecute = true } on a place the trace found: Windows opens the
            // folder in Explorer, or the file with the program it has for that kind of file.
            else if (t.Reach() is not null && ShellExecute(h))
            {
                bool folder = target.EndsWith(" folder", StringComparison.Ordinal);
                opens = folder ? $"Opens the {target} in Explorer" : $"Opens {target} with the program Windows has for it";
                if (folder) program = "explorer";
            }
            // new ProcessStartInfo(value) { UseShellExecute = true } on something the source doesn't pin down:
            // Windows opens it by what it turns out to be. Say that, not "which program".
            else if (ShellExecute(h))
            {
                opens = "Hands " + (t.Settings.Count > 0 ? "a setting" : "a value") + " to Windows to open";
                notes.Add("Windows opens it by what it is: a web address in the browser, a file with its program, but a program, a script or another kind of link (ms-settings:, file:) would run or open that instead. The code doesn't check which it is.");
                if (t.Settings.Count > 0)
                    notes.Add($"Whoever can edit the settings ({string.Join(", ", t.Settings.Take(2))}) decides what it opens.");
                if (urls.Count > 0)
                    notes.Add("Among the values the scan found: " + Tracer.Clip(string.Join(", ", urls.Take(3)), 160) + "; the source doesn't show it's always a web address.");
                if (!t.Determined)
                {
                    legibility = Legibility.Untraced;
                    reasons.Add("What it's given isn't in the source.");
                }
            }
            else
            {
                legibility = Legibility.Untraced;
                reasons.Add("Which program it starts isn't in the source.");
            }
        }

        if (runas)
        {
            // Starting a program as administrator is starting a program: its kind is that, its scope Admin.
            var elevation = MarkHidden(encodedPowerShell, h.Make(FindingKind.Process, Scope.Admin, legibility, target,
                (Commands.Describe(string.Join(" ", literals)) is { } words ? words + ": starts " : "Starts ") + target + " as administrator" + (h.Elevated
                    ? " (the app already runs as administrator, so Windows doesn't ask again)."
                    : " (Windows asks the user)."), reasons, notes, t));
            elevation.Program = ProgramName(program);
            elevation.AsAdministrator = true;
            yield return elevation;
            yield break;
        }
        // netsh advfirewall set allprofiles state off: say what it does before what it is.
        var plain = Commands.Describe(string.Join(" ", literals));
        // powershell -Command "Set-NetFirewallRule …": what the script does, by its commands.
        var commands = flags.Count > 0 || program is not null && Regex.IsMatch(program, @"(?i)^(?:powershell|pwsh)(?:\.exe)?$")
            ? PowerShellScript.Commands(all + (encodedPowerShell && Fold.PowerShell(all) is { } decoded ? "\n" + decoded : "")) : [];
        if (!encodesHere && commands.Count > 0) notes.Add("The script " + PowerShellScript.Describe(commands) + ".");
        foreach (var f in flags) notes.Add("PowerShell " + f + ".");
        var made = MarkHidden(encodedPowerShell, h.Make(FindingKind.Process, scope, legibility, target,
            opens is not null ? opens + "." : plain is null ? "Starts " + target + "." : plain + ": starts " + target + ".", reasons, notes, t));
        made.Program = ProgramName(program);
        made.Commands = encodesHere ? [] : commands;
        yield return made;
    }

    // Kinds of link Windows hands to a handler of its own, some used to run code.
    private static readonly Regex RiskyScheme = R(@"(?i)^(?:ms-msdt|search-ms|search|ms-officecmd|ms-appinstaller|ms-cxh|ms-word|ms-excel|ms-powerpoint|shell|vbscript|javascript|file):");

    /// <summary>A value that isn't a web address: a drive or share path, a program or script, a link of another kind.</summary>
    private static bool NotWeb(string l) =>
        Regex.IsMatch(l, @"^(?:[A-Za-z]:[\\/]|\\\\)")
        || Regex.IsMatch(l, @"(?i)\.(?:exe|com|bat|cmd|ps1|vbs|vbe|js|jse|wsf|msi|msc|cpl|lnk|scr|hta|reg)(?:\s|$)")
        || Regex.IsMatch(l, @"^[A-Za-z][\w+.-]{1,30}:") && !Regex.IsMatch(l, @"(?i)^https?://");

    private static string HostOf(string url) => Regex.Match(url, @"(?i)^https?://(?<h>[^/:?#{}]+)") is { Success: true } m ? m.Groups["h"].Value : "";

    /// <summary>
    /// Where the code checks for an http or https address before it starts one: in the member that starts it,
    /// or, through a helper, in the member that calls the helper. Null when it doesn't.
    /// </summary>
    private static string? WebCheck(Hit h)
    {
        string? In(CodeFile file, int position)
        {
            // From the member's start, or further back: Guards checks the start really sits under the if.
            int start = Math.Max(0, Math.Min(file.MemberStart(position), position - 600));
            foreach (Match m in WebScheme.Matches(file.Text[start..position]))
                if (Guards(file, start + m.Index, position)) return $"{file.Path}:{file.LineOf(start + m.Index)}";
            // if (detail is { IsWebAddress: true }) or if (x.IsWebAddress): a property of the repo's own that makes the
            // check, one step away. It counts when its definition holds the check itself.
            foreach (Match m in Regex.Matches(file.Text[start..position], @"\{\s*(?<p>[A-Z]\w*)\s*:\s*true\b|\.\s*(?<p>[A-Z]\w*)\b(?!\s*\()"))
            {
                var defs = h.Code.Members(m.Groups["p"].Value, false).Where(d => WebScheme.IsMatch(d.Expression)).ToList();
                if (defs.Count == 0 || !Guards(file, start + m.Index, position)) continue;
                var (_, defFile, defPos) = defs[0];
                return $"{defFile.Path}:{defFile.LineOf(defPos)}, through {m.Groups["p"].Value}";
            }
            return null;
        }
        return In(h.File, h.Position) ?? (h.Binding is { } b ? In(b.CallFile, b.CallPosition) : null);
    }

    private static readonly Regex WebScheme = R(@"\bUri\s*\.\s*UriSchemeHttps?\b|\.\s*Scheme\s*(?:==|!=|is|\.Equals\s*\()\s*""https?""|StartsWith\s*\(\s*""https?://""");

    /// <summary>
    /// The check at <paramref name="check"/> sits in an if's condition that the start at <paramref name="position"/>
    /// depends on: the start is inside the if's branch, or the if leaves early (return, continue, throw) when the
    /// check fails and the start comes after it. A check that only logs, or sits elsewhere, doesn't count.
    /// </summary>
    private static bool Guards(CodeFile file, int check, int position)
    {
        var masked = file.Masked;
        var head = Regex.Match(masked[Math.Max(0, check - 300)..check], @"\bif\s*\((?=[^;{}]*$)");
        if (!head.Success) return false;
        int open = Math.Max(0, check - 300) + head.Index + head.Length - 1;
        int close = Match(masked, open, '(', ')');
        if (close < 0 || close < check) return false;
        var condition = file.Text[open..close];
        int body = close + 1;
        while (body < masked.Length && char.IsWhiteSpace(masked[body])) body++;
        if (body >= masked.Length) return false;
        bool negated = Regex.IsMatch(condition, @"!=|!\s*Uri\s*\.\s*TryCreate|\bis\s+not\b|!\s*\(|!\s*\w+\s*\.\s*StartsWith");
        int end = masked[body] == '{' ? Match(masked, body, '{', '}') : masked.IndexOf(';', body);
        if (end < 0) return false;
        if (negated)
            return Regex.IsMatch(masked[body..end], @"^\{?\s*(?:return|continue|throw|break)\b") && position > end;
        return position > body && position < end;
    }

    private static int Match(string text, int open, char a, char b)
    {
        int depth = 0;
        for (int i = open; i < text.Length; i++)
        {
            if (text[i] == a) depth++;
            else if (text[i] == b && --depth == 0) return i;
        }
        return -1;
    }

    /// <summary>The method that starts it, or the one calling it through a helper, base64s a text it builds or is given.</summary>
    private static bool EncodesInMember(Hit h)
    {
        bool In(CodeFile file, int position)
        {
            int start = file.MemberStart(position);
            return Regex.IsMatch(file.Masked[start..Math.Min(file.Masked.Length, position + 200)], @"\bConvert\s*\.\s*ToBase64String\s*\(");
        }
        return In(h.File, h.Position) || h.Binding is { } b && In(b.CallFile, b.CallPosition);
    }

    private static readonly Regex OwnExe = R(@"\bEnvironment\s*\.\s*ProcessPath\b|\bMainModule\s*\??\.\s*FileName\b|\bApplication\s*\.\s*ExecutablePath\b|GetEntryAssembly\(\)\s*\??\.\s*Location\b");

    /// <summary>The start in this statement asks Windows to open what it's given (UseShellExecute = true).</summary>
    private static bool ShellExecute(Hit h)
    {
        var text = h.File.Text;
        int end = text.IndexOf(';', h.Position);
        var statement = text[h.Position..(end < 0 ? Math.Min(text.Length, h.Position + 400) : end)];
        return Regex.IsMatch(statement, @"\bUseShellExecute\s*=\s*true\b");
    }

    private static readonly (Regex Pattern, string What)[] Personal =
    [
        (R(@"\bEnvironment\s*\.\s*UserName\b|\bWindowsIdentity\b.*\.(?:Name|User|Owner)\b|\bUserPrincipal\b"), "the Windows user name"),
        (R(@"\bEnvironment\s*\.\s*UserDomainName\b"), "the Windows domain"),
        (R(@"\bEnvironment\s*\.\s*MachineName\b|\bDns\s*\.\s*GetHostName\b"), "the computer name"),
        (R(@"\bEnvironment\s*\.\s*OSVersion\b|\bRuntimeInformation\s*\.\s*OSDescription\b"), "the Windows version"),
        (R(@"\bClipboard\s*\.\s*Get\w*"), "the clipboard"),
        (R(@"\bFile\s*\.\s*Read\w*\s*\(|\bnew\s+StreamContent\s*\(|\bFile\s*\.\s*OpenRead\s*\("), "the contents of a file"),
        (R(@"\bEnvironment\s*\.\s*GetEnvironmentVariables?\s*\("), "environment variables"),
        (R(@"\bRegistry\w*\s*\.|\bGetValue\s*\("), "values from the registry"),
        (R(@"\bProcess\s*\.\s*GetProcesses\w*\s*\("), "the list of running programs"),
        (R(@"\bNetworkInterface\b|\bGetPhysicalAddress\s*\("), "network adapter details"),
        (R(@"\bCopyFromScreen\s*\(|\bScreen\s*\.\s*\w+Bounds\b"), "a screenshot"),
        (R(@"\bGetAsyncKeyState\b|\bGetKeyState\b|\bKeyboard\s*\."), "keyboard input"),
        (R(@"\bProtectedData\s*\.\s*Unprotect\b|\bPassword\b|\bCredential\b"), "a password or credential")
    ];

    /// <summary>What a request body holds: personal data the source shows by name, fixed text, or what the trace says.</summary>
    private static string? WhatIsSent(Hit h, int arg)
    {
        if (h.TraceArg(arg) is not { } t || h.Arg(arg) is not { } expression) return null;
        var seen = string.Join("\n", t.Steps.Select(s => s.Code).Prepend(expression));
        var personal = Personal.Where(p => p.Pattern.IsMatch(seen)).Select(p => p.What).Distinct().ToList();
        if (personal.Count > 0) return string.Join(", ", personal.Take(3));
        var described = t.Describe(false);
        return described.StartsWith("not determined", StringComparison.Ordinal) ? null : described;
    }

    /// <summary>Can, not does: declared, looked up or created, but not used in this source. Ranked below what's used.</summary>
    private static Finding MarkUnused(bool unused, Finding f)
    {
        f.Unused = unused;
        return f;
    }

    /// <summary>"powershell", "netsh", "explorer": the program's name without folder or .exe, for the overview.</summary>
    private static string? ProgramName(string? program) =>
        program is null ? null : Regex.Replace(FileNameOf(program), @"(?i)\.exe$", "").ToLowerInvariant();

    /// <summary>The last part of a Windows or Unix path, the same on every OS the scan runs on.</summary>
    private static string FileNameOf(string path) => path[(path.LastIndexOfAny(['\\', '/']) + 1)..];

    private const int MaxScripts = 30;

    /// <summary>
    /// The scripts a helper like RunPowerShell(script) is given, one finding per call: what each does, by
    /// the commands in it. The helper's own finding is the program it starts; these are what it runs.
    /// </summary>
    private static IEnumerable<Finding> ScriptFindings(Hit h, List<string> flags)
    {
        // Through a helper (ToolRunner.Run), the method that encodes is the one calling it (PowerShell.Run).
        var (hostFile, hostPosition) = h.Binding is { } hb ? (hb.CallFile, hb.CallPosition) : (h.File, h.Position);
        int start = hostFile.MemberStart(hostPosition);
        var header = Regex.Match(hostFile.Masked[start..Math.Min(hostPosition, hostFile.Masked.Length)],
            @"(?<m>[A-Za-z_]\w*)\s*(?:<[^<>()]*>)?\s*\((?<ps>(?:[^()]|\([^()]*\))*)\)\s*(?:where\b[^{]*)?(?:\{|=>)");
        if (!header.Success) yield break;
        var method = header.Groups["m"].Value;
        // The parameter that carries the script: one named for it (script, command, code), else the first string.
        var parameters = header.Groups["ps"].Value.Split(',').Select(p => p.Trim()).ToList();
        int index = parameters.FindIndex(p => Regex.IsMatch(p, @"^(?:string\??)\s+(?i:script|command|commands|code|cmd|text)\b"));
        if (index < 0) index = parameters.FindIndex(p => Regex.IsMatch(p, @"^(?:string\??)\s+\w+"));
        if (index < 0) yield break;
        var calls = h.Code.CallersOf(method, hostFile, start + header.Index)
            .Where(c => h.File.Origin == Origin.Tests || c.File.Origin != Origin.Tests).Take(MaxScripts).ToList();
        foreach (var (file, open) in calls)
        {
            // Its own call of the helper that starts PowerShell isn't a caller of it.
            if (file == hostFile && open >= start && open <= hostPosition + 200) continue;
            var args = file.Arguments(open);
            if (index >= args.Count) continue;
            var argument = Tracer.StripNamed(args[index]);
            var at = h.AtCaller(file, open, argument, method + "(script) → PowerShell");
            var t = at.TraceArg(0);
            if (t is null) continue;
            var text = string.Join("\n", t.Literals);
            var commands = PowerShellScript.Commands(text);
            var reasons = new List<string>();
            Legibility legibility;
            if (commands.Count == 0)
            {
                legibility = Legibility.Untraced;
                reasons.Add("The script's commands aren't in the source the scan followed.");
            }
            else if (t.Unresolved.Count > 0 || t.Sources.Any(s => s.Open) || t.Literals.Any(l => l.Contains("{}")))
            {
                legibility = Legibility.PartlyClear;
                reasons.Add("The commands are in the source; parts of the script (names, values) are filled in while it runs.");
            }
            else legibility = Legibility.Clear;
            var notes = new List<string> { $"Run by {method} ({hostFile.Path}:{hostFile.LineOf(hostPosition)}), which starts PowerShell." };
            foreach (var f in flags) notes.Add("PowerShell " + f + ".");
            foreach (var f in PowerShellScript.Flags(text)) notes.Add("The script " + f + ".");
            if (Commands.Describe(text) is { } plain) notes.Insert(0, plain + ".");
            var target = commands.Count == 0 ? "a PowerShell script" : "PowerShell: " + Tracer.Clip(string.Join(", ", commands), 110);
            var summary = commands.Count == 0 ? "Runs a PowerShell script the scan couldn't read." : "Runs a PowerShell script that " + PowerShellScript.Describe(commands) + ".";
            var finding = at.Make(FindingKind.Process, h.DefaultScope, legibility, target, summary, reasons, notes, t);
            finding.Program = "powershell";
            finding.Commands = commands;
            yield return finding;
        }
    }

    /// <summary>The calls of the method around the hit: where a helper like RunPowerShell(script) gets its script.</summary>
    private static string ScriptCallers(Hit h)
    {
        var (hostFile, hostPosition) = h.Binding is { } hb ? (hb.CallFile, hb.CallPosition) : (h.File, h.Position);
        int start = hostFile.MemberStart(hostPosition);
        // The name right before the parameter list that opens the body: not "static" in "static (bool Ok, string Output) Run(…)".
        var header = Regex.Match(hostFile.Masked[start..Math.Min(hostPosition, hostFile.Masked.Length)],
            @"(?<m>[A-Za-z_]\w*)\s*(?:<[^<>()]*>)?\s*\((?:[^()]|\([^()]*\))*\)\s*(?:where\b[^{]*)?(?:\{|=>)");
        if (!header.Success) return "";
        var calls = h.Code.CallersOf(header.Groups["m"].Value, hostFile, start + header.Index)
            .Where(c => h.File.Origin == Origin.Tests || c.File.Origin != Origin.Tests).ToList();
        if (calls.Count == 0) return "";
        var places = calls.Take(4).Select(c => $"{c.File.Path}:{c.File.LineOf(c.Open)}");
        return $"{calls.Count} call{(calls.Count == 1 ? "" : "s")} of {header.Groups["m"].Value} ({string.Join(", ", places)}{(calls.Count > 4 ? ", …" : "")})";
    }

    private static Finding MarkHidden(bool encoded, Finding f)
    {
        if (encoded) { f.HiddenOnPurpose = true; f.HowHidden = "encoded PowerShell"; }
        return f;
    }

    private static IEnumerable<Finding> PowerShellCommand(Hit h)
    {
        var t = h.TraceArg(0);
        if (t is null) yield break;
        var (legibility, reasons) = t.Judge();
        if (t.Unresolved.Count > 0 || t.Literals.Any(l => l.Contains("{}")))
        {
            legibility = Legibility.Opaque;
            reasons.Add("The PowerShell it runs is assembled at run time.");
        }
        var target = Tracer.Clip(t.Literals.FirstOrDefault(l => l.Length > 0) ?? t.Describe(false), 120);
        var plain = Commands.Describe(string.Join(" ", t.Literals));
        var commands = PowerShellScript.Commands(string.Join("\n", t.Literals));
        var notes = new List<string> { "Runs PowerShell inside the app, not as a program of its own." };
        if (commands.Count > 0) notes.Add("The script " + PowerShellScript.Describe(commands) + ".");
        notes.AddRange(PowerShellScript.Flags(string.Join("\n", t.Literals)).Select(f => "The script " + f + "."));
        var made = h.Make(FindingKind.Process, h.DefaultScope, legibility, target, (plain is null ? "Runs PowerShell: " : plain + ": runs PowerShell: ") + target + ".", reasons, notes, t);
        made.Program = "powershell";
        made.Commands = commands;
        yield return made;
    }

    private static IEnumerable<Finding> NetworkCredential(Hit h)
    {
        var user = h.TraceArg(0);
        var password = h.TraceArg(1);
        var (legibility, reasons) = Merge(user, password);
        var userText = user?.Literals.FirstOrDefault(l => l.Length > 0);
        bool unused = h.ResultUnused == true;
        yield return MarkUnused(unused, h.Make(FindingKind.Credential, Scope.WebService, legibility, userText ?? "a user name",
            unused ? "Creates a credential with a user name and password; not used in this source."
                : ToProxy(h) ? "Logs in to the proxy with a user name and password." : "Logs in to a service with a user name and password.",
            reasons, null, password ?? user));
        if (h.Arg(1) is { } p && IsPlainLiteral(p) && p.Trim('"', '@').Length > 0)
            yield return SecretFinding(h, "password", p.Trim('@').Trim('"'));
    }

    /// <summary>
    /// The credential is the proxy's: proxy.Credentials = …, proxy.UseDefaultCredentials = true, on a variable that
    /// is a WebProxy (or plainly named for one).
    /// </summary>
    private static bool ToProxy(Hit h)
    {
        int from = h.File.Text.LastIndexOf('\n', Math.Max(0, h.Position - 1)) + 1;
        int to = Math.Min(h.File.Text.Length, h.Position + h.MatchLength);
        var line = h.File.Text[from..to];
        var receiver = Regex.Match(line, @"(?<r>[A-Za-z_]\w*)\s*\.\s*(?:Credentials|UseDefaultCredentials)\s*=");
        if (!receiver.Success) return Regex.IsMatch(line, @"\bWebProxy\b");
        var name = receiver.Groups["r"].Value;
        return Regex.IsMatch(name, @"(?i)proxy") || h.Code.TypeOfVariable(name, h.File, h.Position) is "WebProxy" or "IWebProxy";
    }

    private static IEnumerable<Finding> Token(Hit h, int arg, string scheme)
    {
        int index = arg >= 0 ? arg : 1;
        var t = h.TraceArg(index);
        var (legibility, reasons) = t?.Judge() ?? (Legibility.PartlyClear, ["The token isn't in the source."]);
        var from = t is null ? "" : t.Sources.FirstOrDefault(s => s.Kind is SourceKind.EnvironmentVariable or SourceKind.Configuration or SourceKind.UserFolder)?.Label ?? "";
        var target = "a " + scheme.Trim() + " credential" + (from.Length > 0 ? " from " + from : "");
        yield return h.Make(FindingKind.Credential, Scope.WebService, legibility, target, "Sends " + target + " to a web service.", reasons, null, t);
        if (h.Arg(index) is { } a && IsPlainLiteral(a) && a.Trim('"', '@', '$').Length >= 8)
            yield return SecretFinding(h, "token", a.Trim('@', '$').Trim('"'));
    }

    private static bool IsPlainLiteral(string arg) => Regex.IsMatch(arg.Trim(), @"^@?""[^""{}]*""$");

    public static string Mask(string secret) =>
        secret.Length <= 4 ? new string('•', secret.Length) : secret[..4] + "… (" + secret.Length + " characters)";

    private static Finding SecretFinding(Hit h, string what, string value) =>
        h.Make(FindingKind.Secret, Scope.WebService, Legibility.Clear, Mask(value), (System.Text.RegularExpressions.Regex.IsMatch(what, "^(?:[aeioAEIO]|SSH\\b|RSA\\b|SAS\\b)") ? "An " : "A ") + what + " is written in the code.",
            null, ["Anyone with the source has it. Rotate it, and keep it outside the code."], call: what);

    private static IEnumerable<Finding> Named(Hit h, FindingKind kind, Scope scope, string verb)
    {
        var t = h.TraceArg(0);
        var (legibility, reasons) = t?.Judge() ?? (Legibility.Clear, new List<string>());
        var target = t is null ? "—" : t.Literals.FirstOrDefault(l => l.Length > 0) ?? t.Describe(false);
        yield return h.Make(kind, scope, legibility, target, verb + " " + target + ".", reasons, null, t);
    }

    private static IEnumerable<Finding> Wmi(Hit h)
    {
        var t = h.Trace(string.Join(", ", h.Args));
        var (legibility, reasons) = t.Judge();
        var query = t.Literals.FirstOrDefault(l => Regex.IsMatch(l, @"(?i)select|win32_|msft_|root\\")) ?? t.Literals.FirstOrDefault(l => l.Length > 0) ?? "a WMI class";
        var scope = Regex.IsMatch(string.Join(" ", t.Literals), @"(?i)Win32_Service|Win32_Process|MSFT_NetFirewall|SecurityCenter|Win32_ShadowCopy|StdRegProv|Win32_UserAccount")
            ? Scope.Admin : Scope.User;
        yield return h.Make(FindingKind.Wmi, scope, legibility, Tracer.Clip(query, 120), "Uses WMI: " + Tracer.Clip(query, 120) + ".", reasons, null, t);
    }

    private static IEnumerable<Finding> Com(Hit h)
    {
        var t = h.TraceArg(0);
        var progId = t?.Literals.FirstOrDefault(l => l.Length > 0);
        if (progId is null)
        {
            yield return h.Make(FindingKind.Com, h.DefaultScope, Legibility.Opaque, "a COM class named at run time", "Creates a COM object named at run time.",
                ["Which program it drives depends on a name computed at run time."], null, t);
            yield break;
        }
        var (scope, what, note) = progId switch
        {
            var p when p.StartsWith("HNetCfg.", StringComparison.OrdinalIgnoreCase) => (Scope.Admin, "Windows Firewall", null),
            var p when p.StartsWith("Schedule.Service", StringComparison.OrdinalIgnoreCase) => (Scope.Admin, "Task Scheduler", "Scheduled tasks can start programs later and as other accounts."),
            var p when p.StartsWith("Microsoft.Update", StringComparison.OrdinalIgnoreCase) => (Scope.Admin, "Windows Update", null),
            var p when p.StartsWith("WScript.Shell", StringComparison.OrdinalIgnoreCase) => (h.DefaultScope, "Windows Script Host shell", "Can run commands and change the registry."),
            var p when p.StartsWith("Shell.Application", StringComparison.OrdinalIgnoreCase) => (h.DefaultScope, "the Windows shell", null),
            var p when p.StartsWith("WbemScripting", StringComparison.OrdinalIgnoreCase) => (h.DefaultScope, "WMI", null),
            _ => (h.DefaultScope, progId, (string?)null)
        };
        var (legibility, reasons) = t!.Judge();
        // Can versus does: looking the type up isn't driving it. Only creating an object from it is.
        var after = h.VariableAfter();
        bool creates = after is { } a && Regex.IsMatch(a.After, @"\b(?:Activator\s*\.\s*CreateInstance|CreateInstance)\s*\(\s*" + Regex.Escape(a.Name) + @"\b");
        var summary = creates ? "Drives " + what + " through COM (" + progId + ")."
            : after is { Used: false } ? "Looks up the COM type for " + what + " (" + progId + "); not used in this source."
            : "Looks up the COM type for " + what + " (" + progId + ").";
        yield return MarkUnused(after is { Used: false }, h.Make(FindingKind.Com, scope, legibility, progId, summary, reasons,
            note is null ? null : [note], t));
    }

    private enum ReflectionKind { Type, Member, Create }

    private static IEnumerable<Finding> Reflection(Hit h, ReflectionKind kind)
    {
        bool creates = kind == ReflectionKind.Create;
        var a = h.Arg(0);
        if (a is null) yield break;
        if (Regex.IsMatch(a, @"^\s*(?:typeof|nameof)\s*\(")) yield break; // compile-time names: nothing hidden
        if (h.Call.StartsWith("Activator") && a.StartsWith("typeof", StringComparison.Ordinal)) yield break;

        var t = h.Trace(a);
        var (legibility, reasons) = t.Judge();
        // A name hidden but fixed in the source (new string(new[] { 'S', … }) + ".Diagnostics.Process") is worked out.
        var name = t.Decoded.Count > 0 ? t.Decoded[^1].Value : t.NearLiterals.FirstOrDefault();
        if (t.Unresolved.Count > 0 || name is null || name.Contains("{}"))
        {
            legibility = Legibility.Opaque;
            // Why it's opaque comes first; what the trace found on the way follows.
            reasons.Insert(0, creates
                ? "The type it creates is decided at run time, so what runs can't be read in the source."
                : "The name it looks up is computed at run time, so what runs can't be read in the source.");
        }
        bool computed = legibility == Legibility.Opaque && (name is null || name.Contains("{}"));
        var target = computed ? (creates ? "a type chosen at run time" : "a name computed at run time") : name ?? t.Describe(false);

        // current = new Config(); current.GetType().GetProperty(name): whatever the name, it can only reach the app's
        // own type, made right there, and the types its properties declare, all the app's own. The source shows what
        // can happen; which one is picked while it runs. Nothing hidden, nothing from outside: Run time, not Opaque.
        string? bounded = null;
        if (computed && kind != ReflectionKind.Type && t.Decoded.Count == 0 && t.OpaqueReasons.Count == 0
            && ReachTypes(h) is { Own.Count: > 0, Other.Count: 0, Any: false } reach && h.Code.ReachableOwnTypes(reach.Own) is { } reachable)
        {
            legibility = Legibility.PartlyClear;
            reasons.RemoveAt(0);
            var owner = string.Join(", ", reach.Own.Take(2));
            var names = t.Unresolved.Select(u => Regex.Match(u, @"one of (?<n>\d+) values")).FirstOrDefault(m => m.Success)?.Groups["n"].Value;
            reasons.Insert(0, $"The name is picked while it runs{(names is null ? "" : $", one of {names} written in the source")}, but it can only reach {owner}, "
                              + $"made in this method, and the {reachable.Count - reach.Own.Count} type{(reachable.Count - reach.Own.Count == 1 ? "" : "s")} its properties declare, all the app's own.");
            target = creates ? $"a type {owner}'s properties declare" : $"a property of {owner}, by name";
            bounded = creates ? $"Creates an object of a type {owner}'s properties declare."
                : $"Looks up a property of {owner} by name{(names is null ? "" : $" (one of {names} names written in the source)")}.";
        }
        var summary = bounded ?? (kind, computed) switch
        {
            (ReflectionKind.Create, true) => "Creates an object of a type chosen at run time.",
            (ReflectionKind.Member, true) => "Looks up a member by a name computed at run time.",
            (ReflectionKind.Type, true) => "Looks up a type by a name computed at run time.",
            (ReflectionKind.Create, false) => $"Creates an instance of {target} by name.",
            (ReflectionKind.Member, false) => $"Looks up the member {target} by name.",
            _ => $"Looks up the type {target} by name."
        };
        // var m = t.GetMethod("Start"): looked up, never invoked here. Something it can do, not something it does.
        bool unused = h.ResultUnused == true;
        if (unused) summary = summary.TrimEnd('.') + "; not used in this source.";
        var made = MarkUnused(unused, h.Make(FindingKind.Reflection, h.DefaultScope, legibility, target, summary, reasons, null, t));
        made.LooksInside = ReflectionReach(h, kind);
        yield return made;
    }

    private static readonly Regex AnyType = new(@"\bType\s*\.\s*GetType\s*\(|\bAssembly\s*\.\s*(?:Load\w*|GetType|GetExecutingAssembly|GetEntryAssembly)\b|\.GetTypes\s*\(\s*\)|\bAppDomain\b|\bAssembly\s*\.\s*Load", RegexOptions.Compiled);

    /// <summary>
    /// How far a reflection call can reach, from what it looks inside: the repo's own types
    /// (current.GetType() with current = new Config()), a .NET type (typeof(Process)), or any type at all
    /// (Type.GetType(name)). Null when the source doesn't show it.
    /// </summary>
    private static string? ReflectionReach(Hit h, ReflectionKind kind)
    {
        var (own, other, any) = ReachTypes(h);
        if (own.Count > 0 && other.Count == 0 && !any)
            return $"Only the app's own types ({string.Join(", ", own.Take(3))}) and what they contain"
                   + (kind == ReflectionKind.Create ? "; it can only create types those declare." : ".");
        if (any || h.Call.Contains("Type.GetType", StringComparison.Ordinal) || h.Call.StartsWith("Assembly", StringComparison.Ordinal))
            return "Any type it's given by name, including Windows' and .NET's own (such as Process or Registry).";
        if (other.Count > 0)
            return $"{string.Join(", ", other.Take(3))}, from .NET or a package" + (own.Count > 0 ? $", and the app's own {string.Join(", ", own.Take(3))}." : ".");
        return null;
    }

    /// <summary>The types a reflection call looks inside: the app's own, others, and whether it can be any type at all.</summary>
    private static (List<string> Own, List<string> Other, bool Any) ReachTypes(Hit h)
    {
        int start = h.File.MemberStart(h.Position);
        var body = h.File.Masked[start..Math.Min(h.File.Masked.Length, h.Position + 300)];
        var types = new List<string>();
        foreach (Match g in Regex.Matches(body, @"(?<v>[A-Za-z_]\w*)\s*\.\s*GetType\s*\(\s*\)"))
            foreach (Match n in Regex.Matches(body, $@"\b{Regex.Escape(g.Groups["v"].Value)}\s*=\s*new\s+(?<t>[A-Z][\w.]*)\s*[({{]"))
                types.Add(n.Groups["t"].Value);
        // typeof(X) looked inside (typeof(X).GetProperty, Activator.CreateInstance(typeof(X))), not a type check like IsAssignableFrom.
        foreach (Match t in Regex.Matches(body, @"\btypeof\s*\(\s*(?<t>[A-Z][\w.]*)\s*\)(?=\s*\.\s*Get(?:Property|Properties|Method|Methods|Field|Fields|Member|Members|Constructor)\b|\s*[,)])(?<!IsAssignableFrom\s*\(\s*typeof\s*\(\s*\k<t>\s*\))"))
            types.Add(t.Groups["t"].Value);
        types = types.Select(t => t[(t.LastIndexOf('.') + 1)..]).Distinct().ToList();
        var own = types.Where(t => h.Code.DeclaresType(t)).ToList();
        var other = types.Except(own).ToList();
        bool any = AnyType.IsMatch(body) || h.Call.Contains("Type.GetType", StringComparison.Ordinal) || h.Call.StartsWith("Assembly", StringComparison.Ordinal);
        return (own, other, any);
    }

    private static IEnumerable<Finding> LoadCode(Hit h)
    {
        var a = h.Arg(0);
        var t = a is null ? null : h.Trace(a);
        var (legibility, reasons) = t?.Judge() ?? (Legibility.Opaque, new List<string>());
        bool bytes = a is not null && (Regex.IsMatch(a, @"(?i)bytes|\bbuffer\b|stream|ReadAllBytes|FromBase64") || h.Call.EndsWith("LoadFromStream"));
        if (bytes || t is null || t.Literals.Count == 0)
        {
            legibility = Legibility.Opaque;
            reasons.Add("Loads code from bytes or a name computed at run time: what runs isn't in this source.");
        }
        else if (legibility == Legibility.Clear)
        {
            legibility = Legibility.PartlyClear;
            reasons.Add("The code it loads lives outside this source.");
        }
        var target = t?.Describe() ?? "code from memory";
        var kind = h.Call.StartsWith("NativeLibrary") ? FindingKind.NativeCode : FindingKind.LoadsCode;
        yield return h.Make(kind, h.DefaultScope, legibility, target, "Loads code: " + target + ".", reasons, null, t);
    }

    private static IEnumerable<Finding> EnvironmentWrite(Hit h)
    {
        var target = h.Args.Count > 2 ? h.Args[2] : "";
        var (scope, where) = target.Contains("Machine") ? (Scope.Admin, "for the whole machine")
            : target.Contains("User") ? (Scope.User, "for the user, kept after the app closes")
            : (Scope.App, "for this process only");
        var name = h.TraceArg(0);
        var (legibility, reasons) = name?.Judge() ?? (Legibility.Clear, new List<string>());
        var label = name?.Literals.FirstOrDefault(l => l.Length > 0) ?? h.Arg(0) ?? "a variable";
        yield return h.Make(FindingKind.Environment, scope, legibility, label, "Sets the environment variable " + label + " " + where + ".", reasons, null, name);
    }

    private static bool IsDeclaration(Hit h) =>
        Regex.IsMatch(h.File.LineText(h.File.LineOf(h.Position)), @"\bextern\b|\bpartial\b.*\(.*\)\s*;");

    /// <summary>The less legible of two traces, with both sets of reasons.</summary>
    private static (Legibility, List<string>) Merge(Tracer? a, Tracer? b)
    {
        var ja = a?.Judge() ?? (Legibility.Clear, new List<string>());
        var jb = b?.Judge() ?? (Legibility.Clear, new List<string>());
        var worst = (Legibility)Math.Max((int)ja.Item1, (int)jb.Item1);
        return (worst, ja.Item2.Concat(jb.Item2).Distinct().ToList());
    }
}
