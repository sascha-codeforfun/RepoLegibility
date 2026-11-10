using System.IO;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using CSharpLexing;

namespace RepoLegibility.Core;

/// <summary>
/// The scans that don't follow a call: the manifest, P/Invoke declarations, data embedded in the
/// code, secrets written in it, the web addresses it names, build steps and CI workflows.
/// </summary>
public static class TextScan
{
    private static Finding Make(string file, int line, Origin origin, string? project, FindingKind kind, Scope scope, Legibility legibility,
        string call, string target, string summary, IEnumerable<string>? reasons = null, IEnumerable<string>? notes = null) => new()
        {
            Kind = kind,
            Scope = scope,
            Legibility = legibility,
            Origin = origin,
            File = file,
            Line = line,
            Call = call,
            Target = target,
            Summary = summary,
            Reasons = reasons?.ToList() ?? [],
            Notes = notes?.ToList() ?? [],
            Project = project
        };

    private static int LineOf(string text, int index) => text.AsSpan(0, Math.Min(index, text.Length)).Count('\n') + 1;

    // ---- elevation ----------------------------------------------------------------------------

    /// <summary>requestedExecutionLevel in any app manifest: requireAdministrator or highestAvailable.</summary>
    public static List<Finding> Manifests(IReadOnlyList<RepoFile> files, IReadOnlyList<ProjectFile> projects, Func<string, Origin> origin)
    {
        var found = new List<Finding>();
        foreach (var file in files.Where(f => f.Text is not null && (f.Extension == ".manifest" || projects.Any(p => p.Manifest == f.Path))))
        {
            var m = Regex.Match(file.Text!, @"requestedExecutionLevel\s+[^>]*level\s*=\s*""(?<l>requireAdministrator|highestAvailable)""", RegexOptions.IgnoreCase);
            if (!m.Success) continue;
            var level = m.Groups["l"].Value;
            bool always = level.Equals("requireAdministrator", StringComparison.OrdinalIgnoreCase);
            found.Add(Make(file.Path, LineOf(file.Text!, m.Index), origin(file.Path), ProjectScan.Owner(projects, file.Path)?.Name,
                FindingKind.Elevation, Scope.Admin, Legibility.Clear, "requestedExecutionLevel " + level, "the whole app",
                always ? "Always runs as administrator: Windows asks for elevation on every start."
                       : "Runs as administrator whenever the user is one.",
                notes: [(always ? "Everything this app runs or loads runs as administrator" : "Whenever the user is an administrator, everything this app runs or loads runs as one")
                        + "; files and keys it writes keep the scope of where they are."]));
        }
        return found;
    }

    // ---- native code --------------------------------------------------------------------------

    private static readonly Regex PInvoke = new(
        @"\[\s*(?:DllImport|LibraryImport)\s*\(\s*(?<lib>@?""[^""]*""|[^,)\]]+)(?<rest>[^\]]*)\]\s*(?:\[[^\]]*\]\s*)*(?:(?:public|private|internal|protected|static|extern|partial|unsafe|new)\s+)+[\w<>\[\],.?*\s]+?\s+(?<name>[A-Za-z_]\w*)\s*\(",
        RegexOptions.Compiled);

    private static readonly HashSet<string> AdminApis = new(StringComparer.OrdinalIgnoreCase)
    {
        "AdjustTokenPrivileges", "OpenProcessToken", "LookupPrivilegeValue", "LookupPrivilegeValueW", "WriteProcessMemory", "ReadProcessMemory",
        "VirtualAllocEx", "CreateRemoteThread", "OpenProcess", "NtSetInformationProcess", "RtlSetProcessIsCritical", "MiniDumpWriteDump",
        "CreateService", "CreateServiceW", "OpenSCManager", "OpenSCManagerW", "ChangeServiceConfig", "ChangeServiceConfigW", "StartService",
        "DeleteService", "InitiateSystemShutdown", "InitiateSystemShutdownEx", "ExitWindowsEx", "SetSystemTime", "LsaOpenPolicy",
        "LsaAddAccountRights", "NetUserAdd", "NetLocalGroupAddMembers", "DeviceIoControl", "SetFileSecurity", "SetNamedSecurityInfo",
        "SetSecurityInfo", "DuplicateTokenEx", "CreateProcessAsUser", "CreateProcessWithTokenW", "NtLoadDriver", "ZwLoadDriver"
    };

    private static readonly Dictionary<string, string> Watched = new(StringComparer.OrdinalIgnoreCase)
    {
        ["SetWindowsHookEx"] = "can observe keyboard or mouse input system-wide",
        ["SetWindowsHookExW"] = "can observe keyboard or mouse input system-wide",
        ["GetAsyncKeyState"] = "can read the keyboard state",
        ["SendInput"] = "can type and click as if the user did",
        ["keybd_event"] = "can type as if the user did",
        ["mouse_event"] = "can click as if the user did",
        ["WriteProcessMemory"] = "writes into another process",
        ["ReadProcessMemory"] = "reads another process's memory",
        ["CreateRemoteThread"] = "runs code inside another process",
        ["VirtualAllocEx"] = "allocates memory in another process",
        ["MiniDumpWriteDump"] = "can dump another process's memory",
        ["CredRead"] = "reads Windows Credential Manager",
        ["CredReadW"] = "reads Windows Credential Manager",
        ["BlockInput"] = "can block the user's keyboard and mouse",
        ["ShellExecute"] = "starts programs",
        ["ShellExecuteW"] = "starts programs",
        ["ShellExecuteEx"] = "starts programs",
        ["CreateProcess"] = "starts programs",
        ["CreateProcessW"] = "starts programs",
        ["WinExec"] = "starts programs",
        ["URLDownloadToFile"] = "downloads files from the internet",
        ["SHOpenWithDialog"] = "shows Windows' Open with dialog; the app the user chooses starts with the file, and \"Always\" makes it the default for that file type",
        ["RegLoadKey"] = "mounts a hive file under HKLM or HKU, for everyone on the computer, until it's unloaded",
        ["RegLoadKeyW"] = "mounts a hive file under HKLM or HKU, for everyone on the computer, until it's unloaded",
        ["RegLoadAppKey"] = "opens a hive file privately, for this process only",
        ["RegLoadAppKeyW"] = "opens a hive file privately, for this process only",
        ["RegSaveKey"] = "saves a registry key and everything under it to a file",
        ["RegSaveKeyW"] = "saves a registry key and everything under it to a file",
        ["RegSaveKeyEx"] = "saves a registry key and everything under it to a file",
        ["RegSaveKeyExW"] = "saves a registry key and everything under it to a file",
        ["RegRestoreKey"] = "overwrites a registry key with the contents of a file",
        ["RegRestoreKeyW"] = "overwrites a registry key with the contents of a file",
        ["RegReplaceKey"] = "replaces a registry hive file at the next start",
        ["RegReplaceKeyW"] = "replaces a registry hive file at the next start",
        ["AdjustTokenPrivileges"] = "turns privileges of the process on or off",
        ["WIMExtractImagePath"] = "extracts files from a Windows image (.wim)",
        ["WIMApplyImage"] = "applies a whole Windows image (.wim) to a folder or drive",
        ["WIMMountImage"] = "mounts a Windows image (.wim) into a folder"
    };

    private static readonly HashSet<string> LookOnly = new(StringComparer.OrdinalIgnoreCase)
    {
        "dwmapi", "dwmapi.dll", "uxtheme", "uxtheme.dll", "shcore", "shcore.dll"
    };

    private sealed record Declaration(CodeFile File, int Index, string Lib, bool Literal, string Name, bool Called, Scope Scope);

    /// <summary>
    /// Native functions, one finding per library (per app or tests): "advapi32.dll: 14 functions, 3 not
    /// called", with each function and where it's declared in the notes, so it can be searched for.
    /// </summary>
    public static List<Finding> PInvokes(IReadOnlyList<CodeFile> code, bool elevated, out int count)
    {
        var declared = new List<Declaration>();
        foreach (var file in code)
        {
            foreach (Match m in PInvoke.Matches(file.Text))
            {
                if (file.Masked[m.Index] != file.Text[m.Index]) continue;
                var libRaw = m.Groups["lib"].Value.Trim();
                bool literal = libRaw.StartsWith('"') || libRaw.StartsWith("@\"", StringComparison.Ordinal);
                var lib = literal ? libRaw.Trim('@').Trim('"') : libRaw;
                // kernel32 and kernel32.dll are one library.
                if (literal && !Path.HasExtension(lib)) lib += ".dll";
                var entry = Regex.Match(m.Groups["rest"].Value, @"EntryPoint\s*=\s*""(?<e>[^""]+)""").Groups["e"].Value;
                var name = entry.Length > 0 ? entry : m.Groups["name"].Value;
                var scope = AdminApis.Contains(name) ? Scope.Admin
                    : LookOnly.Contains(lib) ? Scope.App
                    : elevated ? Scope.Admin : Scope.User;
                // Declared isn't called: count calls of the declared method anywhere in the C#.
                var method = m.Groups["name"].Value;
                var call = new Regex(@"(?<![\w])" + Regex.Escape(method) + @"\s*\(");
                bool called = code.Any(c => call.Matches(c.Masked).Any(x =>
                    !(c == file && Math.Abs(x.Index - m.Index) < m.Length + 200 && c.Masked.LastIndexOf("extern", x.Index, StringComparison.Ordinal) > c.Masked.LastIndexOf(';', Math.Max(0, x.Index - 1)))));
                declared.Add(new Declaration(file, m.Index, lib, literal, name, called, scope));
            }
        }
        count = declared.Count;

        var found = new List<Finding>();
        foreach (var group in declared.GroupBy(d => (d.File.Origin, Lib: d.Lib.ToLowerInvariant(), d.Literal)).OrderBy(g => g.Key.Lib, StringComparer.Ordinal))
        {
            var all = group.OrderBy(d => d.File.Path, StringComparer.Ordinal).ThenBy(d => d.Index).ToList();
            var first = all[0];
            var lib = first.Lib;
            var unused = all.Where(d => !d.Called).ToList();
            var scope = all.Max(d => d.Scope);
            var names = all.Select(d => d.Name).Distinct().ToList();

            var notes = new List<string>();
            foreach (var d in all)
                if (Watched.TryGetValue(d.Name, out var watch)) notes.Add(all.Count == 1 ? $"Watch: {watch}." : $"Watch: {d.Name}: {watch}.");
            if (LookOnly.Contains(lib)) notes.Add("Window appearance only.");
            string Where(Declaration d) => $"{d.Name} ({d.File.Path}:{d.File.LineOf(d.Index)})";
            var calledOnes = all.Where(d => d.Called).ToList();
            // One function: the finding's own place and summary say it all.
            if (all.Count == 1) calledOnes.Clear();
            if (calledOnes.Count > 0) notes.Add("Called: " + string.Join(", ", calledOnes.Select(Where)) + ".");
            if (unused.Count > 0 && all.Count > 1) notes.Add("Declared, not called: " + string.Join(", ", unused.Select(Where)) + ".");

            var legibility = first.Literal ? Legibility.Clear : Legibility.Opaque;
            var reasons = first.Literal ? new List<string>() : ["The library's name is computed, so which native code runs isn't in the source."];
            string summary;
            if (names.Count == 1)
                summary = unused.Count == 0 ? $"Calls the native function {names[0]} in {lib}."
                                            : $"Declares the native function {names[0]} in {lib}; not called in this source.";
            else
                summary = $"Declares {names.Count} native functions in {lib}" + (unused.Count == 0 ? "; all are called."
                    : unused.Count == all.Count ? "; none is called in this source." : $"; {unused.Count} not called in this source.");
            var target = lib + " › " + (names.Count == 1 ? names[0] : $"{names.Count} functions: " + Tracer.Clip(string.Join(", ", names), 100));
            var native = Make(first.File.Path, first.File.LineOf(first.Index), first.File.Origin, first.File.Project?.Name, FindingKind.NativeCode, scope, legibility,
                "[DllImport] " + lib + (names.Count == 1 ? " " + names[0] : $" ({names.Count} functions)"), target, summary, reasons, notes);
            native.Unused = unused.Count == all.Count;
            found.Add(native);
        }
        return found;
    }

    public static int UnsafeBlocks(IReadOnlyList<CodeFile> code) =>
        code.Sum(f => Regex.Matches(f.Masked, @"\bunsafe\b").Count);

    // ---- embedded data ------------------------------------------------------------------------

    private static readonly Dictionary<string, string> PrivilegeMeaning = new(StringComparer.Ordinal)
    {
        ["SeBackupPrivilege"] = "reads any file or registry key, past its permissions",
        ["SeRestorePrivilege"] = "writes any file or registry key, past its permissions",
        ["SeDebugPrivilege"] = "opens any process, including the system's, to read or change it",
        ["SeTakeOwnershipPrivilege"] = "takes ownership of any file, key or object",
        ["SeLoadDriverPrivilege"] = "loads and unloads drivers",
        ["SeTcbPrivilege"] = "acts as part of the operating system",
        ["SeSecurityPrivilege"] = "reads and clears the security log and audit settings",
        ["SeImpersonatePrivilege"] = "acts as another user it has a token for",
        ["SeAssignPrimaryTokenPrivilege"] = "starts processes as another user",
        ["SeCreateTokenPrivilege"] = "creates logon tokens of any kind",
        ["SeManageVolumePrivilege"] = "reads and changes disks below the file system",
        ["SeSystemEnvironmentPrivilege"] = "changes firmware (UEFI) variables",
        ["SeShutdownPrivilege"] = "shuts down or restarts the computer",
        ["SeRemoteShutdownPrivilege"] = "shuts down the computer from the network",
        ["SeSystemtimePrivilege"] = "changes the system time",
        ["SeIncreaseQuotaPrivilege"] = "changes the memory quotas of processes",
        ["SeCreateSymbolicLinkPrivilege"] = "creates symbolic links"
    };

    /// <summary>
    /// Privileges the code turns on (AdjustTokenPrivileges with "SeBackupPrivilege", …): one finding per file that
    /// names them, each with what it lets the process do. Named but never turned on (no AdjustTokenPrivileges or
    /// RtlAdjustPrivilege anywhere) isn't a finding.
    /// </summary>
    public static List<Finding> Privileges(IReadOnlyList<CodeFile> code)
    {
        var found = new List<Finding>();
        bool adjusts = code.Any(f => Regex.IsMatch(f.Masked, @"\b(?:AdjustTokenPrivileges|RtlAdjustPrivilege)\b"));
        if (!adjusts) return found;
        foreach (var file in code)
        {
            var hits = Regex.Matches(file.Text, @"""(?<p>Se[A-Za-z]+Privilege)""")
                .Where(m => file.Masked[m.Index] != file.Text[m.Index] && PrivilegeMeaning.ContainsKey(m.Groups["p"].Value)).ToList();
            if (hits.Count == 0) continue;
            var names = hits.Select(m => m.Groups["p"].Value).Distinct().ToList();
            var meaning = string.Join("; ", names.Select(n => $"{n} {PrivilegeMeaning[n]}"));
            var finding = Make(file.Path, file.LineOf(hits[0].Index), file.Origin, file.Project?.Name, FindingKind.Identity, Scope.Admin, Legibility.Clear,
                "AdjustTokenPrivileges", string.Join(", ", names),
                $"Turns on {string.Join(" and ", names)}: {meaning}.", [],
                ["Only an administrator holds these; turning them on lets this process go past the usual permissions."]);
            found.Add(finding);
        }
        return found;
    }

    public static List<Finding> EmbeddedData(IReadOnlyList<CodeFile> code)
    {
        var found = new List<Finding>();
        foreach (var file in code)
        {
            foreach (var literal in CSharpLexer.Literals(file.Original))
            {
                var text = literal.Text(file.Original);
                if (text.Length < 40) continue;
                var compact = Regex.Replace(text, @"\s+", "");
                bool base64 = compact.Length >= 40 && Regex.IsMatch(compact, @"^[A-Za-z0-9+/]+={0,2}$") && Regex.IsMatch(compact, @"\d") && Regex.IsMatch(compact, "[A-Z]") && Regex.IsMatch(compact, "[a-z]");
                if (!base64) continue;
                // Long ones are data in any case; shorter ones only where they're decoded.
                var after = file.Text.Substring(Math.Max(0, literal.Start - 60), Math.Min(60, literal.Start));
                bool decoded = Regex.IsMatch(after, @"FromBase64String\s*\(\s*$");
                if (compact.Length < 200 && !decoded) continue;
                found.Add(Make(file.Path, file.LineOf(literal.Start), file.Origin, file.Project?.Name, FindingKind.EmbeddedData, Scope.App, Legibility.Opaque,
                    decoded ? "Convert.FromBase64String" : "string literal", $"Base64 data, {compact.Length:N0} characters",
                    $"Holds {compact.Length:N0} characters of Base64 data{(decoded ? " and decodes it" : "")}.",
                    ["What the data is can't be read without decoding it; check what the code does with it."]));
            }

            foreach (Match m in Regex.Matches(file.Masked, @"new\s+(?:byte|sbyte)\s*\[\s*\d*\s*\]\s*\{"))
            {
                int end = file.MatchingBrace(m.Index + m.Length - 1);
                if (end < 0) continue;
                int items = file.Masked[(m.Index + m.Length)..end].Count(c => c == ',') + 1;
                if (items < 64) continue;
                found.Add(Make(file.Path, file.LineOf(m.Index), file.Origin, file.Project?.Name, FindingKind.EmbeddedData, Scope.App, Legibility.Opaque,
                    "new byte[]", $"{items:N0} bytes of binary data", $"Holds {items:N0} bytes of binary data in the code.",
                    ["Binary data in the source can hide code or text; check what the code does with it."]));
            }
        }
        return found;
    }

    // ---- secrets ------------------------------------------------------------------------------

    private static readonly (Regex Pattern, string What)[] TokenPatterns =
    [
        (new(@"\bgh[pousr]_[A-Za-z0-9]{36,}\b", RegexOptions.Compiled), "GitHub token"),
        (new(@"\bgithub_pat_[A-Za-z0-9_]{50,}\b", RegexOptions.Compiled), "GitHub token"),
        (new(@"\bAKIA[0-9A-Z]{16}\b", RegexOptions.Compiled), "AWS access key"),
        (new(@"\bxox[abprs]-[A-Za-z0-9-]{10,}\b", RegexOptions.Compiled), "Slack token"),
        (new(@"\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}\b", RegexOptions.Compiled), "API key (sk-…)"),
        (new(@"\bAIza[0-9A-Za-z_-]{35}\b", RegexOptions.Compiled), "Google API key"),
        (new(@"\bglpat-[A-Za-z0-9_-]{20,}\b", RegexOptions.Compiled), "GitLab token"),
        (new(@"\bnpm_[A-Za-z0-9]{36}\b", RegexOptions.Compiled), "npm token"),
        (new(@"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----", RegexOptions.Compiled), "private key"),
        (new(@"(?i)\bAccountKey=[A-Za-z0-9+/=]{40,}", RegexOptions.Compiled), "Azure storage key"),
        (new(@"(?i)\bSharedAccessSignature=|[?&]sig=[A-Za-z0-9%+/=]{30,}", RegexOptions.Compiled), "Azure shared access signature")
    ];

    private static readonly Regex NamedSecretCode = new(
        @"(?i)\b(?<n>\w*(?:password|passwd|pwd|secret|apikey|api_key|accesstoken|access_token|authtoken|auth_token|clientsecret|client_secret|privatekey|private_key|bearer)\w*)\s*(?:=|:)\s*@?""(?<v>[^""\r\n]{6,})""",
        RegexOptions.Compiled);

    private static readonly Regex NamedSecretData = new(
        @"(?i)""(?<n>[^""]*(?:password|passwd|pwd|secret|apikey|api_key|token|clientsecret)[^""]*)""\s*:\s*""(?<v>[^""\r\n]{6,})""",
        RegexOptions.Compiled);

    private static readonly Regex ConnectionPassword = new(@"(?i)\b(?:password|pwd)\s*=\s*(?<v>[^;""'\s]{4,})", RegexOptions.Compiled);

    private static readonly Regex Placeholder = new(
        @"(?i)^(?:your|example|sample|changeme|change_me|placeholder|dummy|test|xxx+|\*+|<|\{|\$\(|\$\{|%|todo|none|null|password|secret|token)|\s",
        RegexOptions.Compiled);

    private static readonly HashSet<string> SecretFiles = new(StringComparer.OrdinalIgnoreCase)
    {
        ".cs", ".json", ".config", ".xml", ".yml", ".yaml", ".props", ".targets", ".csproj", ".ps1", ".psm1", ".sh", ".cmd", ".bat",
        ".ini", ".env", ".toml", ".js", ".ts", ".py", ".pubxml", ".user", ".settings"
    };

    public static List<Finding> Secrets(IReadOnlyList<RepoFile> files, Func<string, Origin> origin, Func<string, string?> project)
    {
        var found = new List<Finding>();
        foreach (var file in files.Where(f => f.Text is not null && (SecretFiles.Contains(f.Extension) || f.Name.StartsWith(".env", StringComparison.OrdinalIgnoreCase))))
        {
            var text = file.Extension == ".cs" ? CSharpLexer.BlankComments(file.Text!) : file.Text!;
            var seen = new HashSet<int>();

            void Add(int index, string what, string value)
            {
                int line = LineOf(text, index);
                if (!seen.Add(line)) return;
                found.Add(Make(file.Path, line, origin(file.Path), project(file.Path), FindingKind.Secret, Scope.WebService, Legibility.Clear,
                    what, Mask(value), (System.Text.RegularExpressions.Regex.IsMatch(what, "^(?:[aeioAEIO]|SSH\\b|RSA\\b|SAS\\b)") ? "An " : "A ") + what + " is written in the repo.", null,
                    ["Anyone with the source has it. Rotate it, and keep it outside the code."]));
            }

            foreach (var (pattern, what) in TokenPatterns)
                foreach (Match m in pattern.Matches(text))
                    Add(m.Index, what, m.Value);

            var named = file.Extension == ".cs" ? NamedSecretCode : NamedSecretData;
            foreach (Match m in named.Matches(text))
            {
                var v = m.Groups["v"].Value;
                if (Placeholder.IsMatch(v) || v.Contains("{0}") || Regex.IsMatch(v, @"^[\w ]+$") && v.Contains(' ')) continue;
                if (Regex.IsMatch(m.Groups["n"].Value, @"(?i)char|box|label|field|hint|prompt|text|message|policy|length|required|reset|changed|header|name|path|file|url|uri|endpoint|type|mode|kind|format|id$")) continue;
                Add(m.Index, "secret (" + m.Groups["n"].Value + ")", v);
            }

            foreach (Match m in ConnectionPassword.Matches(text))
            {
                var v = m.Groups["v"].Value;
                if (Placeholder.IsMatch(v)) continue;
                // Only inside something that looks like a connection string.
                var around = text.Substring(Math.Max(0, m.Index - 200), Math.Min(200, m.Index));
                if (!Regex.IsMatch(around, @"(?i)(?:server|data source|host|user id|uid)\s*=")) continue;
                Add(m.Index, "database password", v);
            }
        }
        return found;
    }

    public static string Mask(string secret) =>
        secret.Length <= 4 ? new string('•', secret.Length) : secret[..4] + "… (" + secret.Length + " characters)";

    // ---- endpoints ----------------------------------------------------------------------------

    private static readonly Regex Url = new(@"\b(?:https?|wss?|ftps?)://[^\s""'<>)\]\\{}]+", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex Ignored = new(
        @"(?i)^(?:schemas\.microsoft\.com|schemas\.openxmlformats\.org|www\.w3\.org|w3\.org|json-schema\.org|purl\.org|schemas\.xmlsoap\.org|ns\.adobe\.com|tempuri\.org|xml\.org|opensource\.org|creativecommons\.org|www\.apache\.org|aka\.ms|go\.microsoft\.com|learn\.microsoft\.com|docs\.microsoft\.com|github\.com/dotnet|example\.(?:com|org|net)|localhost|127\.0\.0\.1)$",
        RegexOptions.Compiled);

    private static readonly HashSet<string> EndpointFiles = new(StringComparer.OrdinalIgnoreCase)
    {
        ".json", ".config", ".xml", ".yml", ".yaml", ".props", ".targets", ".csproj", ".ps1", ".sh", ".cmd", ".bat", ".ini", ".env", ".toml"
    };

    /// <summary>Web addresses the code and its configuration name, by host. Comments, docs and XML namespaces don't count.</summary>
    public static List<Endpoint> Endpoints(IReadOnlyList<RepoFile> files, IReadOnlyList<CodeFile> code)
    {
        var byUrl = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        void Add(string url, string where)
        {
            url = url.TrimEnd('.', ',', ';', ':', '/');
            if (!byUrl.TryGetValue(url, out var list)) byUrl[url] = list = new List<string>();
            if (list.Count < 5 && !list.Contains(where)) list.Add(where);
        }

        foreach (var file in code)
            foreach (var literal in CSharpLexer.Literals(file.Original))
            {
                // XNamespace ns = "http://…", XNamespace.Get("…"), AddNamespace("x", "…"): an XML namespace, a name.
                var lead = file.Original[Math.Max(0, literal.Start - 60)..literal.Start];
                if (NamespaceUse.IsMatch(lead)) continue;
                var text = literal.Text(file.Original);
                foreach (Match m in Url.Matches(text))
                {
                    // "<urlset xmlns=\"http://www.sitemaps.org/…\"": a namespace written into the XML.
                    var before = text[Math.Max(0, m.Index - 30)..m.Index];
                    if (Regex.IsMatch(before, @"xmlns(?::\w+)?\s*=\s*\\?[""']$|schemaLocation\s*=\s*\\?[""']$")) continue;
                    Add(m.Value, $"{file.Path}:{file.LineOf(literal.Start)}");
                }
            }

        foreach (var file in files.Where(f => f.Text is not null && EndpointFiles.Contains(f.Extension)))
        {
            var text = Regex.Replace(file.Text!, @"<!--.*?-->", m => new string(' ', m.Length), RegexOptions.Singleline);
            foreach (Match m in Url.Matches(text))
            {
                // XML namespaces and schema references aren't calls.
                var before = text.Substring(Math.Max(0, m.Index - 30), Math.Min(30, m.Index));
                if (Regex.IsMatch(before, @"xmlns(?::\w+)?\s*=\s*[""']$|schemaLocation\s*=\s*[""']$|""\$schema""\s*:\s*""$")) continue;
                Add(m.Value, $"{file.Path}:{LineOf(text, m.Index)}");
            }
        }

        var endpoints = byUrl
            .Select(kv => (Url: kv.Key, Host: HostOf(kv.Key), Where: kv.Value))
            // A real host: letters, digits, dots and dashes, with a dot (or localhost); not "https://…" or "https://{host}".
            .Where(e => RealHost.IsMatch(e.Host) && !Ignored.IsMatch(e.Host) && !Ignored.IsMatch(e.Host + PathStart(e.Url)))
            .OrderBy(e => e.Host, StringComparer.OrdinalIgnoreCase).ThenBy(e => e.Url, StringComparer.OrdinalIgnoreCase)
            .Select(e => new Endpoint(e.Url, e.Host, e.Where))
            .ToList();

        // Server=db.example.net;User ID=…: a host a connection string names isn't a web address, but it's where data
        // goes, so it's listed, marked as what it is. A server on this machine ((localdb), ., localhost) isn't.
        var hosts = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        void Host(string text, string where)
        {
            foreach (Match c in ConnectionString.Matches(text))
            {
                var host = Regex.Replace(c.Groups["h"].Value.Trim(), @"^tcp:|[,:]\d+$|\\.*$", "", RegexOptions.IgnoreCase).Trim();
                if (host.Length == 0 || LocalServer.IsMatch(host) || !Regex.IsMatch(host, @"^[A-Za-z0-9][A-Za-z0-9.-]*$")) continue;
                if (!hosts.TryGetValue(host, out var at)) hosts[host] = at = [];
                if (at.Count < 5 && !at.Contains(where)) at.Add(where);
            }
        }
        foreach (var file in code)
            foreach (var literal in CSharpLexer.Literals(file.Original))
                Host(literal.Text(file.Original), $"{file.Path}:{file.LineOf(literal.Start)}");
        foreach (var file in files.Where(f => f.Text is not null && EndpointFiles.Contains(f.Extension)))
            foreach (Match line in Regex.Matches(file.Text!, @"[^\n]+"))
                Host(line.Value, $"{file.Path}:{LineOf(file.Text!, line.Index)}");
        foreach (var (host, where) in hosts.OrderBy(h => h.Key, StringComparer.OrdinalIgnoreCase))
            if (!endpoints.Any(e => e.Host.Equals(host, StringComparison.OrdinalIgnoreCase)))
                endpoints.Add(new Endpoint(host, host, where, "a database host a connection string names"));
        return endpoints;
    }

    /// <summary>The server in a connection string: Server=, Data Source=, Host=, Address= with another setting beside it.</summary>
    private static readonly Regex ConnectionString = new(
        @"(?i)(?<!\w)(?:Server|Data\s+Source|Host|Address|Addr|Network\s+Address)\s*=\s*(?<h>[^;""']+)(?=;[^""']*\b(?:Database|Initial\s+Catalog|User\s*ID|Uid|Password|Pwd|Port|Integrated\s+Security|Trusted_Connection)\s*=)",
        RegexOptions.Compiled);

    private static readonly Regex LocalServer = new(@"(?i)^(?:\.|\(local(?:db)?\)|localhost|127\.0\.0\.1|::1|\(localdb\).*)$", RegexOptions.Compiled);

    private static readonly Regex NamespaceUse = new(
        @"\bXNamespace\s+\w+\s*=\s*@?$|\bXNamespace\s*\.\s*Get\s*\(\s*@?$|\(\s*XNamespace\s*\)\s*@?$|\bAddNamespace\s*\([^;()]*,\s*@?$|\bWriteAttributeString\s*\(\s*""xmlns""[^;()]*,\s*@?$|\bXmlns\s*\.\s*Add\s*\([^;()]*,\s*@?$",
        RegexOptions.Compiled);

    private static readonly Regex RealHost = new(@"^(?:localhost|(?=[A-Za-z0-9.-]*[A-Za-z0-9])[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)$", RegexOptions.Compiled);

    private static string HostOf(string url) =>
        Uri.TryCreate(url, UriKind.Absolute, out var u) ? u.Host : Regex.Match(url, @"://(?<h>[^/:?#]+)").Groups["h"].Value;

    private static string PathStart(string url) =>
        Regex.Match(url, @"://[^/]+(?<p>/[^/]+)?").Groups["p"].Value;

    // ---- build files --------------------------------------------------------------------------

    public static List<Finding> BuildFiles(IReadOnlyList<RepoFile> files, Func<string, string?> project)
    {
        var found = new List<Finding>();
        foreach (var file in files.Where(f => f.Text is not null && f.Extension is ".csproj" or ".props" or ".targets" or ".vbproj" or ".fsproj"))
        {
            var doc = ProjectScan.Parse(file.Text!);
            if (doc is null) continue;
            int Line(XElement e) => ((System.Xml.IXmlLineInfo)e).HasLineInfo() ? ((System.Xml.IXmlLineInfo)e).LineNumber : 1;

            foreach (var e in ProjectScan.Elements(doc, "Exec"))
            {
                var command = ProjectScan.Attr(e, "Command") ?? "";
                var legibility = Legibility.Clear;
                var reasons = new List<string>();
                string? decodedPs = null;
                if (Regex.IsMatch(command, @"(?i)(?:^|\s)-(?:e|enc|encodedcommand)\s"))
                {
                    legibility = Legibility.Opaque;
                    decodedPs = Fold.PowerShell(command);
                    reasons.Add(decodedPs is null ? "Runs an encoded PowerShell command."
                        : $"Hidden on purpose (encoded PowerShell); worked out from the source: {Tracer.Clip(decodedPs, 160)}");
                    if (decodedPs is not null && Commands.Describe(decodedPs) is { } words) reasons.Add(words + ".");
                    if (decodedPs is not null && Regex.IsMatch(decodedPs, @"(?i)\b(?:IEX|Invoke-Expression)\b"))
                        reasons.Add("It runs text as PowerShell code (Invoke-Expression), so what finally runs isn't in the source.");
                }
                else if (Regex.IsMatch(command, @"(?i)(?:curl|wget|iwr|Invoke-WebRequest|Invoke-RestMethod)\b.*(?:\|\s*(?:sh|bash|iex|Invoke-Expression)|iex\b)"))
                {
                    legibility = Legibility.Opaque;
                    reasons.Add("Downloads a script and runs it during the build.");
                }
                else if (command.Contains("$(") || command.Contains("@("))
                {
                    legibility = Legibility.PartlyClear;
                    reasons.Add("Uses build properties set elsewhere.");
                }
                var target = e.Parent?.Name.LocalName == "Target" ? ProjectScan.Attr(e.Parent, "Name") : null;
                var step = Make(file.Path, Line(e), Origin.Build, project(file.Path), FindingKind.BuildStep, Scope.User, legibility, "<Exec>",
                    Tracer.Clip(Regex.Replace(command, @"\s+", " "), 140) + (decodedPs is null ? "" : " → " + Tracer.Clip(decodedPs, 80) + " (decoded)"),
                    // What it does, said once: "Runs text as PowerShell code during the build", not "…: runs a command during the build".
                    (Commands.Describe(decodedPs ?? command) is { } plainBuild ? plainBuild : "Runs a command") + " during the build" + (target is null ? "" : " (target " + target + ")") + ".", reasons,
                    ["Runs on every machine that builds the repo, with that user's rights."]);
                if (decodedPs is not null || legibility == Legibility.Opaque && reasons.Any(r => r.Contains("encoded", StringComparison.Ordinal)))
                {
                    step.HiddenOnPurpose = true;
                    step.HowHidden = "encoded PowerShell";
                }
                found.Add(step);
            }

            foreach (var e in ProjectScan.Elements(doc, "UsingTask"))
            {
                var factory = ProjectScan.Attr(e, "TaskFactory") ?? "";
                if (!factory.Contains("CodeTaskFactory", StringComparison.OrdinalIgnoreCase)) continue;
                found.Add(Make(file.Path, Line(e), Origin.Build, project(file.Path), FindingKind.BuildStep, Scope.User, Legibility.PartlyClear,
                    "<UsingTask " + factory + ">", ProjectScan.Attr(e, "TaskName") ?? "inline task",
                    "Runs C# written inside the build file during the build.",
                    ["The inline task's code is not scanned; read it in the build file."]));
            }

            foreach (var e in ProjectScan.Elements(doc, "DownloadFile"))
                found.Add(Make(file.Path, Line(e), Origin.Build, project(file.Path), FindingKind.Network, Scope.WebService, Legibility.Clear,
                    "<DownloadFile>", ProjectScan.Attr(e, "SourceUrl") ?? "a URL", "Downloads a file during the build."));

            foreach (var e in ProjectScan.Elements(doc, "Import"))
            {
                var p = ProjectScan.Attr(e, "Project") ?? "";
                if (p.Length == 0 || p.StartsWith("Sdk", StringComparison.OrdinalIgnoreCase) || p.Contains("$(MSBuild") || p.Contains("Microsoft.")) continue;
                bool outside = Regex.IsMatch(p, @"^(?:[A-Za-z]:\\|\\\\|/)") || p.Contains("$(");
                if (!outside) continue;
                found.Add(Make(file.Path, Line(e), Origin.Build, project(file.Path), FindingKind.BuildStep, Scope.User, Legibility.PartlyClear,
                    "<Import>", p, "Imports build logic from outside the repo.", ["What it imports isn't in the zip."]));
            }
        }
        return found;
    }

    // ---- scripts ------------------------------------------------------------------------------

    private static readonly Regex DownloadAndRun = new(
        @"(?i)(?:curl|wget|iwr|Invoke-WebRequest|Invoke-RestMethod|irm|DownloadString|DownloadFile|Start-BitsTransfer|certutil\s+-urlcache)\b[^\r\n]*(?:\|\s*(?:sudo\s+)?(?:sh|bash|iex|Invoke-Expression)\b|\biex\b|Invoke-Expression)" +
        @"|(?i)\b(?:iex|Invoke-Expression)\s*\(?\s*(?:\(?\s*(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod|New-Object\s+Net\.WebClient))",
        RegexOptions.Compiled);

    private static readonly Regex EncodedCommand = new(@"(?i)(?:^|\s)-(?:e|en|enc|encodedcommand)\s+[A-Za-z0-9+/=]{8,}|FromBase64String|base64\s+(?:-d|--decode)", RegexOptions.Compiled);

    /// <summary>
    /// Scripts in the repo aren't C# and aren't followed, but a line that downloads code and runs it,
    /// or runs an encoded command, is worth a finding of its own.
    /// </summary>
    public static List<Finding> Scripts(IReadOnlyList<RepoFile> files, Func<string, Origin> origin)
    {
        var found = new List<Finding>();
        foreach (var file in files.Where(f => f.Text is not null && f.Extension is ".ps1" or ".psm1" or ".cmd" or ".bat" or ".sh" or ".vbs"))
        {
            if (WhatScriptRuns(file, origin(file.Path)) is { } named) found.Add(named);
            var lines = file.Text!.Split('\n');
            for (int i = 0; i < lines.Length; i++)
            {
                var line = lines[i].TrimEnd('\r');
                var trimmed = line.TrimStart();
                if (trimmed.StartsWith('#') || trimmed.StartsWith("REM ", StringComparison.OrdinalIgnoreCase) || trimmed.StartsWith("::", StringComparison.Ordinal)) continue;
                string? reason = DownloadAndRun.IsMatch(line) ? "Downloads code and runs it straight away."
                    : EncodedCommand.IsMatch(line) ? "Runs or decodes an encoded command." : null;
                if (reason is null) continue;
                var o = origin(file.Path);
                var decodedScript = Fold.PowerShell(line);
                var script = Make(file.Path, i + 1, o == Origin.App ? Origin.Build : o, null, FindingKind.Process, Scope.User, Legibility.Opaque,
                    "script", Tracer.Clip(trimmed, 140) + (decodedScript is null ? "" : " → " + Tracer.Clip(decodedScript, 80) + " (decoded)"),
                    "A script in the repo " + (reason.StartsWith("Downloads") ? "downloads code and runs it." : "runs an encoded command."),
                    decodedScript is null ? [reason + " The script isn't C#, so nothing else in it is followed."]
                        : [$"Hidden on purpose (encoded PowerShell); worked out from the source: {Tracer.Clip(decodedScript, 160)}", reason + " The script isn't C#, so nothing else in it is followed."]);
                if (!reason.StartsWith("Downloads", StringComparison.Ordinal)) { script.HiddenOnPurpose = true; script.HowHidden = "encoded command"; }
                found.Add(script);
            }
        }
        return found;
    }

    private static readonly Regex BatchTool = new(
        @"(?im)^\s*(?:@?\s*(?:call\s+|start\s+(?:""[^""]*""\s+)?(?:/\w+\s+)*)?)(?<t>schtasks|sc|netsh|bcdedit|icacls|takeown|vssadmin|wevtutil|diskpart|dism|msiexec|shutdown|net|net1|reg|pnputil|fsutil|auditpol|secedit|gpupdate|wusa|sfc|powershell|pwsh|wmic|certutil|bitsadmin|curl|wget)(?:\.exe)?\b",
        RegexOptions.Compiled);

    /// <summary>
    /// A script file in the repo, named by what it runs: a .ps1 by its PowerShell commands, a .cmd or
    /// .bat by the system tools it calls. It isn't C# and isn't followed; whether the app starts it is
    /// for its Process findings to say.
    /// </summary>
    private static Finding? WhatScriptRuns(RepoFile file, Origin o)
    {
        var text = string.Join("\n", file.Text!.Split('\n').Where(l => !l.TrimStart().StartsWith('#')
            && !l.TrimStart().StartsWith("REM ", StringComparison.OrdinalIgnoreCase) && !l.TrimStart().StartsWith("::", StringComparison.Ordinal)));
        string target, summary;
        IReadOnlyList<string> commands;
        var notes = new List<string> { "A script file, not C#: the scan names what it runs but doesn't follow it. Whether the app starts it shows in its process findings." };
        if (file.Extension is ".ps1" or ".psm1")
        {
            commands = PowerShellScript.Commands(text);
            if (commands.Count == 0) return null;
            target = "PowerShell: " + Tracer.Clip(string.Join(", ", commands), 110);
            summary = "A PowerShell script in the repo that " + PowerShellScript.Describe(commands) + ".";
            notes.AddRange(PowerShellScript.Flags(text).Select(f => "The script " + f + "."));
        }
        else if (file.Extension is ".cmd" or ".bat")
        {
            commands = BatchTool.Matches(text).Select(m => m.Groups["t"].Value.ToLowerInvariant()).Distinct().ToList();
            if (commands.Count == 0) return null;
            target = "runs " + string.Join(", ", commands);
            summary = "A batch script in the repo that runs " + string.Join(", ", commands) + ".";
        }
        else return null;
        if (Commands.Describe(text) is { } plain) notes.Insert(0, plain + ".");
        var finding = Make(file.Path, 1, o == Origin.App ? Origin.Build : o, null, FindingKind.Process, Scope.User, Legibility.Clear,
            "script file", target, summary, null, notes);
        finding.Program = file.Extension is ".ps1" or ".psm1" ? "powershell" : "cmd";
        finding.Commands = commands;
        return finding;
    }

    // ---- CI workflows -------------------------------------------------------------------------

    public static List<Finding> Workflows(IReadOnlyList<RepoFile> files, List<CiAction> actions)
    {
        var found = new List<Finding>();
        foreach (var file in files.Where(f => f.Text is not null && f.Path.StartsWith(".github/workflows/", StringComparison.OrdinalIgnoreCase)
                                              && f.Extension is ".yml" or ".yaml"))
        {
            var lines = file.Text!.Split('\n');
            var secrets = new HashSet<string>(StringComparer.Ordinal);
            for (int i = 0; i < lines.Length; i++)
            {
                var line = lines[i].TrimEnd('\r');
                var uses = Regex.Match(line, @"^\s*-?\s*uses:\s*['""]?(?<u>[^'""#\s]+)");
                if (uses.Success)
                {
                    var u = uses.Groups["u"].Value;
                    if (u.StartsWith("./", StringComparison.Ordinal)) continue;
                    bool pinned = Regex.IsMatch(u, @"@[0-9a-f]{40}$");
                    bool docker = u.StartsWith("docker://", StringComparison.Ordinal);
                    bool first = u.StartsWith("actions/", StringComparison.OrdinalIgnoreCase) || u.StartsWith("github/", StringComparison.OrdinalIgnoreCase);
                    actions.Add(new CiAction(u, pinned, $"{file.Path}:{i + 1}"));
                    var reasons = new List<string>();
                    // Not pinned to a commit: what runs is decided outside this repo, by whoever controls the tag
                    // or branch. For a third-party action that's as open as curl | bash: Opaque. GitHub's own
                    // actions (actions/, github/) stay Run time, with the same reason.
                    bool floating = !pinned && !docker;
                    if (floating)
                        reasons.Add("Decided outside this repo: pinned to a tag or branch, not a commit, so whoever controls "
                                    + (first ? "that tag" : "that tag or branch") + " decides what runs.");
                    var legibility = !floating ? Legibility.Clear : first ? Legibility.PartlyClear : Legibility.Opaque;
                    found.Add(Make(file.Path, i + 1, Origin.CI, null, FindingKind.CiAction, Scope.WebService,
                        legibility, "uses:", u,
                        (first ? "Uses the GitHub action " : "Uses the third-party action ") + u + ".", reasons,
                        first ? null : ["Third-party code runs in the CI job, with its token and secrets."]));
                    continue;
                }

                var run = Regex.Match(line, @"^(?<indent>\s*)-?\s*run:\s*(?<cmd>.*)$");
                if (run.Success)
                {
                    var command = run.Groups["cmd"].Value.Trim();
                    int at = i;
                    if (command is "|" or ">" or "|-" or ">-" or "|+" or "")
                    {
                        var block = new List<string>();
                        int indent = run.Groups["indent"].Length;
                        for (int j = i + 1; j < lines.Length; j++)
                        {
                            var l = lines[j].TrimEnd('\r');
                            if (l.Trim().Length > 0 && l.Length - l.TrimStart().Length <= indent) break;
                            if (l.Trim().Length > 0) block.Add(l.Trim());
                        }
                        command = string.Join(" ; ", block);
                    }
                    var legibility = Legibility.Clear;
                    var reasons = new List<string>();
                    if (Regex.IsMatch(command, @"(?i)(?:curl|wget|iwr|Invoke-WebRequest|Invoke-RestMethod)\b[^;]*(?:\|\s*(?:sudo\s+)?(?:sh|bash|iex|Invoke-Expression))"))
                    {
                        legibility = Legibility.Opaque;
                        reasons.Add("Downloads a script and runs it straight away.");
                    }
                    else if (Regex.IsMatch(command, @"(?i)(?:^|\s)-(?:e|enc|encodedcommand)\s|base64\s+(?:-d|--decode)"))
                    {
                        legibility = Legibility.Opaque;
                        reasons.Add("Runs an encoded command.");
                    }
                    found.Add(Make(file.Path, at + 1, Origin.CI, null, FindingKind.CiStep, Scope.WebService, legibility, "run:",
                        Tracer.Clip(command, 140), (Commands.Describe(command) is { } plainCi ? plainCi : "Runs a command") + " in CI.", reasons));
                }

                foreach (Match s in Regex.Matches(line, @"\$\{\{\s*secrets\.(?<s>[A-Za-z_][\w]*)\s*\}\}"))
                {
                    if (!secrets.Add(s.Groups["s"].Value)) continue;
                    found.Add(Make(file.Path, i + 1, Origin.CI, null, FindingKind.Credential, Scope.WebService, Legibility.Clear, "secrets.",
                        s.Groups["s"].Value, "Uses the CI secret " + s.Groups["s"].Value + "."));
                }
            }
        }
        return found;
    }
}
