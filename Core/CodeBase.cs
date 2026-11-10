using System.IO;
using System.Text.RegularExpressions;
using CSharpLexing;

namespace RepoLegibility.Core;

/// <summary>
/// One C# file three times over, at identical positions: the original; Text with comments blanked,
/// where values and literals are read; Masked with strings blanked as well, where calls,
/// definitions and brackets are found.
/// </summary>
public sealed class CodeFile
{
    private readonly int[] _lineStarts;

    public CodeFile(RepoFile file, Origin origin, ProjectFile? project, bool generated)
    {
        File = file;
        Original = file.Text!;
        Text = CSharpLexer.BlankComments(Original);
        Masked = CSharpLexer.BlankCommentsAndStrings(Original);
        Origin = origin;
        Project = project;
        Generated = generated;

        var starts = new List<int> { 0 };
        for (int i = 0; i < Original.Length; i++)
            if (Original[i] == '\n') starts.Add(i + 1);
        _lineStarts = starts.ToArray();
    }

    public RepoFile File { get; }
    public string Path => File.Path;
    public string Original { get; }
    public string Text { get; }
    public string Masked { get; }
    public Origin Origin { get; }
    public ProjectFile? Project { get; }
    public bool Generated { get; }
    public int LineCount => _lineStarts.Length;

    /// <summary>1-based line of a position.</summary>
    public int LineOf(int index)
    {
        int i = Array.BinarySearch(_lineStarts, Math.Clamp(index, 0, Math.Max(0, Original.Length)));
        return (i >= 0 ? i : ~i - 1) + 1;
    }

    /// <summary>The text of a 1-based line, without its line break.</summary>
    public string LineText(int line)
    {
        if (line < 1 || line > _lineStarts.Length) return "";
        int start = _lineStarts[line - 1];
        int end = line < _lineStarts.Length ? _lineStarts[line] : Original.Length;
        return Original[start..end].TrimEnd('\r', '\n');
    }

    /// <summary>
    /// The top-level arguments of a call, from just after its opening parenthesis. Brackets, commas
    /// and semicolons are counted in the masked text; the arguments are read from Text.
    /// </summary>
    public List<string> Arguments(int start)
    {
        var args = new List<string>();
        int depth = 0, from = start;
        for (int i = start; i < Masked.Length && i < start + 6000; i++)
        {
            char c = Masked[i];
            if (c is '(' or '[' or '{') depth++;
            else if (c is ')' or ']' or '}')
            {
                if (depth == 0)
                {
                    if (i > from || args.Count > 0) args.Add(Text[from..i].Trim());
                    return args;
                }
                depth--;
            }
            else if (c == ',' && depth == 0)
            {
                args.Add(Text[from..i].Trim());
                from = i + 1;
            }
            else if (c == ';' && depth == 0) break;
        }
        return args;
    }

    /// <summary>The position just after the closing parenthesis of a call opened at <paramref name="start"/>, or -1.</summary>
    public int AfterArguments(int start)
    {
        int depth = 0;
        for (int i = start; i < Masked.Length && i < start + 6000; i++)
        {
            char c = Masked[i];
            if (c is '(' or '[' or '{') depth++;
            else if (c is ')' or ']' or '}')
            {
                if (depth == 0) return i + 1;
                depth--;
            }
            else if (c == ';' && depth == 0) return -1;
        }
        return -1;
    }

    /// <summary>The closing brace for an opening one, in masked text.</summary>
    public int MatchingBrace(int open)
    {
        int depth = 0;
        for (int i = open; i < Masked.Length; i++)
        {
            if (Masked[i] == '{') depth++;
            else if (Masked[i] == '}' && --depth == 0) return i;
        }
        return -1;
    }

    private List<(int Position, int End, string Name)>? _types;

    /// <summary>The type a position is declared in: the innermost class, struct, record or interface around it.</summary>
    public string? TypeAt(int position)
    {
        // The innermost type whose body holds the position: a record declared inside a class doesn't
        // own the members that follow it. A positional record without a body owns its parameter list.
        _types ??= Regex.Matches(Masked, @"\b(?:class|struct|record|interface)\s+(?<t>[A-Za-z_]\w*)")
            .Select(m => (m.Index, End: TypeEnd(m.Index + m.Length), m.Groups["t"].Value)).ToList();
        string? found = null;
        int start = -1;
        foreach (var (at, end, name) in _types)
        {
            if (at > position) break;
            if (position <= end && at > start) { found = name; start = at; }
        }
        return found;
    }

    /// <summary>Whether the position sits inside a type of that name, at any depth: an outer class's members are in scope in a nested one.</summary>
    public bool InsideType(string type, int position)
    {
        TypeAt(position);
        return _types!.Any(t => t.Name == type && t.Position <= position && position <= t.End);
    }

    /// <summary>Where a type declared at <paramref name="from"/> ends: its closing brace, or the ';' of a record without a body.</summary>
    private int TypeEnd(int from)
    {
        int brace = Masked.IndexOf('{', from), semi = Masked.IndexOf(';', from);
        if (brace < 0) return semi < 0 ? Masked.Length : semi;
        if (semi >= 0 && semi < brace)
        {
            // record R(int A); — but not "record R(int A) : Base(A) { … }" where ';' comes inside the body.
            return semi;
        }
        int depth = 0;
        for (int i = brace; i < Masked.Length; i++)
        {
            if (Masked[i] == '{') depth++;
            else if (Masked[i] == '}' && --depth == 0) return i;
        }
        return Masked.Length;
    }

    /// <summary>
    /// Where the member around a position starts: the header of the method (or accessor, or local
    /// function) whose body holds it, or the type's opening brace. Names introduced before it belong elsewhere.
    /// </summary>
    public int MemberStart(int position) => Member(position).Start;

    /// <summary>
    /// Where the member around a position begins, and whether that is a type's body rather than a
    /// method, accessor or local function.
    /// </summary>
    public (int Start, bool IsType) Member(int position)
    {
        int depth = 0;
        for (int i = Math.Min(position, Masked.Length) - 1; i >= 0; i--)
        {
            char c = Masked[i];
            if (c == '}') { depth++; continue; }
            if (c != '{') continue;
            if (depth > 0) { depth--; continue; }
            int headerStart = Masked.LastIndexOfAny([';', '{', '}'], Math.Max(0, i - 1)) + 1;
            var header = Masked[headerStart..i].TrimEnd();
            if (Regex.IsMatch(header, @"\b(?:class|struct|record|interface|namespace|enum)\b")) return (i + 1, true);
            if (Regex.IsMatch(header.TrimStart(), @"^(?:if|else|for|foreach|while|do|using|switch|try|catch|finally|lock|fixed|unsafe|checked|unchecked)\b")) continue;
            if (header.EndsWith("=>", StringComparison.Ordinal)) continue; // a lambda inside the member
            if (header.EndsWith(')') || Regex.IsMatch(header, @"\b(?:get|set|init|add|remove)$")) return (headerStart, false);
        }
        return (0, true);
    }

    /// <summary>The statement a position sits in: from the previous ; { } to the next ;.</summary>
    public string Statement(int position)
    {
        int start = Masked.LastIndexOfAny([';', '{', '}'], Math.Max(0, Math.Min(position, Masked.Length) - 1)) + 1;
        int end = Masked.IndexOf(';', Math.Min(position, Masked.Length));
        if (end < 0) end = Masked.Length;
        return Text[start..end];
    }
}

/// <summary>
/// All C# of the repo and where names are defined, found once per scan and shared by every trace.
/// </summary>
public sealed class CodeBase
{
    private readonly Dictionary<(string Name, bool IsCall), List<(string Expression, CodeFile File, int Position)>> _members = new();
    private readonly Dictionary<(string Name, CodeFile File), List<(int Index, int End, string Expression)>> _locals = new();
    private readonly Dictionary<string, bool> _declared = new(StringComparer.Ordinal);
    private readonly Dictionary<string, bool> _types = new(StringComparer.Ordinal);
    private readonly Dictionary<string, List<(CodeFile File, int Open)>> _callers = new(StringComparer.Ordinal);
    private readonly object _gate = new();
    private readonly List<RepoFile> _xaml;

    private HashSet<string>? _mediaControls;

    /// <summary>A MediaElement named in the XAML (x:Name="Player"), or a variable declared as a MediaElement or MediaPlayer.</summary>
    public bool IsMediaElement(string name, CodeFile file)
    {
        lock (_gate)
        {
            if (_mediaControls is null)
            {
                _mediaControls = new HashSet<string>(StringComparer.Ordinal);
                foreach (var x in _xaml)
                    foreach (Match m in Regex.Matches(x.Text!, @"<(?:\w+:)?MediaElement\b[^>]*?\b(?:x:)?Name\s*=\s*""(?<n>[A-Za-z_]\w*)"""))
                        _mediaControls.Add(m.Groups["n"].Value);
            }
            if (_mediaControls.Contains(name)) return true;
        }
        return Regex.IsMatch(file.Masked, $@"\b(?:MediaElement|MediaPlayer)\s+{Regex.Escape(name)}\b|\b{Regex.Escape(name)}\s*=\s*new\s+(?:MediaElement|MediaPlayer)\b");
    }

    private HashSet<string>? _typedControls;
    private static readonly Regex TypedInCode = new(
        @"\b(?:System\.Windows\.Controls\.)?(?<t>TextBox|PasswordBox|RichTextBox|ComboBox)\s+(?<n>[A-Za-z_]\w*)\s*(?=[=;,)])", RegexOptions.Compiled);

    /// <summary>The x:Name of every box the user types into in the XAML: &lt;TextBox x:Name="TxtProgram"&gt;, an editable ComboBox, a PasswordBox.</summary>
    public IReadOnlySet<string> TypedControls
    {
        get
        {
            lock (_gate)
            {
                if (_typedControls is not null) return _typedControls;
                var found = new HashSet<string>(StringComparer.Ordinal);
                foreach (var x in _xaml)
                    foreach (Match m in Regex.Matches(x.Text!, @"<(?:\w+:)?(?<t>TextBox|PasswordBox|ComboBox|RichTextBox)\b(?<attrs>[^>]*)>"))
                    {
                        var attrs = m.Groups["attrs"].Value;
                        if (m.Groups["t"].Value == "ComboBox" && !Regex.IsMatch(attrs, @"IsEditable\s*=\s*""True""", RegexOptions.IgnoreCase)) continue;
                        if (Regex.IsMatch(attrs, @"IsReadOnly\s*=\s*""True""", RegexOptions.IgnoreCase)) continue;
                        var name = Regex.Match(attrs, @"\b(?:x:)?Name\s*=\s*""(?<n>[A-Za-z_]\w*)""");
                        if (name.Success) found.Add(name.Groups["n"].Value);
                    }
                // Made in code: readonly TextBox _output = new(); var box = new PasswordBox { … }.
                foreach (var f in Files)
                    foreach (Match m in TypedInCode.Matches(f.Masked))
                    {
                        var init = f.Masked[(m.Index + m.Length)..Math.Min(f.Masked.Length, m.Index + m.Length + 400)];
                        int semi = init.IndexOf(';');
                        if (semi >= 0) init = init[..semi];
                        if (m.Groups["t"].Value == "ComboBox" && !Regex.IsMatch(init, @"\bIsEditable\s*=\s*true\b")) continue;
                        if (Regex.IsMatch(init, @"\bIsReadOnly\s*=\s*true\b")) continue;
                        found.Add(m.Groups["n"].Value);
                    }
                return _typedControls = found;
            }
        }
    }

    public CodeBase(IReadOnlyList<CodeFile> files, IReadOnlyList<RepoFile>? xaml = null)
    {
        _xaml = xaml?.Where(f => f.Text is not null && f.Extension == ".xaml").ToList() ?? [];
        Files = files;
        HasDialogs = files.Any(f => Regex.IsMatch(f.Masked, @"\b(?:SaveFileDialog|OpenFileDialog|OpenFolderDialog|FolderBrowserDialog|CommonOpenFileDialog)\b"));
    }

    public IReadOnlyList<CodeFile> Files { get; }
    public bool HasDialogs { get; }

    // ---- the identifier index -----------------------------------------------------------------
    // Every name in the masked code, with where it stands, built once. A lookup checks those places
    // with a pattern anchored right after the name, instead of running a new pattern over all code.

    private Dictionary<string, List<(CodeFile File, int Index)>>? _tokens;

    private Dictionary<string, List<(CodeFile File, int Index)>> Tokens
    {
        get
        {
            if (_tokens is not null) return _tokens;
            var tokens = new Dictionary<string, List<(CodeFile, int)>>(StringComparer.Ordinal);
            foreach (var file in Files)
            {
                var m = file.Masked;
                for (int i = 0; i < m.Length; i++)
                {
                    char c = m[i];
                    if (!(char.IsLetter(c) || c == '_') || (i > 0 && IsNameChar(m[i - 1]))) continue;
                    int j = i + 1;
                    while (j < m.Length && IsNameChar(m[j])) j++;
                    var name = m[i..j];
                    if (!tokens.TryGetValue(name, out var list)) tokens[name] = list = new List<(CodeFile, int)>();
                    list.Add((file, i));
                    i = j - 1;
                }
            }
            return _tokens = tokens;
        }
    }

    private static bool IsNameChar(char c) => char.IsLetterOrDigit(c) || c == '_';

    /// <summary>Where a name stands in one file, before a position, nearest first.</summary>
    public IEnumerable<int> Before(string name, CodeFile file, int position) =>
        Places(name).Where(p => p.File == file && p.Index < position).Select(p => p.Index).Reverse();

    private IEnumerable<(CodeFile File, int Index)> Places(string name) =>
        Tokens.TryGetValue(name, out var list) ? list : [];

    /// <summary>The character before a name, skipping blanks: '.' for a member access.</summary>
    private static char Before(string masked, int index)
    {
        int k = index - 1;
        while (k >= 0 && masked[k] is ' ' or '\t' or '\r' or '\n') k--;
        return k >= 0 ? masked[k] : '\0';
    }

    /// <summary>A member access that only names the own instance: "this.name".</summary>
    private static bool OnThis(string masked, int index)
    {
        int k = index - 1;
        while (k >= 0 && masked[k] is ' ' or '\t') k--;
        if (k < 0 || masked[k] != '.') return false;
        k--;
        while (k >= 0 && masked[k] is ' ' or '\t') k--;
        return k >= 3 && masked.AsSpan(k - 3, 4).SequenceEqual("this") && (k - 4 < 0 || !IsNameChar(masked[k - 4]));
    }

    /// <summary>A type or modifier stands right before the name: "string name", "List<int> name", "int? name".</summary>
    private static bool AfterType(string masked, int index)
    {
        int k = index - 1;
        if (k < 0 || !(masked[k] is ' ' or '\t' or '\r' or '\n')) return false;
        while (k >= 0 && masked[k] is ' ' or '\t' or '\r' or '\n') k--;
        return k >= 0 && (IsNameChar(masked[k]) || masked[k] is '>' or ']' or '?');
    }

    private static readonly Regex AssignAfter = new(@"\G\s*(?:\?\?)?=(?![=>])", RegexOptions.Compiled);
    private static readonly Regex MemberAfter = new(@"\G\s*(?:\{\s*get;[^}]*\}\s*=|=>|\??\?=(?![=>])|=(?![=>])|\{\s*(?:(?:public|private|protected|internal)\s+)*get\s*(?<getter>\{|=>))", RegexOptions.Compiled);
    private static readonly Regex MethodAfter = new(@"\G\s*(?:<[^<>;]*>)?\s*\([^;{)]*\)\s*(?:=>|\{)", RegexOptions.Compiled | RegexOptions.Singleline);
    private static readonly Regex CallAfter = new(@"\G\s*(?:<[^<>;()]*>)?\s*\(", RegexOptions.Compiled);
    private static readonly Regex DeclaredAfter = new(@"\G\s*(?:\{|;|=)", RegexOptions.Compiled);
    private static readonly Regex MethodDeclarationAfter = new(@"\G\s*(?:<[^<>;()]*>)?\s*\([^;{)]*\)\s*(?:=>|\{|where\b|:\s*(?:base|this)\b)", RegexOptions.Compiled);
    private static readonly Regex TypeKeywordBefore = new(@"\b(?:class|struct|record|interface|enum)\s+$", RegexOptions.Compiled);

    /// <summary>The assignments to a local in one file, in order: "name = …" and "name ??= …".</summary>
    public List<(int Index, int End, string Expression)> Locals(string name, CodeFile file)
    {
        lock (_gate)
        {
            if (_locals.TryGetValue((name, file), out var found)) return found;
            found = new List<(int, int, string)>();
            foreach (var (f, index) in Places(name))
            {
                if (f != file || (Before(file.Masked, index) == '.' && !OnThis(file.Masked, index))) continue;
                var m = AssignAfter.Match(file.Masked, index + name.Length);
                if (!m.Success) continue;
                int start = m.Index + m.Length;
                int end = ExpressionEnd(file.Masked, start);
                found.Add((index, end, file.Text[start..end].Trim()));
            }
            _locals[(name, file)] = found;
            return found;
        }
    }

    /// <summary>
    /// Where an expression that starts at <paramref name="start"/> ends: at a semicolon, or at a comma
    /// or closing bracket on its own level (the end of an initializer entry or an argument).
    /// </summary>
    public static int ExpressionEnd(string masked, int start)
    {
        int depth = 0;
        for (int i = start; i < masked.Length; i++)
        {
            char c = masked[i];
            if (c is '(' or '[' or '{') depth++;
            else if (c is ')' or ']' or '}')
            {
                if (depth == 0) return i;
                depth--;
            }
            else if (depth == 0 && c is ';' or ',') return i;
        }
        return masked.Length;
    }

    private readonly Dictionary<string, int> _methods = new(StringComparer.Ordinal);

    /// <summary>How many methods (or constructors) of this name the repo declares.</summary>
    public int MethodDeclarations(string name)
    {
        lock (_gate)
        {
            if (_methods.TryGetValue(name, out var count)) return count;
            count = Places(name).Count(p => AfterType(p.File.Masked, p.Index)
                                            && MethodDeclarationAfter.IsMatch(p.File.Masked, p.Index + name.Length));
            _methods[name] = count;
            return count;
        }
    }

    private readonly Dictionary<string, List<(string Type, int Index)>> _records = new(StringComparer.Ordinal);

    /// <summary>A positional record's parameter of this name: the record and the parameter's index. The first one found.</summary>
    public (string Type, int Index)? RecordParameter(string name) =>
        RecordParameters(name) is { Count: > 0 } all ? all[0] : null;

    /// <summary>Every positional record with a parameter of this name: Verdict(…, string FullPath, …), SettingInfo(string Path, …).</summary>
    public List<(string Type, int Index)> RecordParameters(string name)
    {
        lock (_gate)
        {
            if (_records.TryGetValue(name, out var known)) return known;
            known = new();
            foreach (var (file, index) in Places(name))
            {
                // Inside the parentheses right after "record Name".
                int open = file.Masked.LastIndexOf('(', index);
                if (open < 0 || file.Masked.IndexOf(')', open) < index) continue;
                var head = Regex.Match(file.Masked[Math.Max(0, open - 160)..open], @"\brecord\s+(?:class\s+|struct\s+)?(?<t>[A-Za-z_]\w*)\s*(?:<[^<>]*>)?\s*$");
                if (!head.Success) continue;
                var list = file.Masked[(open + 1)..index];
                int depth = 0, commas = 0;
                foreach (char c in list)
                {
                    if (c is '(' or '<' or '[') depth++;
                    else if (c is ')' or '>' or ']') depth--;
                    else if (c == ',' && depth == 0) commas++;
                }
                if (!known.Any(k => k.Type == head.Groups["t"].Value)) known.Add((head.Groups["t"].Value, commas));
            }
            _records[name] = known;
            return known;
        }
    }

    /// <summary>True when the repo declares a type of this name.</summary>
    public bool DeclaresType(string name)
    {
        lock (_gate)
        {
            if (_types.TryGetValue(name, out var known)) return known;
            known = Places(name).Any(p => TypeKeywordBefore.IsMatch(p.File.Masked[Math.Max(0, p.Index - 20)..p.Index]));
            _types[name] = known;
            return known;
        }
    }

    /// <summary>A field, property or method across the code: what it's set to, or everything it returns.</summary>
    public List<(string Expression, CodeFile File, int Position)> Members(string name, bool isCall)
    {
        lock (_gate)
        {
            if (_members.TryGetValue((name, isCall), out var found)) return found;

            found = new List<(string, CodeFile, int)>();
            foreach (var (file, index) in Places(name))
            {
                if (Before(file.Masked, index) == '.' && !OnThis(file.Masked, index)) continue;
                // new ShapePath { Data = geometry }: setting another type's property, not declaring this one.
                // new() { Text = "Ready" }: a target-typed new sets a property of a type it doesn't name; it declares
                // one only where the repo has a property of that name.
                if (!isCall && InObjectInitializer(file.Masked, index) is { } made && (made.Length > 0 ? !DeclaresType(made) : !Declared(name))) continue;
                var m = (isCall ? MethodAfter : MemberAfter).Match(file.Masked, index + name.Length);
                if (!m.Success) continue;

                int start = m.Index + m.Length;
                // string PortableRoot { get { …; return x; } }: a get-only property is read like a method, through
                // what its getter returns. A declaration only: a type (or modifier) stands before the name.
                if (!isCall && m.Groups["getter"].Success)
                {
                    if (!AfterType(file.Masked, index)) continue;
                    // Only a getter that gives a place: a string, a path or a list of them. A computed list of
                    // records (ExifItems { get { … } }) says what a file holds, not where anything is.
                    var declaredType = Regex.Match(file.Masked[Math.Max(0, index - 120)..index], @"(?<t>[\w.]+(?:<[^<>;{}()]*>)?(?:\[\])?\??)\s+$").Groups["t"].Value;
                    if (!Regex.IsMatch(declaredType, @"^(?:string|String|Uri|FileInfo|DirectoryInfo|FileSystemInfo|RegistryKey)\b|^(?:[\w.]*(?:List|IEnumerable|IReadOnlyList|IList|ICollection|IReadOnlyCollection|HashSet|ISet)<string\??>|string\[\])\??$"))
                        continue;
                    // Get-only: a property with a setter (or a WPF dependency property behind GetValue) is set from
                    // outside, and that's where its value comes from.
                    int accessorsOpen = file.Masked.IndexOf('{', index + name.Length);
                    int accessorsClose = accessorsOpen < 0 ? -1 : file.MatchingBrace(accessorsOpen);
                    if (accessorsClose < 0) continue;
                    var accessors = file.Masked[accessorsOpen..accessorsClose];
                    if (Regex.IsMatch(accessors, @"\b(?:set|init)\b|\bGetValue\s*\(\s*\w+Property\b")) continue;
                    if (m.Groups["getter"].Value == "=>")
                    {
                        int to = ExpressionEnd(file.Masked, start);
                        var body = file.Text[start..to].Trim();
                        if (body.Length > 0) found.Add((body, file, index));
                        continue;
                    }
                    int shut = file.MatchingBrace(start - 1);
                    if (shut < 0) continue;
                    foreach (Match r in ReturnValue.Matches(file.Masked[start..shut]))
                    {
                        int from = start + r.Index + r.Length;
                        int end = ExpressionEnd(file.Masked, from);
                        found.Add((file.Text[from..end].Trim(), file, start + r.Index));
                    }
                    continue;
                }
                if (!isCall || m.Value.EndsWith("=>", StringComparison.Ordinal))
                {
                    int end = ExpressionEnd(file.Masked, start);
                    var rhs = file.Text[start..end].Trim();
                    if (rhs.Length > 0) found.Add((rhs, file, index));
                    continue;
                }

                // A method with a body: everything it returns.
                int close = file.MatchingBrace(start - 1);
                if (close < 0) continue;
                foreach (Match r in ReturnValue.Matches(file.Masked[start..close]))
                {
                    int from = start + r.Index + r.Length;
                    int end = ExpressionEnd(file.Masked, from);
                    found.Add((file.Text[from..end].Trim(), file, start + r.Index));
                }
            }
            _members[(name, isCall)] = found;
            return found;
        }
    }

    private readonly Dictionary<(string, string?), List<string>?> _webOnly = new();

    /// <summary>
    /// The web addresses a method returns, when that's all it returns: every return is null, a text that starts
    /// with http(s):// and a fixed host ("https://www.rfc-editor.org/rfc/rfc" + n, $"https://www.unicode.org/reports/tr{n}/"),
    /// or a call to a method that itself returns only such addresses. Null when any return could be something
    /// else. What fills in the rest of an address changes the page, not where it goes.
    /// </summary>
    public IReadOnlyList<string>? WebAddressesReturnedBy(string method, string? ownerType = null) =>
        WebAddressesReturnedBy(method, ownerType, new HashSet<(string, string?)>());

    private IReadOnlyList<string>? WebAddressesReturnedBy(string method, string? ownerType, HashSet<(string, string?)> working)
    {
        var key = (method, ownerType);
        lock (_gate)
            if (_webOnly.TryGetValue(key, out var known)) return known;
        // A method calling itself (through an overload) adds nothing; worked out per call, so threads don't share it.
        if (!working.Add(key)) return [];
        var defs = Members(method, true).Where(d => d.File.Origin != Origin.Tests).ToList();
        // Citations.UrlOf, not FindingsCatalog.UrlOf: the type's own, when it has one.
        if (ownerType is not null && defs.Any(d => d.File.TypeAt(d.Position) == ownerType))
            defs = defs.Where(d => d.File.TypeAt(d.Position) == ownerType).ToList();
        List<string>? urls = defs.Count == 0 ? null : new List<string>();
        foreach (var (expression, defFile, defPos) in defs)
        {
            foreach (var branch in Branches(expression))
            {
                if (urls is null) break;
                var b = branch.Trim();
                while (b.StartsWith('(') && b.EndsWith(')')) b = b[1..^1].Trim();
                if (b is "null" or "default" or "null!") continue;
                var literal = Regex.Match(b, @"^\$?@?""(?<u>https?://[^/""{}\s]+/[^""]*)""");
                if (literal.Success) { var u = literal.Groups["u"].Value; urls.Add(u.Contains('{') ? u[..u.IndexOf('{')] + "{}" : u); continue; }
                // Understanding + page, with const string Understanding = "https://www.w3.org/…": the constant fixes the host.
                var constant = Regex.Match(b, @"^(?<c>[A-Za-z_]\w*)\s*(?:\+|$)");
                if (constant.Success && Members(constant.Groups["c"].Value, false) is { Count: > 0 } cs
                    && cs.All(x => Regex.IsMatch(x.Expression, @"^@?""https?://[^/""{}\s]+/[^""]*""$")))
                { urls.AddRange(cs.Select(x => x.Expression.TrimStart('@').Trim('"'))); continue; }
                var call = Regex.Match(b, @"^(?<m>[A-Za-z_]\w*)\s*\(");
                if (call.Success && file_Close(b, call.Length - 1) == b.Length - 1 && WebAddressesReturnedBy(call.Groups["m"].Value, defFile.TypeAt(defPos), working) is { } inner)
                { urls.AddRange(inner); continue; }
                urls = null;
            }
            if (urls is null) break;
        }
        if (urls is { Count: 0 }) urls = null;
        // Only the outermost answer is kept: an inner one may have been worked out with a call still open.
        if (working.Count == 1) lock (_gate) _webOnly[key] = urls;
        working.Remove(key);
        return urls;
    }

    private static int file_Close(string text, int open)
    {
        int depth = 0;
        for (int i = open; i < text.Length; i++)
        {
            if (text[i] == '(') depth++;
            else if (text[i] == ')' && --depth == 0) return i;
        }
        return -1;
    }

    /// <summary>The values an expression can be: the branches of a top-level ?: and ??, each split again.</summary>
    private static IEnumerable<string> Branches(string expression)
    {
        int depth = 0, question = -1;
        bool inString = false;
        for (int i = 0; i < expression.Length; i++)
        {
            char c = expression[i];
            if (c == '"' && (i == 0 || expression[i - 1] != '\\')) inString = !inString;
            if (inString) continue;
            if (c is '(' or '[' or '{') depth++;
            else if (c is ')' or ']' or '}') depth--;
            else if (depth == 0 && c == '?' && i + 1 < expression.Length && expression[i + 1] == '?')
            {
                foreach (var x in Branches(expression[..i])) yield return x;
                foreach (var x in Branches(expression[(i + 2)..])) yield return x;
                yield break;
            }
            else if (depth == 0 && c == '?' && question < 0 && (i + 1 >= expression.Length || expression[i + 1] is not ('.' or '[')))
                question = i;
            else if (depth == 0 && c == ':' && question >= 0)
            {
                foreach (var x in Branches(expression[(question + 1)..i])) yield return x;
                foreach (var x in Branches(expression[(i + 1)..])) yield return x;
                yield break;
            }
        }
        yield return expression;
    }

    /// <summary>
    /// The type a member definition belongs to: new ChangeSet { Folder = folder } inside ChangeSetStore sets
    /// ChangeSet's Folder, not ChangeSetStore's.
    /// </summary>
    public static string? OwnerOf(CodeFile file, int position) =>
        InObjectInitializer(file.Masked, position) is { Length: > 0 } made ? made : file.TypeAt(position);

    /// <summary>The name stands in an object initializer (new T { Name = … }, x with { Name = … }), not in a type's body.</summary>
    internal static string? InObjectInitializer(string masked, int index)
    {
        int depth = 0;
        for (int i = index - 1; i >= Math.Max(0, index - 600); i--)
        {
            char c = masked[i];
            if (c == '}') depth++;
            else if (c == '{')
            {
                if (depth > 0) { depth--; continue; }
                var before = masked[Math.Max(0, i - 160)..i];
                // new Foo { … }, and target-typed new() { … }, whose type isn't written.
                var made = Regex.Match(before, @"\bnew\b\s*(?<t>[A-Za-z_][\w.]*)?[^;{}=]*$");
                if (made.Success) { var t = made.Groups["t"].Value; return t.Length == 0 ? "" : t[(t.LastIndexOf('.') + 1)..]; }
                return Regex.IsMatch(before, @"\bwith\s*$") ? "" : null;
            }
            else if (c == ';' && depth == 0) return null;
        }
        return null;
    }

    /// <summary>Finished traces, by file, position, expression and whether it stays inside its method.</summary>
    public System.Collections.Concurrent.ConcurrentDictionary<(string File, int Position, string Expression, bool Local), Tracer> Traces { get; } = new();

    private readonly Dictionary<string, List<(string Expression, CodeFile File, int Position, string Receiver)>> _through = new(StringComparer.Ordinal);
    private static readonly Regex AssignedAfter = new(@"\G\s*=(?![=>])\s*", RegexOptions.Compiled);

    /// <summary>
    /// Assignments to a property through a variable: ctx.TimeStamp = …, with the variable's name. Members()
    /// has the ones written inside the type (TimeStamp = …, this.TimeStamp = …).
    /// </summary>
    public List<(string Expression, CodeFile File, int Position, string Receiver)> AssignmentsThrough(string name)
    {
        lock (_gate)
        {
            if (_through.TryGetValue(name, out var found)) return found;
            found = new();
            foreach (var (file, index) in Places(name))
            {
                if (Before(file.Masked, index) != '.' || OnThis(file.Masked, index)) continue;
                var m = AssignedAfter.Match(file.Masked, index + name.Length);
                if (!m.Success) continue;
                // The variable right before the dot: ctx in ctx.TimeStamp; a chain (a.b.TimeStamp) isn't one.
                var receiver = Regex.Match(file.Masked[Math.Max(0, index - 80)..index], @"(?<![\w.])(?<r>[A-Za-z_]\w*)\s*\??\.\s*$");
                if (!receiver.Success) continue;
                int start = m.Index + m.Length;
                int end = ExpressionEnd(file.Masked, start);
                var rhs = file.Text[start..end].Trim();
                if (rhs.Length > 0) found.Add((rhs, file, index, receiver.Groups["r"].Value));
            }
            _through[name] = found;
            return found;
        }
    }

    /// <summary>True when the repo declares a property or field of this name, set from elsewhere (binding, deserialising).</summary>
    public bool Declared(string name)
    {
        lock (_gate)
        {
            if (_declared.TryGetValue(name, out var known)) return known;
            known = Places(name).Any(p => AfterType(p.File.Masked, p.Index) && DeclaredAfter.IsMatch(p.File.Masked, p.Index + name.Length));
            _declared[name] = known;
            return known;
        }
    }

    /// <summary>
    /// The calls of one method, declared in <paramref name="file"/> at <paramref name="position"/>.
    /// Calls are found by name; when several types declare a method of that name, only calls in the
    /// same type, qualified with the type, or on a variable, field or property of that type count.
    /// </summary>
    public List<(CodeFile File, int Open)> CallersOf(string method, CodeFile file, int position)
    {
        bool unique = MethodDeclarations(method) <= 1;
        var owner = file.TypeAt(position);
        return Callers(method)
            .Where(c => !(c.File == file && Math.Abs(c.Open - position) < 2))
            .Where(c => unique && !OnKnownOtherType(c.File, c.Open, method, owner)
                        // An unqualified call belongs to the type it's made in (or an outer one): MainWindow's
                        // Write(text, ink) is not LinuxPackage.Write, even in the same file.
                        || (owner is null ? c.File == file : c.File.TypeAt(c.Open) == owner || c.File == file && c.File.InsideType(owner, c.Open))
                           && !OnOtherReceiver(c.File, c.Open, method, owner)
                        || owner is not null && Qualified(c.File, c.Open, method, owner))
            .Where(c => owner is null || !OnPropertyNamedLikeType(c.File, c.Open, method, owner))
            .ToList();
    }

    /// <summary>
    /// Session.Add(key) in the file that declares Pins.Add: a call on something else (a HashSet field), not on
    /// this type. A call with no receiver, on this, or on the type itself is the file's own.
    /// </summary>
    private bool OnOtherReceiver(CodeFile file, int open, string method, string? owner)
    {
        var before = file.Masked[Math.Max(0, open - 240)..open];
        var receiver = Regex.Match(before, $@"(?<r>[A-Za-z_]\w*)\s*\??\.\s*{Regex.Escape(method)}\s*(?:<[^<>]*>)?\s*\($").Groups["r"].Value;
        if (receiver.Length == 0 || receiver is "this" or "base" || receiver == owner) return false;
        if (owner is null) return true;
        return !Qualified(file, open, method, owner);
    }

    /// <summary>
    /// Session.Add(key) where Session is declared a HashSet&lt;string&gt;: the only Add the repo declares isn't this
    /// one. Only a receiver whose declared type is known and another type is ruled out.
    /// </summary>
    private bool OnKnownOtherType(CodeFile file, int open, string method, string? owner)
    {
        var before = file.Masked[Math.Max(0, open - 240)..open];
        var receiver = Regex.Match(before, $@"(?<r>[A-Za-z_]\w*)\s*\??\.\s*{Regex.Escape(method)}\s*(?:<[^<>]*>)?\s*\($").Groups["r"].Value;
        if (receiver.Length == 0 || receiver is "this" or "base" || receiver == owner || owner is null) return false;
        if (DeclaresType(receiver)) return receiver != owner;
        var declared = Regex.Match(file.Masked, $@"\b(?<t>[A-Za-z_]\w*)\s*(?:<[^<>;(){{}}=]*>)?\s*(?:\[\s*\])?\??\s+{Regex.Escape(receiver)}\s*(?:[=;{{,)]|=>)");
        if (!declared.Success || declared.Groups["t"].Value is "var" or "new" or "return" or "out" or "in" or "ref" or "is" or "as" or "using" or "await") return false;
        var t = declared.Groups["t"].Value;
        return t != owner && !Regex.IsMatch(t, "^I[A-Z]");
    }

    /// <summary>
    /// store.Pins.Add(pin) inside class Pins: a property that happens to share the type's name, so List.Add, not
    /// Pins.Add. Namespace.Pins.Add( (capitalised parts) is still the type.
    /// </summary>
    private static bool OnPropertyNamedLikeType(CodeFile file, int open, string method, string type)
    {
        var before = file.Masked[Math.Max(0, open - 240)..open];
        return Regex.IsMatch(before, $@"(?:\b[a-z_]\w*|\)|\])\s*\??\.\s*{Regex.Escape(type)}\s*\??\.\s*{Regex.Escape(method)}\s*(?:<[^<>]*>)?\s*\($");
    }

    /// <summary>Type.Method(, new Type(, or receiver.Method( where the receiver is declared as that type.</summary>
    private bool Qualified(CodeFile file, int open, string method, string type)
    {
        var before = file.Masked[Math.Max(0, open - 240)..open];
        var t = Regex.Escape(type);
        var m = Regex.Escape(method);
        // Type.Method(, Namespace.Type.Method(, new Type(, new Namespace.Type(.
        if (Regex.IsMatch(before, $@"\b{t}\s*\.\s*{m}\s*(?:<[^<>]*>)?\s*\($|\bnew\s+(?:[A-Za-z_]\w*\s*\.\s*)*{t}\s*\($")) return true;

        var receiver = Regex.Match(before, $@"(?<r>[A-Za-z_]\w*)\s*\??\.\s*{m}\s*(?:<[^<>]*>)?\s*\($").Groups["r"].Value;
        if (receiver.Length == 0) return false;
        if (receiver is "this" or "base") return file.TypeAt(open) == type;

        // Declared as the type here or anywhere in the repo: "TriageModel model", "model = new TriageModel(",
        // a property "TriageModel Model { get; }".
        if (Regex.IsMatch(file.Masked, $@"\b{t}\??\s+{Regex.Escape(receiver)}\b|\b{Regex.Escape(receiver)}\s*=\s*new\s+{t}\b")) return true;
        return Places(receiver).Any(p => Regex.IsMatch(p.File.Masked[Math.Max(0, p.Index - type.Length - 4)..p.Index], $@"\b{t}\??\s+$"));
    }

    private static readonly Regex FilledFrom = new(
        @"\b(?<how>Deserialize\w*|Get|GetValue)\s*<\s*(?<t>[A-Za-z_]\w*)\s*>\s*\(" +
        @"|\bnew\s+(?<how>XmlSerializer|DataContractSerializer|DataContractJsonSerializer)\s*\(\s*typeof\s*\(\s*(?<t>[A-Za-z_]\w*)\s*\)",
        RegexOptions.Compiled);
    private static readonly Regex PropertyOfType = new(
        @"\b(?:public|internal)\s+(?:required\s+)?(?:[A-Za-z_][\w.]*\s*<\s*)?(?<t>[A-Za-z_]\w*)\s*>?\s*(?:\[\])?\??\s+[A-Za-z_]\w*\s*\{",
        RegexOptions.Compiled);
    private Dictionary<string, string>? _settingTypes;

    /// <summary>
    /// The repo's own types that the shipped code fills from a file or configuration —
    /// JsonSerializer.Deserialize&lt;Config&gt;, new XmlSerializer(typeof(Config)), configuration.Get&lt;Config&gt;() —
    /// and the types of their properties one level down (a Site inside Config). Each with where it's filled.
    /// </summary>
    public IReadOnlyDictionary<string, string> SettingTypes
    {
        get
        {
            lock (_gate)
            {
                if (_settingTypes is not null) return _settingTypes;
                var found = new Dictionary<string, string>(StringComparer.Ordinal);
                foreach (var file in Files.Where(f => f.Origin != Origin.Tests))
                    foreach (Match m in FilledFrom.Matches(file.Masked))
                    {
                        var t = m.Groups["t"].Value;
                        var how = m.Groups["how"].Value;
                        if (how is "Get" or "GetValue" && !Regex.IsMatch(file.Masked[Math.Max(0, m.Index - 80)..m.Index], @"(?:Section|Configuration|config\w*)\s*(?:\([^()]*\))?\s*\.\s*$", RegexOptions.IgnoreCase)) continue;
                        if (!DeclaresType(t) || found.ContainsKey(t)) continue;
                        // A change set or a cache the app saves and reads back is its own data, not settings someone edits:
                        // what's in it was decided where it was made. Settings are types named for it.
                        if (!Regex.IsMatch(t, @"(?i)config|setting|option|preference")) continue;
                        var format = how.StartsWith("Deserialize", StringComparison.Ordinal) ? (file.Masked.Contains("Xml", StringComparison.Ordinal) && !file.Masked.Contains("Json", StringComparison.Ordinal) ? "XML" : "JSON")
                            : how.Contains("Xml", StringComparison.Ordinal) ? "XML" : how.StartsWith("DataContract", StringComparison.Ordinal) ? "XML or JSON" : "configuration";
                        found[t] = $"{format} at {file.Path}:{file.LineOf(m.Index)}";
                    }
                // One level down: the types of their properties, filled by the same call.
                foreach (var (type, where) in found.ToList())
                    foreach (var file in Files.Where(f => f.Origin != Origin.Tests))
                        foreach (Match m in PropertyOfType.Matches(file.Masked))
                            if (file.TypeAt(m.Index) == type && m.Groups["t"].Value is var inner && inner != type
                                && !found.ContainsKey(inner) && DeclaresType(inner))
                                found[inner] = where;
                return _settingTypes = found;
            }
        }
    }

    /// <summary>
    /// When a property of this name is declared in a type filled from settings: that type and where it's
    /// filled. The owner's type is preferred when it's known.
    /// </summary>
    public (string Type, string Where)? SettingOf(string name, string? ownerType = null)
    {
        var types = SettingTypes;
        if (types.Count == 0) return null;
        if (ownerType is not null && types.TryGetValue(ownerType, out var w) && DeclaresIn(name, ownerType)) return (ownerType, w);
        // AppPaths.BaseDirectory => AppContext.BaseDirectory: the owner computes it, so it's never filled
        // from a settings file, whatever another type's BaseDirectory is.
        if (ownerType is not null && !types.ContainsKey(ownerType) && Places(name).Any(p => p.File.TypeAt(p.Index) == ownerType
                && Regex.IsMatch(p.File.Masked[(p.Index + name.Length)..Math.Min(p.File.Masked.Length, p.Index + name.Length + 40)], @"^\s*(?:=>|\{\s*get\s*(?:=>|\{))")))
            return null;
        foreach (var (file, index) in Places(name))
        {
            if (file.Origin == Origin.Tests) continue;
            if (!Regex.IsMatch(file.Masked[(index + name.Length)..Math.Min(file.Masked.Length, index + name.Length + 40)], @"^\s*\{\s*(?:get|set|init|private|protected|internal)\b")) continue;
            if (file.TypeAt(index) is { } owner && types.TryGetValue(owner, out var where)) return (owner, where);
        }
        return null;
    }

    private bool DeclaresIn(string name, string type) =>
        Places(name).Any(p => p.File.TypeAt(p.Index) == type
            && Regex.IsMatch(p.File.Masked[(p.Index + name.Length)..Math.Min(p.File.Masked.Length, p.Index + name.Length + 40)], @"^\s*\{\s*(?:get|set|init|private|protected|internal)\b"));

    /// <summary>The words a dead end uses when only tests call the method: what the "Not called by the app" tag looks for.</summary>
    public const string OnlyTests = "only tests use it";

    /// <summary>
    /// Why a method has no call in the C#, as far as the source shows: XAML names it, it's passed on
    /// as a delegate, or nothing in the repo refers to it.
    /// </summary>

    private static readonly Regex PropertyDecl = new(
        @"\bpublic\s+(?<static>static\s+)?(?:required\s+|virtual\s+|override\s+|new\s+)*(?<t>[A-Za-z_][\w.]*(?:\s*<[^;{}()=]*?>)?\s*\??(?:\[\s*\])?)\s+(?<n>[A-Z]\w*)\s*\{\s*(?:get|init|set)\b",
        RegexOptions.Compiled);

    // Types whose objects reflection can make without running code of anyone else's: values, text, collections.
    private static readonly Regex Plain = new(
        @"^(?:bool|byte|sbyte|short|ushort|int|uint|long|ulong|float|double|decimal|char|string|object|DateTime|DateTimeOffset|TimeSpan|Guid|DateOnly|TimeOnly|Version|JsonNode|JsonElement)\??$|^(?:List|IList|IReadOnlyList|ICollection|IReadOnlyCollection|IEnumerable|HashSet|ISet|Dictionary|IDictionary|IReadOnlyDictionary|SortedDictionary|ImmutableArray|ImmutableList)\s*<|\[\s*\]$",
        RegexOptions.Compiled);

    /// <summary>
    /// Every type reflection can reach from these app types by walking their public properties: the types
    /// themselves, the property types of each, and theirs in turn. Null when one of them is neither the app's own
    /// nor a plain value, text or collection (a Uri, a Process, a type from a package), or the walk runs long.
    /// </summary>
    private Dictionary<string, List<string>>? _propertyTypes;

    /// <summary>The public instance property types each type of shipped code declares, worked out once.</summary>
    private Dictionary<string, List<string>> PropertyTypes
    {
        get
        {
            lock (_gate)
            {
                if (_propertyTypes is not null) return _propertyTypes;
                var map = new Dictionary<string, List<string>>(StringComparer.Ordinal);
                foreach (var file in Files.Where(f => f.Origin != Origin.Tests))
                    foreach (Match m in PropertyDecl.Matches(file.Masked))
                    {
                        if (m.Groups["static"].Success || file.TypeAt(m.Index) is not { } owner) continue;
                        if (!map.TryGetValue(owner, out var list)) map[owner] = list = new List<string>();
                        list.Add(Regex.Replace(m.Groups["t"].Value, @"\s+", ""));
                    }
                return _propertyTypes = map;
            }
        }
    }

    public List<string>? ReachableOwnTypes(IEnumerable<string> start)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var queue = new Queue<string>(start);
        while (queue.Count > 0)
        {
            var type = queue.Dequeue();
            if (!seen.Add(type)) continue;
            if (seen.Count > 200 || !DeclaresType(type)) return null;
            foreach (var t in PropertyTypes.TryGetValue(type, out var list) ? list : [])
                {
                    if (Plain.IsMatch(t)) continue;
                    var name = t.TrimEnd('?');
                    name = name[(name.LastIndexOf('.') + 1)..];
                    if (DeclaresType(name)) { if (!seen.Contains(name)) queue.Enqueue(name); continue; }
                    return null;
                }
        }
        return seen.ToList();
    }

    private static readonly Regex HashCall = new(@"\b(?:SHA(?:1|256|384|512)|MD5)\s*\.\s*(?:HashData|Create\s*\(\s*\)\s*\.\s*ComputeHash)\s*\(|\bIncrementalHash\s*\.\s*CreateHash\b", RegexOptions.Compiled);

    /// <summary>
    /// The hash a method returns, when it's one: every definition hashes with SHA-256 (or SHA-1, SHA-384, SHA-512,
    /// MD5) and returns the hash as text. "SHA-256", or null. GetHashCode isn't one: it isn't stable.
    /// </summary>
    public string? HashReturnedBy(string method, string? ownerType)
    {
        var defs = Members(method, true).Where(d => d.File.Origin != Origin.Tests).ToList();
        if (ownerType is not null && defs.Any(d => d.File.TypeAt(d.Position) == ownerType))
            defs = defs.Where(d => d.File.TypeAt(d.Position) == ownerType).ToList();
        if (defs.Count == 0) return null;
        string? algorithm = null;
        foreach (var (_, file, position) in defs)
        {
            int start = file.MemberStart(position);
            var body = file.Masked[start..Math.Min(file.Masked.Length, position + 200)];
            var m = HashCall.Match(body);
            if (!m.Success) return null;
            var a = Regex.Match(m.Value, @"SHA(?:1|256|384|512)|MD5").Value;
            algorithm ??= a.Length == 0 ? "SHA-256" : a.StartsWith("SHA") ? "SHA-" + a[3..] : a;
        }
        return algorithm;
    }

    /// <summary>The types in shipped code that declare a property of this name (with a getter, or as an expression).</summary>
    public List<string> PropertyOwners(string name) =>
        Places(name).Where(p => p.File.Origin != Origin.Tests
                                && Regex.IsMatch(p.File.Masked[(p.Index + name.Length)..Math.Min(p.File.Masked.Length, p.Index + name.Length + 30)], @"^\s*(?:\{\s*(?:get|set|init|private|protected|internal)\b|=>)")
                                && Before(p.File.Masked, p.Index) != '.')
            .Select(p => p.File.TypeAt(p.Index)).OfType<string>().Distinct().ToList();

    /// <summary>A list in a window whose selection is bound to a property: where it is, and what fills the list.</summary>
    public sealed record ListPick(string File, int Line, string Property, string? ItemsSource);

    private readonly Dictionary<string, List<ListPick>> _listPicks = new(StringComparer.Ordinal);

    /// <summary>
    /// The lists in the XAML that bind their selection to <paramref name="property"/>:
    /// SelectedItem="{Binding SelectedA}" on a ComboBox, ListBox, DataGrid or the like. What the user picks
    /// there is the property's value.
    /// </summary>
    public IReadOnlyList<ListPick> ListPicksOf(string property)
    {
        lock (_gate)
            if (_listPicks.TryGetValue(property, out var known)) return known;
        var found = new List<ListPick>();
        var bound = new Regex($@"\bSelected(?:Item|Value|Items)\s*=\s*""\{{Binding\s+(?:Path\s*=\s*)?{Regex.Escape(property)}\s*[,}}]");
        foreach (var x in _xaml)
            foreach (Match m in bound.Matches(x.Text!))
            {
                // The element the attribute sits on: from its '<' to its '>'.
                int open = x.Text!.LastIndexOf('<', m.Index);
                int close = x.Text.IndexOf('>', m.Index);
                var element = open < 0 || close < 0 ? "" : x.Text[open..close];
                var source = Regex.Match(element, @"\bItemsSource\s*=\s*""\{Binding\s+(?:Path\s*=\s*)?(?<p>[A-Za-z_][\w.]*)");
                int line = 1;
                for (int i = 0; i < m.Index; i++) if (x.Text[i] == '\n') line++;
                found.Add(new ListPick(x.Path, line, property, source.Success ? source.Groups["p"].Value : null));
            }
        lock (_gate) _listPicks[property] = found;
        return found;
    }

    /// <summary>What a collection is filled with: Snapshots.Add(x) and Snapshots.Insert(i, x), in shipped code.</summary>
    public List<(CodeFile File, int Position, string Item)> AddsTo(string collection)
    {
        var result = new List<(CodeFile, int, string)>();
        foreach (var (f, index) in Places(collection))
        {
            if (f.Origin == Origin.Tests) continue;
            var call = Regex.Match(f.Masked[(index + collection.Length)..Math.Min(f.Masked.Length, index + collection.Length + 20)], @"^\s*\.\s*(?<m>Add|Insert)\s*\(");
            if (!call.Success) continue;
            var args = f.Arguments(index + collection.Length + call.Length);
            var item = call.Groups["m"].Value == "Insert" ? (args.Count > 1 ? args[1] : null) : (args.Count > 0 ? args[0] : null);
            if (item is not null) result.Add((f, index, item.Trim()));
        }
        return result;
    }

    /// <summary>
    /// Where a method calls the delegate it's handed as argument <paramref name="argIndex"/>: for
    /// <c>Table(string number, Func&lt;string, …&gt; read, …)</c>, each <c>read(x)</c> or <c>read.Invoke(x)</c> in its body,
    /// with the argument at <paramref name="paramIndex"/>. A delegate handed on (<c>=> Build(path, read, …)</c>) is
    /// followed into that method too, a few steps deep. Shipped code only.
    /// </summary>
    public List<(CodeFile File, int Position, string Argument)> DelegateCalls(string method, int argIndex, int paramIndex, int depth = 0)
    {
        var found = new List<(CodeFile, int, string)>();
        if (depth > 3) return found;
        foreach (var (f, i) in Places(method).ToList())
        {
            if (f.Origin == Origin.Tests || !AfterType(f.Masked, i)) continue;
            var decl = MethodDeclarationAfter.Match(f.Masked, i + method.Length);
            if (!decl.Success) continue;
            int open = f.Masked.IndexOf('(', i + method.Length);
            if (open < 0) continue;
            var ps = ParameterList(f, open + 1);
            if (argIndex >= ps.Count) continue;
            var p = Regex.Replace(ps[argIndex], @"\s*=.*$", "", RegexOptions.Singleline);
            var pn = Regex.Match(p, @"(?<n>[A-Za-z_]\w*)\s*$").Groups["n"].Value;
            if (pn.Length == 0 || !Regex.IsMatch(p, @"\b(?:Func|Action|Predicate|Converter)\s*<|\bdelegate\b|^\s*[A-Z]\w*(?:Handler|Callback|Reader|Factory)\b")) continue;
            int close = f.AfterArguments(open + 1);
            if (close < 0) continue;
            int bodyStart = close, bodyEnd;
            var arrow = Regex.Match(f.Masked[close..Math.Min(f.Masked.Length, close + 200)], @"^\s*(?:where\b[^{=]*)?(?<k>=>|\{)");
            if (!arrow.Success) continue;
            bodyStart = close + arrow.Groups["k"].Index;
            bodyEnd = arrow.Groups["k"].Value == "{" ? f.MatchingBrace(bodyStart) : ExpressionEnd(f.Masked, bodyStart + 2);
            if (bodyEnd <= bodyStart) continue;
            foreach (int k in Places(pn).Where(q => q.File == f && q.Index > bodyStart && q.Index < bodyEnd).Select(q => q.Index))
            {
                if (k > 0 && (f.Masked[k - 1] == '.' || IsNameChar(f.Masked[k - 1]))) continue;
                var after = f.Masked[(k + pn.Length)..Math.Min(f.Masked.Length, k + pn.Length + 30)];
                var call = Regex.Match(after, @"^\s*(?:\?\s*\.\s*Invoke|\.\s*Invoke)?\s*\(");
                if (call.Success)
                {
                    var args = f.Arguments(k + pn.Length + call.Length);
                    if (paramIndex < args.Count) found.Add((f, k, args[paramIndex]));
                    continue;
                }
                // Handed on: Build(path, read, columns): the same delegate, now that method's argument.
                if (!Regex.IsMatch(after, @"^\s*[,)]")) continue;
                if (EnclosingCall(f, k, bodyStart) is not { } around || around.Method == method) continue;
                found.AddRange(DelegateCalls(around.Method, around.ArgIndex, paramIndex, depth + 1));
            }
        }
        return found.Distinct().ToList();
    }

    /// <summary>A declaration's parameters, split at top-level commas: Func&lt;string, string, bool&gt; edit stays one.</summary>
    private static List<string> ParameterList(CodeFile f, int start)
    {
        var list = new List<string>();
        int depth = 0, from = start;
        for (int i = start; i < f.Masked.Length && i < start + 3000; i++)
        {
            char c = f.Masked[i];
            if (c is '(' or '[' or '{' or '<') depth++;
            else if (c is ']' or '}' or '>') depth--;
            else if (c == ')')
            {
                if (depth == 0) { if (i > from || list.Count > 0) list.Add(f.Text[from..i].Trim()); return list; }
                depth--;
            }
            else if (c == ',' && depth == 0) { list.Add(f.Text[from..i].Trim()); from = i + 1; }
            else if (c == ';') break;
        }
        return list;
    }

    /// <summary>The call a name stands in as one whole argument: Change(entry, confirm, DictionaryEditor.Pin, …) for Pin.</summary>
    private static (string Method, int ArgIndex)? EnclosingCall(CodeFile f, int k, int limit)
    {
        // Back over a qualifier: DictionaryEditor.Pin, this.Pin.
        int start = k;
        while (start > 1 && f.Masked[start - 1] == '.' && IsNameChar(f.Masked[start - 2]))
        {
            start -= 2;
            while (start > 0 && IsNameChar(f.Masked[start - 1])) start--;
        }
        int callOpen = -1, level = 0;
        for (int b = start - 1; b > limit; b--)
        {
            char c = f.Masked[b];
            if (c is ')' or ']' or '}') level++;
            else if (c is '(' or '[' or '{') { if (level-- == 0) { callOpen = b; break; } }
            else if (c == ';') break;
        }
        if (callOpen < 0 || f.Masked[callOpen] != '(') return null;
        var callee = Regex.Match(f.Masked[Math.Max(0, callOpen - 80)..callOpen], @"(?<w>[A-Za-z_]\w*)\s*(?:<[^<>()]*>)?\s*$").Groups["w"].Value;
        if (callee.Length == 0 || callee is "nameof" or "typeof" or "if" or "while" or "foreach" or "using" or "lock" or "switch") return null;
        var args = f.Arguments(callOpen + 1);
        int depth = 0, index = 0;
        for (int i = callOpen + 1; i < start; i++)
        {
            char c = f.Masked[i];
            if (c is '(' or '[' or '{') depth++;
            else if (c is ')' or ']' or '}') depth--;
            else if (c == ',' && depth == 0) index++;
        }
        return index < args.Count && Regex.IsMatch(args[index], @"^[\w.]+$") ? (callee, index) : null;
    }

    /// <summary>
    /// Where a method is handed to another as a delegate (Change(entry, confirm, DictionaryEditor.Pin)), what that
    /// method passes when it calls it: its argument at <paramref name="paramIndex"/>. Shipped code only.
    /// </summary>
    public List<(CodeFile File, int Position, string Argument)> HandedAsDelegate(string method, CodeFile file, int position, int paramIndex)
    {
        var found = new List<(CodeFile, int, string)>();
        foreach (var (f, index) in Places(method).ToList())
        {
            if (f.Origin == Origin.Tests && file.Origin != Origin.Tests) continue;
            if (f == file && Math.Abs(index - position) < method.Length + 400 && AfterType(f.Masked, index)) continue;
            if (CallAfter.IsMatch(f.Masked, index + method.Length)) continue;
            if (!Regex.IsMatch(f.Masked[(index + method.Length)..Math.Min(f.Masked.Length, index + method.Length + 20)], @"^\s*[,)]")) continue;
            if (EnclosingCall(f, index, Math.Max(0, index - 4000)) is not { } around || around.Method == method) continue;
            found.AddRange(DelegateCalls(around.Method, around.ArgIndex, paramIndex));
        }
        return found.Distinct().ToList();
    }

    /// <summary>An XAML attribute that names an event handler: Click, Loaded, SelectionChanged, PreviewKeyDown, Button.Click …</summary>
    private const string XamlEvent = @"(?:[A-Za-z]\w*\.)?(?:Click|DoubleClick|MouseDoubleClick|Checked|Unchecked|Indeterminate|Loaded|Unloaded|Initialized|"
        + @"Closing|Closed|Activated|Deactivated|ContentRendered|Opened|Tick|Executed|CanExecute|PreviewExecuted|PreviewCanExecute|"
        + @"Drop|Sorting|Scroll|Expanded|Collapsed|Selected|Unselected|SourceUpdated|TargetUpdated|SubmenuOpened|SubmenuClosed|"
        + @"Navigated|Navigating|LoadCompleted|NavigationCompleted|NavigationStarting|CoreWebView2InitializationCompleted|"
        + @"\w*Changed|\w*Changing|Preview\w+|Key(?:Down|Up)|Mouse\w+|Drag\w+|Got\w*Focus|Lost\w*Focus|Touch\w+|Stylus\w+|"
        + @"Manipulation\w+|Request\w+|Context\w+|Text(?:Input)|Validation\w*|Error)";

    public string UsageOf(string method, CodeFile file, int position)
    {
        // Only an event attribute wires a method up (Click="OnSave"); a button's text (Content="Save") doesn't.
        var xaml = _xaml.FirstOrDefault(x => Regex.IsMatch(x.Text!, $@"(?<![\w.:]){XamlEvent}\s*=\s*""{Regex.Escape(method)}"""));
        if (xaml is not null) return $"which nothing in the C# calls; {xaml.Path} names it, so XAML wires it up";

        // Shipped code is judged by shipped code: a test that calls it or passes it on doesn't explain the app.
        string? inTests = null;
        foreach (var (f, index) in Places(method))
        {
            if (f == file && Math.Abs(index - position) < method.Length + 400 && AfterType(f.Masked, index)) continue; // the declaration
            bool test = file.Origin != Origin.Tests && f.Origin == Origin.Tests;
            if (CallAfter.IsMatch(f.Masked, index + method.Length))
            {
                if (test) inTests ??= $"{f.Path}:{f.LineOf(index)}";
                continue;
            }
            if (AfterType(f.Masked, index) && MethodDeclarationAfter.IsMatch(f.Masked, index + method.Length)) continue;
            if (test) { inTests ??= $"{f.Path}:{f.LineOf(index)}"; continue; }
            return $"which nothing in the C# calls; it's passed on as a delegate at {f.Path}:{f.LineOf(index)}";
        }
        if (inTests is not null) return $"which nothing in the app calls; {OnlyTests} ({inTests})";
        return "which nothing in the repo calls (an interface, reflection, a framework, or code outside the repo)";
    }

    /// <summary>Calls of a method (or constructor) by name: the position just after each opening parenthesis.</summary>
    public List<(CodeFile File, int Open)> Callers(string method)
    {
        lock (_gate)
        {
            if (_callers.TryGetValue(method, out var found)) return found;
            found = new List<(CodeFile, int)>();
            foreach (var (file, index) in Places(method))
            {
                var m = CallAfter.Match(file.Masked, index + method.Length);
                if (!m.Success) continue;
                int open = m.Index + m.Length;
                int after = file.AfterArguments(open);
                if (after < 0) continue;
                // A declaration, not a call: a body or => follows the parameter list.
                var rest = file.Masked.AsSpan(after, Math.Min(200, file.Masked.Length - after)).TrimStart();
                if (rest.StartsWith("{") || rest.StartsWith("=>") || rest.StartsWith("where ")
                    || (rest.StartsWith(":") && Regex.IsMatch(rest.ToString(), @"^:\s*(?:base|this)\s*\("))) continue;
                found.Add((file, open));
            }
            _callers[method] = found;
            return found;
        }
    }

    private static readonly Regex ReturnValue = new(@"\breturn\b", RegexOptions.Compiled);

    private static readonly Regex TargetTypedNew = new(@"\bnew\s*\(", RegexOptions.Compiled);

    /// <summary>
    /// Target-typed "new(…)" that makes a <paramref name="type"/>: in a member declared to return it
    /// (=> new(…) or return new(…)), or assigned to a variable of that type. The position just after "(".
    /// </summary>
    private readonly Dictionary<string, List<(CodeFile, int)>> _targetTyped = new(StringComparer.Ordinal);

    public List<(CodeFile File, int Open)> TargetTypedNews(string type)
    {
        lock (_gate)
            if (_targetTyped.TryGetValue(type, out var cached)) return cached;
        var returns = new Regex(@"\b" + Regex.Escape(type) + @"\??\s+[A-Za-z_]\w*\s*(?:<[^<>()]*>)?\s*\(");
        var assigned = new Regex(@"\b" + Regex.Escape(type) + @"\??\s+[A-Za-z_]\w*\s*=\s*$");
        var found = new List<(CodeFile, int)>();
        foreach (var file in Files)
        {
            if (!file.Masked.Contains(type, StringComparison.Ordinal)) continue;
            foreach (Match m in TargetTypedNew.Matches(file.Masked))
            {
                int statement = file.Masked.LastIndexOfAny([';', '{', '}'], Math.Max(0, m.Index - 1)) + 1;
                var head = file.Masked[statement..m.Index];
                bool makes = assigned.IsMatch(head)
                    || Regex.IsMatch(head, @"=>\s*$") && returns.IsMatch(head);
                // In a list of them: IReadOnlyList<SettingInfo> All = [ new(…), new(…) ], new List<T> { new(…) }, T[] x = { new(…) }.
                if (!makes && Opener(file.Masked, m.Index) is int opener and > 0)
                {
                    var before = file.Masked[Math.Max(0, opener - 200)..opener];
                    makes = Regex.IsMatch(before, @"(?:<\s*" + Regex.Escape(type) + @"\s*>|\b" + Regex.Escape(type) + @"\s*\[\s*\])[^;{}\[\]]*$");
                }
                if (!makes && Regex.IsMatch(head, @"^\s*return\s*$"))
                {
                    int start = file.MemberStart(m.Index);
                    int brace = file.Masked.IndexOf('{', start);
                    makes = brace > start && brace < m.Index && returns.IsMatch(file.Masked[start..brace]);
                }
                if (makes) found.Add((file, m.Index + m.Length));
            }
        }
        lock (_gate) _targetTyped[type] = found;
        return found;
    }

    private static readonly Regex TypeBefore = new(@"(?<![\w.])(?<t>[A-Za-z_]\w*)(?:<[^<>;(){}]*>)?(?:\[\])?\??\s+$", RegexOptions.Compiled | RegexOptions.RightToLeft);
    private static readonly Regex NewAfter = new(@"\G\s*=\s*new\s+(?<t>[A-Za-z_]\w*)", RegexOptions.Compiled);
    private readonly Dictionary<(CodeFile File, int Member, string Name), string?> _variableTypes = new();

    /// <summary>The unmatched '[' or '{' around a position (the list it sits in), or -1.</summary>
    private static int Opener(string text, int position)
    {
        int depth = 0;
        for (int i = position - 1; i >= 0 && position - i < 200_000; i--)
        {
            char c = text[i];
            if (c is ')' or ']' or '}') depth++;
            else if (c is '(' or '[' or '{')
            {
                if (depth == 0) return c == '(' ? -1 : i;
                depth--;
            }
            else if (c == ';' && depth == 0) return -1;
        }
        return -1;
    }

    /// <summary>
    /// The type a variable is declared as, in its member before <paramref name="position"/> or as a field
    /// of the file: "Uri? targetUri", "x = new HttpClient(". Null when the source doesn't say.
    /// Read from the name index, so it costs a few short look-behinds per use.
    /// </summary>
    private static readonly Regex Sequence = new(@"\b(?:IReadOnlyList|IReadOnlyCollection|IEnumerable|IList|ICollection|List|HashSet|ImmutableArray|ImmutableList)\s*<\s*(?<t>[A-Za-z_][\w.]*)\s*>\s*$|(?<t>[A-Za-z_][\w.]*)\s*\[\s*\]\s*$", RegexOptions.Compiled);

    /// <summary>
    /// "in Citations.Split(text)" after a foreach variable: the item type the called method's declaration
    /// returns (IReadOnlyList&lt;Piece&gt; gives Piece), when the repo declares that method, in shipped code, once.
    /// </summary>
    private string? ForeachItemType(CodeFile file, int afterName)
    {
        var call = Regex.Match(file.Masked[afterName..Math.Min(file.Masked.Length, afterName + 200)],
            @"^\s+in\s+(?:(?:[A-Za-z_]\w*\s*\.\s*)*(?<owner>[A-Z]\w*)\s*\.\s*)?(?<m>[A-Za-z_]\w*)\s*\(");
        if (!call.Success) return null;
        string method = call.Groups["m"].Value, owner = call.Groups["owner"].Value;
        var types = new HashSet<string>(StringComparer.Ordinal);
        foreach (var (f, index) in Places(method))
        {
            if (f.Origin == Origin.Tests) continue;
            if (!Regex.IsMatch(f.Masked[(index + method.Length)..Math.Min(f.Masked.Length, index + method.Length + 3)], @"^\s*\(")) continue;
            if (owner.Length > 0 && f.TypeAt(index) != owner) continue;
            var returned = Sequence.Match(f.Masked[Math.Max(0, index - 120)..index].TrimEnd());
            if (returned.Success) types.Add(returned.Groups["t"].Value.Split('.')[^1]);
        }
        return types.Count == 1 ? types.First() : null;
    }

    public string? TypeOfVariable(string name, CodeFile file, int position)
    {
        int member = file.MemberStart(position);
        lock (_gate)
            if (_variableTypes.TryGetValue((file, member, name), out var known)) return known;

        string? inMember = null, inFile = null;
        foreach (var (f, index) in Places(name))
        {
            if (f != file) continue;
            string? type = null;
            var made = NewAfter.Match(file.Masked, index + name.Length);
            if (made.Success) type = made.Groups["t"].Value;
            else
            {
                var before = TypeBefore.Match(file.Masked[Math.Max(0, index - 120)..index]);
                if (before.Success && before.Groups["t"].Value is var t
                    && t is not ("var" or "return" or "new" or "out" or "ref" or "in" or "is" or "as" or "await" or "else" or "case" or "using" or "yield" or "throw"))
                    type = t;
            }
            // foreach (var piece in Citations.Split(text)): the item type of what the method returns.
            if (type is null && Regex.IsMatch(file.Masked[Math.Max(0, index - 40)..index], @"\bforeach\s*\(\s*var\s+$"))
                type = ForeachItemType(file, index + name.Length);
            if (type is null) continue;
            if (index >= member && index < position) inMember = type;
            else inFile ??= type;
        }
        var result = inMember ?? inFile;
        lock (_gate) _variableTypes[(file, member, name)] = result;
        return result;
    }
}
