using System.Text.RegularExpressions;
using CSharpLexing;

namespace RepoLegibility.Core;

/// <summary>What a piece of a code line is, for colouring it.</summary>
public enum SpanKind
{
    Plain,
    Keyword,
    String,
    Number,
    Comment,
    /// <summary>A type or namespace name, as far as the source shows without compiling it.</summary>
    Type
}

/// <summary>A piece of a code line and what it is.</summary>
public readonly record struct CodeSpan(string Text, SpanKind Kind);

/// <summary>
/// Basic C# colouring for the code excerpts: keywords, strings, numbers, comments. The excerpt is
/// lexed as one block, so comments and strings that run over several lines stay coloured to their
/// end; holes in interpolated strings ($"…{x}…") are code again. Types and namespaces are told by
/// their place (after new, typeof, is, as, ':' or '[', inside &lt;…&gt;, before a name, in a using or
/// namespace line, the capitalised parts of System.IO.Path) — without a compiler a capitalised
/// property can be coloured as a type too, which is harmless.
/// </summary>
public static class Highlight
{
    private static readonly HashSet<string> Keywords = new(StringComparer.Ordinal)
    {
        "abstract", "as", "async", "await", "base", "bool", "break", "byte", "case", "catch", "char", "checked",
        "class", "const", "continue", "decimal", "default", "delegate", "do", "double", "else", "enum", "event",
        "explicit", "extern", "false", "finally", "fixed", "float", "for", "foreach", "get", "goto", "if",
        "implicit", "in", "init", "int", "interface", "internal", "is", "lock", "long", "namespace", "new", "not",
        "null", "object", "operator", "or", "and", "out", "override", "params", "partial", "private", "protected",
        "public", "readonly", "record", "ref", "required", "return", "sbyte", "sealed", "set", "short", "sizeof",
        "stackalloc", "static", "string", "struct", "switch", "this", "throw", "true", "try", "typeof", "uint",
        "ulong", "unchecked", "unsafe", "ushort", "using", "value", "var", "virtual", "void", "volatile", "when",
        "where", "while", "with", "yield", "nint", "nuint", "dynamic", "global", "file", "scoped", "let", "from",
        "select", "orderby", "group", "into", "join", "on", "equals", "by", "ascending", "descending", "add", "remove"
    };

    // Accessor words: keywords only before ; { or => (get; set; init => …).
    private static readonly HashSet<string> Accessors = new(StringComparer.Ordinal) { "get", "set", "init", "add", "remove" };

    // Query words: keywords only when a name follows (from x in …, select x).
    private static readonly HashSet<string> Query = new(StringComparer.Ordinal)
        { "let", "from", "select", "orderby", "group", "into", "join", "on", "equals", "by", "ascending", "descending" };

    // Other contextual words: keywords unless used as a name (var = 1;, x.await, record,).
    private static readonly HashSet<string> Contextual = new(StringComparer.Ordinal)
        { "var", "async", "await", "yield", "record", "required", "partial", "when", "where", "with", "not", "and", "or",
          "dynamic", "global", "scoped", "nint", "nuint" };

    private static readonly Regex Word = new(@"@?[A-Za-z_]\w*|(?<![\w.])(?:0[xX][0-9A-Fa-f_]+|0[bB][01_]+|\d[\d_]*(?:\.\d[\d_]*)?(?:[eE][+-]?\d+)?)[uUlLfFdDmM]{0,2}", RegexOptions.Compiled);

    /// <summary>Each line of <paramref name="lines"/> as coloured pieces; tabs become four spaces.</summary>
    public static IReadOnlyList<IReadOnlyList<CodeSpan>> Lines(IReadOnlyList<string> lines)
    {
        var code = string.Join("\n", lines);
        CSharpLexer.Kind[] kinds;
        try
        {
            kinds = CSharpLexer.Classify(code);
        }
        catch (RegexMatchTimeoutException)
        {
            return lines.Select(l => (IReadOnlyList<CodeSpan>)[new CodeSpan(l.Replace("\t", "    "), SpanKind.Plain)]).ToList();
        }

        var kind = new SpanKind[code.Length];
        for (int i = 0; i < code.Length; i++)
            kind[i] = kinds[i] switch
            {
                CSharpLexer.Kind.Comment => SpanKind.Comment,
                CSharpLexer.Kind.String or CSharpLexer.Kind.Char => SpanKind.String,
                CSharpLexer.Kind.Directive => SpanKind.Keyword,
                _ => SpanKind.Plain
            };

        // Words and numbers in code: keywords, numeric literals, types and namespaces.
        string previous = "";
        bool previousType = false, typeChain = false;
        foreach (Match m in Word.Matches(code))
        {
            if (kinds[m.Index] != CSharpLexer.Kind.Code) { previous = ""; previousType = false; continue; }
            SpanKind? found = char.IsDigit(m.Value[0]) ? SpanKind.Number
                : IsKeyword(code, m) ? SpanKind.Keyword
                : IsType(code, m, previous, previousType, ref typeChain) ? SpanKind.Type
                : null;
            previous = m.Value;
            previousType = found == SpanKind.Type;
            if (found is not { } k) continue;
            for (int i = m.Index; i < m.Index + m.Length; i++) kind[i] = k;
        }

        var result = new List<IReadOnlyList<CodeSpan>>(lines.Count);
        int start = 0;
        foreach (var line in lines)
        {
            var spans = new List<CodeSpan>();
            int i = start, end = start + line.Length;
            while (i < end)
            {
                int j = i;
                while (j < end && kind[j] == kind[i]) j++;
                spans.Add(new CodeSpan(code[i..j].Replace("\t", "    "), kind[i]));
                i = j;
            }
            result.Add(spans);
            start = end + 1;
        }
        return result;
    }

    private static readonly HashSet<string> XmlExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".csproj", ".vbproj", ".fsproj", ".props", ".targets", ".xml", ".manifest", ".xaml", ".config", ".resx",
        ".nuspec", ".pubxml", ".slnx", ".runsettings", ".ruleset", ".vsixmanifest", ".wxs", ".appxmanifest"
    };

    /// <summary>A file shown with XML colouring: project and build files, manifests, XAML.</summary>
    public static bool IsXml(string path) => XmlExtensions.Contains(System.IO.Path.GetExtension(path));

    /// <summary>
    /// XML colouring with the same five kinds, as the kit's guide maps them: a tag's name is a keyword,
    /// an attribute's name a type, a value a string, a comment a comment. Brackets, text and entities
    /// stay plain. The excerpt is read as one block, so a comment over several lines stays a comment.
    /// </summary>
    public static IReadOnlyList<IReadOnlyList<CodeSpan>> Xml(IReadOnlyList<string> lines)
    {
        var code = string.Join("\n", lines);
        var kind = new SpanKind[code.Length];
        int i = 0;
        void Mark(int from, int to, SpanKind k) { for (int x = from; x < to && x < kind.Length; x++) kind[x] = k; }
        while (i < code.Length)
        {
            if (code[i] != '<') { i++; continue; }
            if (string.CompareOrdinal(code, i, "<!--", 0, 4) == 0)
            {
                int end = code.IndexOf("-->", i + 4, StringComparison.Ordinal);
                end = end < 0 ? code.Length : end + 3;
                Mark(i, end, SpanKind.Comment);
                i = end;
                continue;
            }
            if (string.CompareOrdinal(code, i, "<![CDATA[", 0, 9) == 0)
            {
                int end = code.IndexOf("]]>", i + 9, StringComparison.Ordinal);
                end = end < 0 ? code.Length : end + 3;
                Mark(i, end, SpanKind.String);
                i = end;
                continue;
            }
            // <name, </name, <?name, <!DOCTYPE: the name is the keyword; then attributes until the closing >.
            int j = i + 1;
            if (j < code.Length && code[j] is '/' or '?' or '!') j++;
            int nameStart = j;
            while (j < code.Length && (char.IsLetterOrDigit(code[j]) || code[j] is '_' or '-' or '.' or ':')) j++;
            Mark(nameStart, j, SpanKind.Keyword);
            while (j < code.Length && code[j] != '>' && code[j] != '<')
            {
                char c = code[j];
                if (c is '"' or '\'')
                {
                    int end = code.IndexOf(c, j + 1);
                    end = end < 0 ? code.Length : end + 1;
                    Mark(j, end, SpanKind.String);
                    j = end;
                    continue;
                }
                if (char.IsLetter(c) || c == '_')
                {
                    int a = j;
                    while (j < code.Length && (char.IsLetterOrDigit(code[j]) || code[j] is '_' or '-' or '.' or ':')) j++;
                    Mark(a, j, SpanKind.Type);
                    continue;
                }
                j++;
            }
            i = j < code.Length && code[j] == '>' ? j + 1 : j;
        }
        return Split(code, kind, lines);
    }

    /// <summary>The block cut back into its lines, each as runs of one kind; tabs become four spaces.</summary>
    private static List<IReadOnlyList<CodeSpan>> Split(string code, SpanKind[] kind, IReadOnlyList<string> lines)
    {
        var result = new List<IReadOnlyList<CodeSpan>>(lines.Count);
        int start = 0;
        foreach (var line in lines)
        {
            var spans = new List<CodeSpan>();
            int i = start, end = start + line.Length;
            while (i < end)
            {
                int j = i;
                while (j < end && kind[j] == kind[i]) j++;
                spans.Add(new CodeSpan(code[i..j].Replace("\t", "    "), kind[i]));
                i = j;
            }
            result.Add(spans);
            start = end + 1;
        }
        return result;
    }

    private static bool IsType(string code, Match m, string previous, bool previousType, ref bool typeChain)
    {
        var w = m.Value;
        if (!char.IsUpper(w[0])) return false;

        int before = m.Index - 1;
        while (before >= 0 && code[before] is ' ' or '\t') before--;
        char prevChar = before >= 0 ? code[before] : '\0';
        int after = m.Index + m.Length;
        while (after < code.Length && code[after] is ' ' or '\t') after++;
        char next = after < code.Length ? code[after] : '\0';

        if (prevChar == '.')
        {
            // System.IO.Path.Combine: the capitalised parts before the method. BindingFlags.Public: a member, plain.
            if (!previousType) return false;
            if (next == '.') return true;
            if (typeChain) return next != '(' || IsCtorChain(code, m.Index);
            return char.IsLetter(next) || next is '_' or '<' || next == '?' && after + 1 < code.Length && code[after + 1] is ' ' or '\t' or '>';
        }

        // The first part of a name: where it stands says whether it's a type.
        typeChain = previous is "new" or "typeof" or "using" or "namespace" or "is" or "as" || prevChar is '[' or '<' or ':';
        if (next == '(') return previous == "new" || prevChar == '[';   // a constructor or an attribute; a call stays plain
        return true;
    }

    /// <summary>new System.Text.StringBuilder(…): the last part of a chain started by new (or '[') is the type.</summary>
    private static bool IsCtorChain(string code, int index)
    {
        int k = index;
        while (k > 0 && (char.IsLetterOrDigit(code[k - 1]) || code[k - 1] is '_' or '.' or ' ')) k--;
        // …or an attribute: [System.Diagnostics.CodeAnalysis.RequiresUnreferencedCode(…)].
        return code[k..index].TrimStart().StartsWith("new ", StringComparison.Ordinal) || k > 0 && code[k - 1] == '[';
    }

    private static bool IsKeyword(string code, Match m)
    {
        var w = m.Value;
        if (w[0] == '@' || !Keywords.Contains(w) || w is "value" or "file") return false;

        int before = m.Index - 1;
        while (before >= 0 && code[before] is ' ' or '\t') before--;
        if (before >= 0 && code[before] == '.') return false;   // a member named like a keyword

        int after = m.Index + m.Length;
        while (after < code.Length && code[after] is ' ' or '\t') after++;
        char next = after < code.Length ? code[after] : '\0';
        char next2 = after + 1 < code.Length ? code[after + 1] : '\0';

        if (Accessors.Contains(w)) return next is ';' or '{' || next == '=' && next2 == '>';
        if (Query.Contains(w)) return char.IsLetter(next) || next == '_';
        if (Contextual.Contains(w)) return !(next is '=' or ';' or ',' or ')' or '.' or '[' or ']' or '}') || next == '=' && next2 == '>';
        return true;
    }
}
