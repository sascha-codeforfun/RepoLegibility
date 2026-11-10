using System.Text;
using System.Text.RegularExpressions;

namespace RepoLegibility.Core;

/// <summary>
/// Works out values the source fixes but hides: "ht" + "tp" + …, new string(new[] { 'S', … }),
/// Encoding.UTF8.GetString(Convert.FromBase64String("…")), (char)115, and PowerShell's -EncodedCommand.
/// Pure computation on literals in the source: nothing is run. Anything it can't work out exactly
/// (a variable, a call it doesn't know) makes it give up, so a value it returns is the real one.
/// </summary>
public static class Fold
{
    private const int MaxLength = 4096;

    private static readonly Regex CharArray = new(
        @"^new\s+string\s*\(\s*new\s*(?:char\s*)?\[\s*\]\s*\{(?<items>[^{}]*)\}\s*\)$", RegexOptions.Compiled);
    private static readonly Regex Decode = new(
        @"^(?:System\.Text\.)?Encoding\s*\.\s*(?<enc>UTF8|ASCII|Unicode|Latin1|Default|UTF32|BigEndianUnicode)\s*\.\s*GetString\s*\(\s*(?:System\.)?Convert\s*\.\s*FromBase64String\s*\((?<inner>.*)\)\s*\)$",
        RegexOptions.Compiled | RegexOptions.Singleline);
    private static readonly Regex CharCode = new(@"^\(\s*char\s*\)\s*(?<n>0[xX][0-9A-Fa-f]+|\d+)$", RegexOptions.Compiled);
    private static readonly Regex StringConcat = new(@"^string\s*\.\s*Concat\s*\((?<args>.*)\)$", RegexOptions.Compiled | RegexOptions.Singleline);
    private static readonly Regex EncodedCommand = new(
        @"(?:^|\s)-(?:e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\s+(?<b64>[A-Za-z0-9+/]{4,}={0,2})(?=\s|$|['""])",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    /// <summary>The value of an expression made only of literals and the known hiding tricks, or null.</summary>
    public static string? Value(string expression)
    {
        try
        {
            var result = Expr(expression.Trim());
            return result is { Length: > 0 and <= MaxLength } ? result : null;
        }
        catch (FormatException)
        {
            return null;
        }
        catch (ArgumentException)
        {
            return null;
        }
    }

    /// <summary>The script hidden in powershell -EncodedCommand (Base64 of UTF-16LE), or null.</summary>
    public static string? PowerShell(string command)
    {
        var m = EncodedCommand.Match(command);
        if (!m.Success) return null;
        try
        {
            var bytes = Convert.FromBase64String(m.Groups["b64"].Value);
            if (bytes.Length == 0 || bytes.Length % 2 != 0) return null;
            var text = Encoding.Unicode.GetString(bytes);
            return text.Length > 0 && text.All(c => !char.IsControl(c) || c is '\r' or '\n' or '\t') ? text : null;
        }
        catch (FormatException)
        {
            return null;
        }
    }

    private static string? Expr(string e)
    {
        e = StripParens(e);
        var terms = SplitTop(e, '+');
        if (terms is null) return null;
        if (terms.Count > 1)
        {
            var sb = new StringBuilder();
            foreach (var term in terms)
            {
                if (Term(term.Trim()) is not { } v) return null;
                sb.Append(v);
                if (sb.Length > MaxLength) return null;
            }
            return sb.ToString();
        }
        return Term(e);
    }

    private static string? Term(string t)
    {
        t = StripParens(t);
        if (t.Length == 0) return null;
        if (t[0] == '"' || t.StartsWith("@\"", StringComparison.Ordinal)) return StringLiteral(t);
        if (t[0] == '\'') return CharLiteral(t) is { } c ? c.ToString() : null;

        var code = CharCode.Match(t);
        if (code.Success)
        {
            var n = code.Groups["n"].Value;
            int value = n.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? Convert.ToInt32(n[2..], 16) : int.Parse(n);
            return value is > 0 and <= 0xFFFF ? ((char)value).ToString() : null;
        }

        var array = CharArray.Match(t);
        if (array.Success)
        {
            var items = SplitTop(array.Groups["items"].Value, ',');
            if (items is null) return null;
            var sb = new StringBuilder();
            foreach (var item in items)
            {
                var x = item.Trim();
                if (x.Length == 0) continue;
                if (x[0] == '\'' && CharLiteral(x) is { } c) sb.Append(c);
                else if (Term(CharCode.IsMatch(x) ? x : "(char)" + x) is { } s) sb.Append(s);   // 'S' or 83 or (char)83
                else return null;
            }
            return sb.ToString();
        }

        var decode = Decode.Match(t);
        if (decode.Success)
        {
            if (Expr(decode.Groups["inner"].Value) is not { } b64) return null;
            var bytes = Convert.FromBase64String(b64);
            Encoding enc = decode.Groups["enc"].Value switch
            {
                "ASCII" => Encoding.ASCII,
                "Unicode" => Encoding.Unicode,
                "Latin1" => Encoding.Latin1,
                "UTF32" => Encoding.UTF32,
                "BigEndianUnicode" => Encoding.BigEndianUnicode,
                _ => Encoding.UTF8
            };
            return enc.GetString(bytes);
        }

        var concat = StringConcat.Match(t);
        if (concat.Success && SplitTop(concat.Groups["args"].Value, ',') is { } parts)
        {
            var sb = new StringBuilder();
            foreach (var p in parts)
                if (Expr(p) is { } v) sb.Append(v); else return null;
            return sb.ToString();
        }
        return null;
    }

    private static string? StringLiteral(string t)
    {
        if (t.StartsWith("@\"", StringComparison.Ordinal))
        {
            if (t.Length < 3 || t[^1] != '"') return null;
            var body = t[2..^1];
            if (Regex.IsMatch(body.Replace("\"\"", ""), "\"")) return null;
            return body.Replace("\"\"", "\"");
        }
        if (t.Length < 2 || t[^1] != '"') return null;
        var sb = new StringBuilder();
        for (int i = 1; i < t.Length - 1; i++)
        {
            char c = t[i];
            if (c == '"') return null; // two literals side by side, or something else
            if (c != '\\') { sb.Append(c); continue; }
            if (++i >= t.Length - 1) return null;
            if (Escape(t, ref i) is not { } esc) return null;
            sb.Append(esc);
        }
        return sb.ToString();
    }

    private static char? CharLiteral(string t)
    {
        if (t.Length < 3 || t[0] != '\'' || t[^1] != '\'') return null;
        if (t[1] != '\\') return t.Length == 3 ? t[1] : null;
        int i = 2;
        var c = Escape(t, ref i);
        return c is { Length: 1 } && i == t.Length - 2 ? c[0] : null;
    }

    /// <summary>The escape at t[i] (just after the backslash); i ends on its last character.</summary>
    private static string? Escape(string t, ref int i) => t[i] switch
    {
        'n' => "\n",
        'r' => "\r",
        't' => "\t",
        '0' => "\0",
        '\\' => "\\",
        '"' => "\"",
        '\'' => "'",
        'a' => "\a",
        'b' => "\b",
        'f' => "\f",
        'v' => "\v",
        'u' => HexEscape(t, ref i, exactly: 4),
        'x' => HexEscape(t, ref i, exactly: 0),
        _ => null
    };

    /// <summary>\uXXXX (exactly 4 digits) or \xX to \xXXXX (1 to 4).</summary>
    private static string? HexEscape(string t, ref int i, int exactly)
    {
        int start = i + 1, end = start;
        while (end < t.Length && end - start < 4 && Uri.IsHexDigit(t[end])) end++;
        if (end == start || exactly > 0 && end - start != exactly) return null;
        var value = Convert.ToInt32(t[start..end], 16);
        i = end - 1;
        return ((char)value).ToString();
    }

    private static string StripParens(string e)
    {
        e = e.Trim();
        while (e.Length > 1 && e[0] == '(' && e[^1] == ')' && Matching(e) == e.Length - 1) e = e[1..^1].Trim();
        return e;
    }

    private static int Matching(string e)
    {
        int depth = 0;
        bool inString = false;
        for (int i = 0; i < e.Length; i++)
        {
            char c = e[i];
            if (inString) { if (c == '\\') i++; else if (c == '"') inString = false; continue; }
            if (c == '"') { inString = true; continue; }
            if (c == '\'') { int close = e.IndexOf('\'', i + (i + 1 < e.Length && e[i + 1] == '\\' ? 3 : 2)); if (close < 0) return -1; i = close; continue; }
            if (c == '(') depth++;
            else if (c == ')' && --depth == 0) return i;
        }
        return -1;
    }

    /// <summary>Splits at <paramref name="separator"/> outside brackets, strings and chars; null when it can't.</summary>
    internal static List<string>? SplitTop(string e, char separator)
    {
        var parts = new List<string>();
        int depth = 0, start = 0;
        for (int i = 0; i < e.Length; i++)
        {
            char c = e[i];
            if (c == '@' && i + 1 < e.Length && e[i + 1] == '"')
            {
                i += 2;
                while (i < e.Length && !(e[i] == '"' && (i + 1 >= e.Length || e[i + 1] != '"'))) i += e[i] == '"' ? 2 : 1;
                continue;
            }
            if (c == '"')
            {
                i++;
                while (i < e.Length && e[i] != '"') i += e[i] == '\\' ? 2 : 1;
                if (i >= e.Length) return null;
                continue;
            }
            if (c == '\'')
            {
                int close = e.IndexOf('\'', i + (i + 1 < e.Length && e[i + 1] == '\\' ? 3 : 2));
                if (close < 0) return null;
                i = close;
                continue;
            }
            if (c is '(' or '[' or '{') depth++;
            else if (c is ')' or ']' or '}') depth--;
            else if (c == separator && depth == 0)
            {
                parts.Add(e[start..i]);
                start = i + 1;
            }
        }
        parts.Add(e[start..]);
        return parts;
    }
}
