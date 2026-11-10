using System;
using System.Collections.Generic;
using System.Linq;

namespace CSharpLexing;

/// <summary>
/// Reads C# source once, character by character, and says what every position is: code, comment,
/// preprocessor directive, string or char. It knows the literal forms of current C#: regular,
/// verbatim ($@ and @$ alike), interpolated with holes, raw ("""), interpolated raw ($$"""),
/// u8 suffixes and char literals with every escape. Interpolation holes are code, lexed the same
/// way, so strings inside them are found too; a hole's alignment (",-10") and format (":F1") are not.
///
/// Every output keeps the input's length and line breaks: a blanked character becomes a space,
/// line breaks stay, so indices and line numbers carry over unchanged. Nothing throws. A regular or
/// interpolated string that isn't closed ends at the end of its line; an unclosed verbatim or raw
/// string or block comment runs to the end of the text.
///
/// Self-contained: no dependencies beyond the base library and nothing specific to one app, so the
/// file can be copied as is.
/// </summary>
public static class CSharpLexer
{
    /// <summary>What a character of source is.</summary>
    public enum Kind : byte
    {
        Code,
        Comment,
        /// <summary>A preprocessor line: #region, #if, #pragma, #error and the rest.</summary>
        Directive,
        /// <summary>A string literal, including its prefix, quotes, braces around holes, format clauses and u8 suffix.</summary>
        String,
        Char
    }

    public enum LiteralKind
    {
        Regular,
        Verbatim,
        Raw,
        Interpolated,
        InterpolatedVerbatim,
        InterpolatedRaw
    }

    /// <summary>
    /// A piece of a literal's content: literal text, or the expression of a hole. A hole's span leaves
    /// out its braces, its alignment and its format clause: "x" in {x,10:N2}.
    /// </summary>
    public readonly record struct Part(int Start, int Length, bool IsHole);

    /// <param name="Start">Index of the first character: the prefix ($, @) or the opening quote.</param>
    /// <param name="Length">Through the closing quotes and any u8 suffix.</param>
    /// <param name="Terminated">False when the literal wasn't closed (it then ends at its line end or at the end of the text).</param>
    /// <param name="Parts">The content between the quotes, in order. Text is source text, escapes not decoded.</param>
    public sealed record Literal(int Start, int Length, LiteralKind Kind, bool Utf8, bool Terminated, IReadOnlyList<Part> Parts)
    {
        public int End => Start + Length;

        public bool IsInterpolated => Kind is LiteralKind.Interpolated or LiteralKind.InterpolatedVerbatim or LiteralKind.InterpolatedRaw;

        /// <summary>The content as written, each hole shown as <paramref name="hole"/> ("{}" unless given).</summary>
        public string Text(string code, string hole = "{}") =>
            string.Concat(Parts.Select(p => p.IsHole ? hole : code.Substring(p.Start, p.Length)));

        /// <summary>
        /// The content as the program sees it: "C:\\Temp" is C:\Temp, \" a quote, "" in a verbatim string a quote,
        /// {{ in an interpolated one a brace. Holes shown as <paramref name="hole"/>.
        /// </summary>
        public string Value(string code, string hole = "{}") =>
            string.Concat(Parts.Select(p => p.IsHole ? hole : Decode(code.Substring(p.Start, p.Length), Kind)));

        private static string Decode(string text, LiteralKind kind)
        {
            if (kind is LiteralKind.Interpolated or LiteralKind.InterpolatedVerbatim or LiteralKind.InterpolatedRaw)
                text = text.Replace("{{", "{").Replace("}}", "}");
            if (kind is LiteralKind.Verbatim or LiteralKind.InterpolatedVerbatim) return text.Replace("\"\"", "\"");
            if (kind is not (LiteralKind.Regular or LiteralKind.Interpolated) || text.IndexOf('\\') < 0) return text;
            var b = new System.Text.StringBuilder(text.Length);
            for (int i = 0; i < text.Length; i++)
            {
                char c = text[i];
                if (c != '\\' || i + 1 >= text.Length) { b.Append(c); continue; }
                char n = text[++i];
                switch (n)
                {
                    case '\\': b.Append('\\'); break;
                    case '"': b.Append('"'); break;
                    case '\'': b.Append('\''); break;
                    case 'n': b.Append('\n'); break;
                    case 'r': b.Append('\r'); break;
                    case 't': b.Append('\t'); break;
                    case '0': b.Append('\0'); break;
                    case 'a': b.Append('\a'); break;
                    case 'b': b.Append('\b'); break;
                    case 'f': b.Append('\f'); break;
                    case 'v': b.Append('\v'); break;
                    case 'e': b.Append('\u001b'); break;
                    case 'u' when i + 4 < text.Length && int.TryParse(text.AsSpan(i + 1, 4), System.Globalization.NumberStyles.HexNumber, null, out var u):
                        b.Append((char)u); i += 4; break;
                    case 'x':
                        int len = 0;
                        while (len < 4 && i + 1 + len < text.Length && IsHex(text[i + 1 + len])) len++;
                        if (len > 0 && int.TryParse(text.AsSpan(i + 1, len), System.Globalization.NumberStyles.HexNumber, null, out var x)) { b.Append((char)x); i += len; }
                        else b.Append("\\x");
                        break;
                    default: b.Append('\\').Append(n); break;
                }
            }
            return b.ToString();
        }
    }

    /// <summary>The kind of every character. The array is the caller's own copy.</summary>
    public static Kind[] Classify(string code) => (Kind[])Lex(code).Kinds.Clone();

    /// <summary>Comments and directives blanked. Strings and chars kept.</summary>
    public static string BlankComments(string code) => Lex(code).CommentsBlanked;

    /// <summary>Comments, directives, strings and chars blanked. Interpolation holes stay as code.</summary>
    public static string BlankCommentsAndStrings(string code) => Lex(code).AllBlanked;

    /// <summary>Every string literal, including those inside interpolation holes, ordered by position.</summary>
    public static IReadOnlyList<Literal> Literals(string code) => Lex(code).Literals;

    /// <summary>
    /// One text, lexed once. Several callers usually ask about the same text (one file, read by several
    /// checks), so the result is kept for as long as that string instance lives and is dropped with it.
    /// Safe to use from several threads at once.
    /// </summary>
    private sealed record Lexed(Kind[] Kinds, string CommentsBlanked, string AllBlanked, IReadOnlyList<Literal> Literals);

    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<string, Lexed> Cache = new();

    private static Lexed Lex(string code) => Cache.GetValue(code, static text =>
    {
        var scanner = new Scanner(text);
        scanner.Run();
        scanner.Literals.Sort((a, b) => a.Start.CompareTo(b.Start));

        // Both blanked copies in one pass.
        var comments = text.ToCharArray();
        var all = text.ToCharArray();
        var kinds = scanner.Kinds;
        for (int i = 0; i < kinds.Length; i++)
        {
            var kind = kinds[i];
            if (kind == Kind.Code || IsNewLine(text[i])) continue;
            all[i] = ' ';
            if (kind is Kind.Comment or Kind.Directive) comments[i] = ' ';
        }

        return new Lexed(kinds, new string(comments), new string(all), scanner.Literals.AsReadOnly());
    });

    private static bool IsNewLine(char c) => c is '\n' or '\r' or '\u0085' or '\u2028' or '\u2029';

    private static bool IsIdentifierChar(char c) => c < 128
        ? char.IsAsciiLetterOrDigit(c) || c == '_'
        : char.IsLetterOrDigit(c) || char.GetUnicodeCategory(c) is
        System.Globalization.UnicodeCategory.NonSpacingMark or System.Globalization.UnicodeCategory.SpacingCombiningMark
        or System.Globalization.UnicodeCategory.ConnectorPunctuation or System.Globalization.UnicodeCategory.Format;

    private static bool IsHex(char c) => char.IsAsciiHexDigit(c);

    private sealed class Scanner(string s)
    {
        public readonly Kind[] Kinds = new Kind[s.Length];
        public readonly List<Literal> Literals = new();
        private int _i;

        /// <summary>Why a run of code stopped.</summary>
        private enum Stop { End, HoleClose, Format, Abort }

        public void Run() => Code(holeBraces: 0, singleLine: false);

        private char At(int index) => index < s.Length ? s[index] : '\0';

        private void Mark(int from, int to, Kind kind)
        {
            for (int k = Math.Max(0, from); k < to && k < s.Length; k++) Kinds[k] = kind;
        }

        private int LineEnd(int from)
        {
            int k = from;
            while (k < s.Length && !IsNewLine(s[k])) k++;
            return k;
        }

        /// <summary>
        /// Code, from the current position. At the top level (holeBraces 0) it runs to the end of the
        /// text. Inside a hole it stops at the brace that closes the hole, at a format clause, or, in a
        /// single-line interpolated string, at a semicolon that can only mean the string was never closed.
        /// </summary>
        private Stop Code(int holeBraces, bool singleLine)
        {
            bool inHole = holeBraces > 0;
            int depth = 0;
            bool lineStart = !inHole && LineStartsAt(_i);

            while (_i < s.Length)
            {
                char c = s[_i];

                if (IsNewLine(c)) { lineStart = true; _i++; continue; }
                if (c is ' ' or '\t' or '\f' or '\v' or '\uFEFF') { _i++; continue; }

                if (lineStart && c == '#' && !inHole)
                {
                    int end = LineEnd(_i);
                    Mark(_i, end, Kind.Directive);
                    _i = end;
                    continue;
                }
                lineStart = false;

                if (c == '/' && At(_i + 1) == '/')
                {
                    int end = LineEnd(_i);
                    Mark(_i, end, Kind.Comment);
                    _i = end;
                    continue;
                }
                if (c == '/' && At(_i + 1) == '*')
                {
                    int close = s.IndexOf("*/", _i + 2, StringComparison.Ordinal);
                    int end = close < 0 ? s.Length : close + 2;
                    Mark(_i, end, Kind.Comment);
                    _i = end;
                    continue;
                }
                if (c == '\'') { CharLiteral(); continue; }
                if (c is '"' or '@' or '$' && StringLiteral()) continue;

                if (IsIdentifierChar(c))
                {
                    while (_i < s.Length && IsIdentifierChar(s[_i])) _i++;
                    continue;
                }

                if (inHole)
                {
                    if (c is '(' or '[' or '{') depth++;
                    else if (c is ')' or ']') { if (depth > 0) depth--; }
                    else if (c == '}')
                    {
                        if (depth == 0) return Stop.HoleClose;
                        depth--;
                    }
                    else if (c == ':' && depth == 0 && At(_i + 1) != ':' && (_i == 0 || s[_i - 1] != ':'))
                        return Stop.Format;
                    // {value,-10} and {value,8:F1}: the alignment is part of the format clause, not code.
                    else if (c == ',' && depth == 0)
                        return Stop.Format;
                    else if (c == ';' && depth == 0 && singleLine)
                        return Stop.Abort;
                }
                _i++;
            }
            return Stop.End;
        }

        private bool LineStartsAt(int index)
        {
            for (int k = index - 1; k >= 0; k--)
            {
                if (IsNewLine(s[k])) return true;
                if (s[k] is not (' ' or '\t' or '\f' or '\v' or '\uFEFF')) return false;
            }
            return true;
        }

        /// <summary>'x', '\'', 'A', '\x41'. A lone apostrophe that closes nothing is marked on its own.</summary>
        private void CharLiteral()
        {
            int start = _i;
            int j = start + 1;
            if (At(j) == '\\')
            {
                char escape = At(j + 1);
                j += 2;
                int maxHex = escape switch { 'u' => 4, 'U' => 8, 'x' => 4, _ => 0 };
                for (int h = 0; h < maxHex && j < s.Length && IsHex(s[j]); h++) j++;
            }
            else if (j < s.Length && s[j] != '\'' && !IsNewLine(s[j]))
                j += char.IsHighSurrogate(s[j]) && j + 1 < s.Length && char.IsLowSurrogate(s[j + 1]) ? 2 : 1;

            if (At(j) != '\'')
            {
                // Malformed: look a short way along the line for the closing apostrophe.
                int k = start + 1;
                while (k < s.Length && k - start < 12 && !IsNewLine(s[k]) && s[k] != '\'') k++;
                j = k < s.Length && s[k] == '\'' && k > start + 1 ? k : start;
            }

            Mark(start, j + 1, Kind.Char);
            _i = j + 1;
        }

        /// <summary>A string literal of any kind starting at the current position; false if there's none.</summary>
        private bool StringLiteral()
        {
            int start = _i;
            int j = start;
            bool verbatim = false;
            int dollars = 0;

            if (At(j) == '@') { verbatim = true; j++; }
            while (At(j) == '$') { dollars++; j++; }
            if (!verbatim && dollars > 0 && At(j) == '@') { verbatim = true; j++; }
            if (At(j) != '"') return false;

            int quotes = 0;
            while (At(j + quotes) == '"') quotes++;

            LiteralKind kind;
            if (quotes >= 3 && !verbatim)
                kind = dollars > 0 ? LiteralKind.InterpolatedRaw : LiteralKind.Raw;
            else
            {
                quotes = 1;
                kind = (verbatim, dollars > 0) switch
                {
                    (true, true) => LiteralKind.InterpolatedVerbatim,
                    (true, false) => LiteralKind.Verbatim,
                    (false, true) => LiteralKind.Interpolated,
                    _ => LiteralKind.Regular
                };
            }

            _i = j + quotes;
            Body(start, kind, quotes, Math.Max(1, dollars));
            return true;
        }

        private void Body(int start, LiteralKind kind, int quotes, int holeBraces)
        {
            bool raw = kind is LiteralKind.Raw or LiteralKind.InterpolatedRaw;
            bool verbatim = kind is LiteralKind.Verbatim or LiteralKind.InterpolatedVerbatim;
            bool interpolated = kind is LiteralKind.Interpolated or LiteralKind.InterpolatedVerbatim or LiteralKind.InterpolatedRaw;
            bool singleLine = !raw && !verbatim;

            var parts = new List<Part>();
            int segment = start;   // first character not yet marked as String
            int text = _i;         // start of the current text part
            bool terminated = false;

            void CloseText(int at)
            {
                if (at > text) parts.Add(new Part(text, at - text, false));
            }

            while (_i < s.Length)
            {
                char c = s[_i];

                if (singleLine && IsNewLine(c)) break;

                if (c == '\\' && singleLine)
                {
                    _i += _i + 1 < s.Length && !IsNewLine(s[_i + 1]) ? 2 : 1;
                    continue;
                }

                if (c == '"')
                {
                    if (raw)
                    {
                        int run = 0;
                        while (At(_i + run) == '"') run++;
                        if (run >= quotes)
                        {
                            CloseText(_i);
                            _i += run;
                            terminated = true;
                            break;
                        }
                        _i += run;
                        continue;
                    }
                    if (verbatim && At(_i + 1) == '"') { _i += 2; continue; }
                    CloseText(_i);
                    _i++;
                    terminated = true;
                    break;
                }

                if (interpolated && c == '{')
                {
                    int open;   // where the hole's opening braces start
                    if (raw)
                    {
                        int run = 0;
                        while (At(_i + run) == '{') run++;
                        if (run < holeBraces) { _i += run; continue; }
                        open = _i + run - holeBraces;   // extra leading braces are text
                    }
                    else
                    {
                        if (At(_i + 1) == '{') { _i += 2; continue; }
                        open = _i;
                    }

                    CloseText(open);
                    _i = open + (raw ? holeBraces : 1);
                    Mark(segment, _i, Kind.String);

                    int expression = _i;
                    var stop = Code(raw ? holeBraces : 1, singleLine);
                    parts.Add(new Part(expression, _i - expression, true));

                    if (stop == Stop.Format)
                    {
                        segment = _i;
                        while (_i < s.Length && s[_i] != '}' && !(singleLine && IsNewLine(s[_i]))) _i++;
                        if (_i >= s.Length || s[_i] != '}') { segment = Math.Min(segment, _i); stop = Stop.Abort; }
                        else stop = Stop.HoleClose;
                    }
                    else segment = _i;

                    if (stop != Stop.HoleClose)
                    {
                        // The literal ends inside or right after the hole: never closed.
                        Mark(segment, _i, Kind.String);
                        segment = text = _i;
                        break;
                    }

                    int closed = 0;
                    while (closed < (raw ? holeBraces : 1) && At(_i) == '}') { _i++; closed++; }
                    text = _i;
                    continue;
                }

                if (interpolated && c == '}' && !raw && At(_i + 1) == '}') { _i += 2; continue; }

                _i++;
            }

            if (!terminated) CloseText(_i);

            bool utf8 = false;
            if (terminated && At(_i) is 'u' or 'U' && At(_i + 1) == '8' && !(_i + 2 < s.Length && IsIdentifierChar(s[_i + 2])))
            {
                _i += 2;
                utf8 = true;
            }

            Mark(segment, _i, Kind.String);
            Literals.Add(new Literal(start, _i - start, kind, utf8, terminated, parts));
        }
    }
}
