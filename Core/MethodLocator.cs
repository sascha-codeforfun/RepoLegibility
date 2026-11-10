using System.Text.RegularExpressions;

namespace RepoLegibility.Core;

/// <summary>
/// The name of the method (or constructor, local function or property) a position in C# code sits
/// in. Reads masked source, where strings and comments are blanked so their braces don't count.
/// It walks outward through the braces: blocks of if, for, using, lambdas and initializers belong to
/// the member around them; a class or namespace brace means the position isn't inside a member body,
/// which leaves an expression-bodied member (=>) as the only possibility. Unknown when unsure.
/// </summary>
public static class MethodLocator
{
    private static readonly HashSet<string> NotMembers = new(StringComparer.Ordinal)
    {
        "if", "for", "foreach", "while", "using", "switch", "catch", "lock", "fixed", "when",
        "base", "this", "nameof", "typeof", "sizeof", "default", "new", "return", "checked", "unchecked"
    };

    private static readonly HashSet<string> BlockWords = new(StringComparer.Ordinal)
    {
        "else", "try", "finally", "do", "unsafe", "checked", "unchecked", "get", "set", "init", "add", "remove"
    };

    private static readonly Regex TypeDeclaration = new(
        @"\b(?:class|struct|record|interface|enum|namespace)\b", RegexOptions.Compiled);

    // name(args) at the end of a header, optionally followed by a constructor initializer or constraints.
    private static readonly Regex Signature = new(
        @"(?<name>[A-Za-z_]\w*)\s*(?:<[^<>]*(?:<[^<>]*>[^<>]*)*>)?\s*\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)" +
        @"\s*(?::\s*(?:base|this)\s*\((?:[^()]|\([^()]*\))*\))?\s*(?:where\s[^{;]*)?$",
        RegexOptions.Compiled);

    private static readonly Regex ExpressionBodied = new(
        @"(?<name>[A-Za-z_]\w*)\s*(?:<[^<>]*>)?\s*\((?:[^()]|\([^()]*\))*\)\s*=>",
        RegexOptions.Compiled);

    private static readonly Regex TrailingWord = new(@"(?<word>[A-Za-z_]\w*)\s*$", RegexOptions.Compiled);

    public static string? Enclosing(string masked, int position)
    {
        int depth = 0;
        for (int i = Math.Min(position, masked.Length) - 1; i >= 0; i--)
        {
            char c = masked[i];
            if (c == '}') { depth++; continue; }
            if (c != '{') continue;
            if (depth > 0) { depth--; continue; }

            var head = Header(masked, i).TrimEnd();
            if (TypeDeclaration.IsMatch(head)) return ExpressionMember(masked, position);
            if (head.EndsWith("=>", StringComparison.Ordinal) || head.EndsWith('=') || head.EndsWith(',') || head.EndsWith('(')) continue;

            if (head.EndsWith(')'))
            {
                var sig = Signature.Match(head);
                if (!sig.Success) continue;
                var name = sig.Groups["name"].Value;
                if (NotMembers.Contains(name) || PrecededByNew(head, sig.Index)) continue;
                return name;
            }

            // A property: "Name {", unless the word is a block keyword (else, try, get …).
            var word = TrailingWord.Match(head);
            if (word.Success && !BlockWords.Contains(word.Groups["word"].Value) && !PrecededByNew(head, word.Index)
                && !head.EndsWith(']'))
                return word.Groups["word"].Value;
        }

        return ExpressionMember(masked, position);
    }

    /// <summary>The text before a brace, back to the previous statement or block boundary.</summary>
    private static string Header(string masked, int brace)
    {
        int start = masked.LastIndexOfAny([';', '{', '}'], Math.Max(0, brace - 1));
        return masked[(start + 1)..brace];
    }

    private static string? ExpressionMember(string masked, int position)
    {
        int start = masked.LastIndexOfAny([';', '{', '}'], Math.Max(0, Math.Min(position, masked.Length) - 1)) + 1;
        var statement = masked[start..Math.Min(position, masked.Length)];
        foreach (Match m in ExpressionBodied.Matches(statement))
        {
            var name = m.Groups["name"].Value;
            if (!NotMembers.Contains(name) && !PrecededByNew(statement, m.Index)) return name;
        }
        return null;
    }

    private static bool PrecededByNew(string text, int index)
    {
        var before = text[..index].TrimEnd();
        return before.EndsWith("new", StringComparison.Ordinal)
               && (before.Length == 3 || !char.IsLetterOrDigit(before[^4]) && before[^4] != '_');
    }
}
