using System;
using System.Collections.Generic;
using System.Text;
using System.Windows;
using System.Windows.Documents;
using RepoLegibility.Core.Pdf;

namespace RepoLegibility.Pdf;

/// <summary>
/// A hyperlink to place: its laid-out text (whitespace removed) and either its ASCII URI or, for a link
/// inside the document ("#id"), the id of the <see cref="PdfAnchor"/> it jumps to.
/// </summary>
internal sealed record LinkTarget(string Key, string Uri, string? Anchor = null);

/// <summary>
/// Marks a block as a place in the PDF: set it as the <c>Tag</c> of a Paragraph, Section, List or Table.
/// A hyperlink whose NavigateUri is "#" + <paramref name="Id"/> jumps there. Level 1 and 2 also make a
/// bookmark with <paramref name="Title"/> (2 sits under the 1 before it); level 0 is a jump target only.
/// The block is found on the pages by its text, in reading order; <paramref name="Match"/> narrows that to
/// a part of it (the start of a long heading line, say), so it must be text the block shows.
/// </summary>
public sealed record PdfAnchor(string Id, string Title, int Level, string? Match = null);

/// <summary>An anchor found on the pages: where its first character sits (DIP, from the page's top).</summary>
internal readonly record struct PlacedAnchor(PdfAnchor Anchor, int Page, double Top);

/// <summary>Finds every block tagged with a <see cref="PdfAnchor"/>, in document order, with the text to look for.</summary>
internal static class AnchorCollector
{
    public static List<(PdfAnchor Anchor, string Key)> Collect(FlowDocument document)
    {
        var result = new List<(PdfAnchor, string)>();
        Walk(document, result);
        return result;
    }

    private static void Walk(DependencyObject node, List<(PdfAnchor, string)> result)
    {
        if (node is TextElement { Tag: PdfAnchor anchor } element)
        {
            string key = LinkPlacer.Normalize(anchor.Match ?? new TextRange(element.ContentStart, element.ContentEnd).Text);
            if (key.Length > 0) result.Add((anchor, key));
        }
        foreach (object child in LogicalTreeHelper.GetChildren(node))
            if (child is DependencyObject d) Walk(d, result);
    }
}

/// <summary>Finds every Hyperlink in the document, including inside BlockUIContainer / TextBlock content.</summary>
internal static class HyperlinkCollector
{
    public static List<LinkTarget> Collect(FlowDocument document, List<string> notes)
    {
        var result = new List<LinkTarget>();
        Walk(document, result, notes);
        return result;
    }

    private static void Walk(DependencyObject node, List<LinkTarget> result, List<string> notes)
    {
        if (node is Hyperlink link)
        {
            Add(link, result, notes);
            return;
        }
        foreach (object child in LogicalTreeHelper.GetChildren(node))
            if (child is DependencyObject d) Walk(d, result, notes);
    }

    private static void Add(Hyperlink link, List<LinkTarget> result, List<string> notes)
    {
        string text = new TextRange(link.ContentStart, link.ContentEnd).Text;
        string shown = text.Length > 60 ? text[..57] + "…" : text;
        Uri? uri = link.NavigateUri;
        if (uri is null) { notes.Add($"hyperlink \"{shown}\" has no NavigateUri and is not linked"); return; }
        if (!uri.IsAbsoluteUri && uri.OriginalString.StartsWith('#') && uri.OriginalString.Length > 1)
        {
            string inner = LinkPlacer.Normalize(text);
            if (inner.Length == 0) { notes.Add($"link to {uri.OriginalString} has no text and is not linked"); return; }
            result.Add(new LinkTarget(inner, "", uri.OriginalString[1..]));
            return;
        }
        if (!uri.IsAbsoluteUri || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        { notes.Add($"hyperlink \"{shown}\" is not an absolute http/https link ({uri.OriginalString}) and is not linked"); return; }

        string key = LinkPlacer.Normalize(text);
        if (key.Length == 0) { notes.Add($"hyperlink to {uri.AbsoluteUri} has no text and is not linked"); return; }
        result.Add(new LinkTarget(key, ToAscii(uri)));
    }

    /// <summary>URI in 7-bit ASCII: percent-encoded path/query (AbsoluteUri) with an IDN host as punycode.</summary>
    private static string ToAscii(Uri uri)
    {
        string s = uri.AbsoluteUri;
        foreach (char c in s)
        {
            if (c > 0x7E)
            {
                var b = new UriBuilder(uri) { Host = uri.IdnHost };
                s = b.Uri.AbsoluteUri;
                break;
            }
        }
        return s;
    }
}

/// <summary>
/// Matches link texts against the laid-out characters in reading order and produces one
/// annotation rectangle per line fragment (consecutive characters from the same line).
/// </summary>
internal static class LinkPlacer
{
    public static string Normalize(string text)
    {
        var sb = new StringBuilder(text.Length);
        foreach (char c in text)
            if (!char.IsWhiteSpace(c) && c != '­') sb.Append(c);
        return sb.ToString();
    }

    /// <summary>The laid-out characters without whitespace, and the same as one string to search.</summary>
    private static (List<PlacedChar> Seq, string All) Sequence(IReadOnlyList<PlacedChar> chars)
    {
        var seq = new List<PlacedChar>(chars.Count);
        var text = new StringBuilder(chars.Count);
        foreach (var c in chars)
        {
            if (char.IsWhiteSpace(c.Ch) || c.Ch == '­') continue;
            seq.Add(c);
            text.Append(c.Ch);
        }
        return (seq, text.ToString());
    }

    /// <summary>
    /// Finds each anchor's text on the pages, in reading order: each is looked for after the one before,
    /// so a heading's words that occur earlier in the text don't catch it. One that isn't found is noted.
    /// </summary>
    public static Dictionary<string, PlacedAnchor> Locate(IReadOnlyList<(PdfAnchor Anchor, string Key)> anchors,
                                                       IReadOnlyList<PlacedChar> chars, List<string> notes)
    {
        var (seq, all) = Sequence(chars);
        var result = new Dictionary<string, PlacedAnchor>(StringComparer.Ordinal);
        int cursor = 0;
        foreach (var (anchor, key) in anchors)
        {
            // Only where a line of text starts: a heading's words inside other text (a file name in a table
            // row, say) aren't the heading.
            int at = all.IndexOf(key, cursor, StringComparison.Ordinal);
            while (at > 0 && seq[at - 1].Run == seq[at].Run && seq[at - 1].Page == seq[at].Page)
                at = all.IndexOf(key, at + 1, StringComparison.Ordinal);
            if (at < 0) { notes.Add($"\"{Short(anchor.Title)}\" was not found on the pages, so nothing jumps to it"); continue; }
            cursor = at + key.Length;
            if (!result.TryAdd(anchor.Id, new PlacedAnchor(anchor, seq[at].Page, seq[at].Box.Top)))
                notes.Add($"the place \"{anchor.Id}\" is named twice; links go to the first");
        }
        return result;
    }

    private static string Short(string s) => s.Length > 60 ? s[..57] + "…" : s;

    public static List<PdfLink>[] Place(IReadOnlyList<LinkTarget> targets, IReadOnlyList<PlacedChar> chars,
                                        IReadOnlyList<double> pageHeightsDip, IReadOnlyDictionary<string, PlacedAnchor> anchors,
                                        List<string> notes, out int placed)
    {
        var perPage = new List<PdfLink>[pageHeightsDip.Count];
        for (int i = 0; i < perPage.Length; i++) perPage[i] = new List<PdfLink>();
        placed = 0;

        var (seq, all) = Sequence(chars);

        int cursor = 0;
        foreach (var target in targets)
        {
            int at = all.IndexOf(target.Key, cursor, StringComparison.Ordinal);
            if (at < 0)
            {
                notes.Add($"link text for {target.Anchor ?? target.Uri} was not found on the pages and is not linked");
                continue;
            }
            cursor = at + target.Key.Length;
            const double k = PageWalker.PointsPerDip;
            int destPage = -1;
            double destTop = 0;
            if (target.Anchor is { } id)
            {
                if (!anchors.TryGetValue(id, out var dest)) { notes.Add($"link to \"#{id}\" has no place to jump to and is not linked"); continue; }
                destPage = dest.Page;
                destTop = (pageHeightsDip[dest.Page] - Math.Max(0, dest.Top - 6)) * k; // a little above the line
            }
            placed++;
            foreach (var (page, box) in Fragments(seq, at, target.Key.Length))
            {
                double h = pageHeightsDip[page];
                perPage[page].Add(new PdfLink(box.Left * k, (h - box.Bottom) * k, box.Right * k, (h - box.Top) * k, target.Uri, destPage, destTop));
            }
        }
        return perPage;
    }

    /// <summary>Unions character boxes per glyph run, then merges neighbouring runs on the same line.</summary>
    private static List<(int Page, Rect Box)> Fragments(List<PlacedChar> seq, int start, int length)
    {
        var result = new List<(int Page, Rect Box)>();
        int lastRun = -1;
        for (int i = start; i < start + length; i++)
        {
            var c = seq[i];
            if (result.Count > 0)
            {
                var (page, box) = result[^1];
                bool sameLine = page == c.Page &&
                    (c.Run == lastRun || (Math.Abs(box.Top - c.Box.Top) < 1.0 && Math.Abs(box.Bottom - c.Box.Bottom) < 1.0
                                          && c.Box.Left >= box.Left));
                if (sameLine)
                {
                    box.Union(c.Box);
                    result[^1] = (page, box);
                    lastRun = c.Run;
                    continue;
                }
            }
            result.Add((c.Page, c.Box));
            lastRun = c.Run;
        }
        return result;
    }
}
