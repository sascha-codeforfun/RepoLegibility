using System;
using System.Collections.Generic;
using System.Text;

namespace RepoLegibility.Core.Pdf;

/// <summary>
/// Everything needed to embed one font as a Type0 / CIDFont with Identity-H encoding.
/// Glyph IDs are used directly as CIDs (CIDToGIDMap /Identity).
/// </summary>
internal sealed class PdfFontData
{
    /// <summary>PostScript-style name without subset tag; ASCII letters, digits and '-' only.</summary>
    public required string BaseName { get; init; }

    /// <summary>TrueType (glyf) or CFF-flavoured OpenType font program.</summary>
    public required byte[] FontProgram { get; init; }

    /// <summary>True if <see cref="FontProgram"/> is a subset; adds the six-letter subset tag.</summary>
    public required bool IsSubset { get; init; }

    /// <summary>Glyph advance widths in 1/1000 em, keyed by glyph ID.</summary>
    public required SortedDictionary<ushort, int> Widths { get; init; }

    /// <summary>Unicode text per glyph ID for the ToUnicode CMap (first glyph of a cluster carries the cluster text).</summary>
    public required SortedDictionary<ushort, string> Unicode { get; init; }

    public required int Ascent { get; init; }
    public required int Descent { get; init; }
    public required int CapHeight { get; init; }
}

/// <summary>Builders for the font-related PDF structures (ISO 32000-1 §9.7.4.3 /W, §9.10.3 ToUnicode).</summary>
internal static class PdfFontEncoding
{
    /// <summary>
    /// /W array: runs of consecutive glyph IDs as <c>first [w1 w2 …]</c>, e.g. <c>[3 [500 600] 10 [250]]</c>.
    /// </summary>
    public static string BuildWidthsArray(SortedDictionary<ushort, int> widths)
    {
        var sb = new StringBuilder("[");
        int prev = -2;
        bool open = false;
        foreach (var (gid, w) in widths)
        {
            if (gid != prev + 1)
            {
                if (open) sb.Append("] ");
                sb.Append(PdfFormat.Int(gid)).Append(" [");
                open = true;
            }
            else
            {
                sb.Append(' ');
            }
            sb.Append(PdfFormat.Int(w));
            prev = gid;
        }
        if (open) sb.Append(']');
        return sb.Append(']').ToString();
    }

    /// <summary>ToUnicode CMap mapping 2-byte codes to UTF-16BE text with bfchar blocks of at most 100 entries.</summary>
    public static string BuildToUnicodeCMap(SortedDictionary<ushort, string> unicode)
    {
        var entries = new List<KeyValuePair<ushort, string>>();
        foreach (var kv in unicode)
            if (!string.IsNullOrEmpty(kv.Value)) entries.Add(kv);

        var sb = new StringBuilder();
        sb.Append("/CIDInit /ProcSet findresource begin\n")
          .Append("12 dict begin\n")
          .Append("begincmap\n")
          .Append("/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def\n")
          .Append("/CMapName /Adobe-Identity-UCS def\n")
          .Append("/CMapType 2 def\n")
          .Append("1 begincodespacerange\n<0000> <FFFF>\nendcodespacerange\n");
        for (int start = 0; start < entries.Count; start += 100)
        {
            int n = Math.Min(100, entries.Count - start);
            sb.Append(PdfFormat.Int(n)).Append(" beginbfchar\n");
            for (int i = start; i < start + n; i++)
                sb.Append('<').Append(PdfFormat.Hex4(entries[i].Key)).Append("> <")
                  .Append(PdfFormat.Utf16Hex(entries[i].Value)).Append(">\n");
            sb.Append("endbfchar\n");
        }
        sb.Append("endcmap\n")
          .Append("CMapName currentdict /CMap defineresource pop\n")
          .Append("end\nend\n");
        return sb.ToString();
    }
}
