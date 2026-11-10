using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using System.Windows.Media;
using RepoLegibility.Core.Pdf;

namespace RepoLegibility.Pdf;

/// <summary>One typeface (including its style simulation) as used on the pages.</summary>
internal sealed class FontEntry
{
    public FontEntry(GlyphTypeface typeface, int index)
    {
        Typeface = typeface;
        ResourceName = PdfDocumentBuilder.FontResourceName(index);
    }

    public GlyphTypeface Typeface { get; }
    public string ResourceName { get; }
    public SortedDictionary<ushort, int> Widths { get; } = new();
    public SortedDictionary<ushort, string> Unicode { get; } = new();

    /// <summary>Glyph advance in 1/1000 em as written to /W; also records the glyph as used.</summary>
    public int Width(ushort gid)
    {
        if (!Widths.TryGetValue(gid, out int w))
        {
            w = Typeface.AdvanceWidths.TryGetValue(gid, out double em) ? (int)Math.Round(em * 1000.0, MidpointRounding.AwayFromZero) : 0;
            Widths[gid] = w;
        }
        return w;
    }

    /// <summary>First mapping wins; a glyph shared by different texts keeps the first one.</summary>
    public void MapUnicode(ushort gid, string text)
    {
        Width(gid);
        if (text.Length > 0) Unicode.TryAdd(gid, text);
    }
}

/// <summary>Collects used glyphs per typeface and turns them into embeddable PDF fonts.</summary>
internal sealed class FontCollector
{
    private readonly Dictionary<GlyphTypeface, FontEntry> _byTypeface = new();
    private readonly List<FontEntry> _ordered = new();

    public FontEntry Use(GlyphTypeface typeface)
    {
        if (!_byTypeface.TryGetValue(typeface, out var entry))
        {
            entry = new FontEntry(typeface, _ordered.Count);
            _byTypeface.Add(typeface, entry);
            _ordered.Add(entry);
        }
        return entry;
    }

    /// <summary>Subsets, checks and adds every used font to the builder, in first-use order.</summary>
    public void AddTo(PdfDocumentBuilder builder, List<string> notes)
    {
        foreach (var entry in _ordered)
        {
            int index = builder.AddFont(Create(entry, notes));
            if (PdfDocumentBuilder.FontResourceName(index) != entry.ResourceName)
                throw new InvalidOperationException("Font resource order mismatch.");
        }
    }

    private static PdfFontData Create(FontEntry entry, List<string> notes)
    {
        GlyphTypeface gt = entry.Typeface;
        string display = DisplayName(gt);
        FontEmbeddingRight rights = gt.EmbeddingRights;

        if (rights == FontEmbeddingRight.RestrictedLicense)
            throw new PdfExportException($"The font \"{display}\" does not allow embedding (restricted license). Use a different font in the document.");
        if (rights is FontEmbeddingRight.InstallableButWithBitmapsOnly or FontEmbeddingRight.InstallableButNoSubsettingAndWithBitmapsOnly
            or FontEmbeddingRight.PreviewAndPrintButWithBitmapsOnly or FontEmbeddingRight.PreviewAndPrintButNoSubsettingAndWithBitmapsOnly
            or FontEmbeddingRight.EditableButWithBitmapsOnly or FontEmbeddingRight.EditableButNoSubsettingAndWithBitmapsOnly)
            throw new PdfExportException($"The font \"{display}\" only allows bitmap embedding, which this PDF export does not do. Use a different font in the document.");

        bool noSubsetting = rights is FontEmbeddingRight.InstallableButNoSubsetting
            or FontEmbeddingRight.PreviewAndPrintButNoSubsetting or FontEmbeddingRight.EditableButNoSubsetting;

        entry.Width(0); // .notdef is always part of the subset
        byte[] program;
        if (noSubsetting)
        {
            using Stream stream = gt.GetFontStream();
            using var ms = new MemoryStream();
            stream.CopyTo(ms);
            program = ms.ToArray();
            notes.Add($"font \"{display}\" forbids subsetting and was embedded in full");
        }
        else
        {
            try { program = gt.ComputeSubset(new List<ushort>(entry.Widths.Keys)); }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            { throw new PdfExportException($"The font \"{display}\" could not be subset for embedding: {ex.Message}", ex); }

            // The subset still carries every table of the font (a colour emoji font's layers: megabytes
            // for one check mark); only what a PDF draws with is embedded. Glyph IDs stay as they are.
            program = SfntTables.KeepForPdf(program);
        }

        TrueTypeFile tt;
        try { tt = TrueTypeFile.Parse(program); }
        catch (FormatException ex) { throw new PdfExportException($"The font \"{display}\" cannot be embedded: {ex.Message}", ex); }

        // Self-check: the PDF uses glyph IDs as CIDs, so the subset must keep the original IDs.
        foreach (var (gid, text) in entry.Unicode)
        {
            if (HasInk(text) && !tt.HasOutline(gid))
                throw new PdfExportException(
                    $"The embedded subset of font \"{display}\" has no outline for glyph {gid} (\"{text}\"). " +
                    "GlyphTypeface.ComputeSubset does not keep the original glyph IDs for this font, " +
                    "so the export was stopped instead of writing wrong characters.");
        }

        return new PdfFontData
        {
            BaseName = PostScriptName(gt),
            FontProgram = program,
            IsSubset = !noSubsetting,
            Widths = entry.Widths,
            Unicode = entry.Unicode,
            Ascent = (int)Math.Round(gt.Baseline * 1000.0),
            Descent = -(int)Math.Round((gt.Height - gt.Baseline) * 1000.0),
            CapHeight = (int)Math.Round(gt.CapsHeight * 1000.0),
        };
    }

    /// <summary>True if the text should produce visible ink (not whitespace, control or format characters).</summary>
    private static bool HasInk(string text)
    {
        foreach (char c in text)
        {
            var cat = char.GetUnicodeCategory(c);
            if (!char.IsWhiteSpace(c) && cat is not (UnicodeCategory.Control or UnicodeCategory.Format
                or UnicodeCategory.SpaceSeparator or UnicodeCategory.NonSpacingMark))
                return true;
        }
        return false;
    }

    private static string DisplayName(GlyphTypeface gt)
    {
        string family = Pick(gt.FamilyNames), face = Pick(gt.FaceNames);
        string name = string.IsNullOrEmpty(face) ? family : family + " " + face;
        StyleSimulations sim = gt.StyleSimulations;
        if (sim != StyleSimulations.None) name += $" ({sim})";
        return name.Length > 0 ? name : gt.FontUri?.ToString() ?? "unknown font";
    }

    private static string PostScriptName(GlyphTypeface gt)
    {
        var sb = new StringBuilder();
        Append(sb, Pick(gt.FamilyNames));
        sb.Append('-');
        Append(sb, Pick(gt.FaceNames));
        StyleSimulations sim = gt.StyleSimulations;
        if ((sim & StyleSimulations.BoldSimulation) != 0) sb.Append("SimBold");
        if ((sim & StyleSimulations.ItalicSimulation) != 0) sb.Append("SimItalic");
        string s = sb.ToString().Trim('-');
        return s.Length > 0 ? s : "Font";

        static void Append(StringBuilder sb, string text)
        {
            foreach (char c in text)
                if (c is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9') sb.Append(c);
        }
    }

    private static string Pick(IDictionary<CultureInfo, string> names)
    {
        if (names.TryGetValue(CultureInfo.GetCultureInfo("en-US"), out string? en)) return en;
        foreach (var kv in names) return kv.Value;
        return "";
    }
}
