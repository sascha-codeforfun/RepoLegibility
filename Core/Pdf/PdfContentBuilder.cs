using System;
using System.Collections.Generic;
using System.Text;

namespace RepoLegibility.Core.Pdf;

/// <summary>Builds a page content stream from PDF operators (ISO 32000-1 §8.2, §9.4).</summary>
internal sealed class PdfContentBuilder
{
    private readonly StringBuilder _sb = new();

    private PdfContentBuilder Op(string op)
    {
        _sb.Append(op).Append('\n');
        return this;
    }

    private PdfContentBuilder Op(string op, params double[] args)
    {
        foreach (double a in args) _sb.Append(PdfFormat.Num(a)).Append(' ');
        return Op(op);
    }

    public PdfContentBuilder SaveState() => Op("q");
    public PdfContentBuilder RestoreState() => Op("Q");

    public PdfContentBuilder Transform(double a, double b, double c, double d, double e, double f)
        => Op("cm", a, b, c, d, e, f);

    public PdfContentBuilder SetGraphicsState(string resourceName)
    {
        _sb.Append(PdfFormat.Name(resourceName)).Append(' ');
        return Op("gs");
    }

    public PdfContentBuilder SetFillRgb(double r, double g, double b) => Op("rg", r, g, b);
    public PdfContentBuilder SetStrokeRgb(double r, double g, double b) => Op("RG", r, g, b);
    public PdfContentBuilder SetLineWidth(double w) => Op("w", w);

    /// <summary>0 butt, 1 round, 2 projecting square.</summary>
    public PdfContentBuilder SetLineCap(int cap) => Op("J", cap);

    /// <summary>0 miter, 1 round, 2 bevel.</summary>
    public PdfContentBuilder SetLineJoin(int join) => Op("j", join);

    public PdfContentBuilder SetMiterLimit(double limit) => Op("M", limit);

    public PdfContentBuilder SetDash(IReadOnlyList<double> pattern, double phase)
    {
        _sb.Append('[');
        for (int i = 0; i < pattern.Count; i++)
        {
            if (i > 0) _sb.Append(' ');
            _sb.Append(PdfFormat.Num(pattern[i]));
        }
        _sb.Append("] ");
        return Op("d", phase);
    }

    public PdfContentBuilder MoveTo(double x, double y) => Op("m", x, y);
    public PdfContentBuilder LineTo(double x, double y) => Op("l", x, y);
    public PdfContentBuilder CurveTo(double x1, double y1, double x2, double y2, double x3, double y3)
        => Op("c", x1, y1, x2, y2, x3, y3);
    public PdfContentBuilder ClosePath() => Op("h");
    public PdfContentBuilder Rectangle(double x, double y, double w, double h) => Op("re", x, y, w, h);

    public PdfContentBuilder Fill(bool evenOdd) => Op(evenOdd ? "f*" : "f");
    public PdfContentBuilder Stroke() => Op("S");
    public PdfContentBuilder FillAndStroke(bool evenOdd) => Op(evenOdd ? "B*" : "B");

    /// <summary>Intersects the clip with the current path and discards the path (W n).</summary>
    public PdfContentBuilder Clip(bool evenOdd) => Op(evenOdd ? "W* n" : "W n");

    public PdfContentBuilder BeginText() => Op("BT");
    public PdfContentBuilder EndText() => Op("ET");

    public PdfContentBuilder SetFont(string resourceName, double size)
    {
        _sb.Append(PdfFormat.Name(resourceName)).Append(' ');
        return Op("Tf", size);
    }

    /// <summary>0 fill, 2 fill then stroke (§9.3.6).</summary>
    public PdfContentBuilder SetTextRenderMode(int mode) => Op("Tr", mode);

    public PdfContentBuilder SetTextMatrix(double a, double b, double c, double d, double e, double f)
        => Op("Tm", a, b, c, d, e, f);

    /// <summary>
    /// Shows 2-byte glyph codes (Identity-H) with a TJ array. <c>adjustAfter[i]</c> is the TJ number
    /// placed after glyph i, in thousandths of text space (positive moves the next glyph left).
    /// </summary>
    public PdfContentBuilder ShowGlyphs(IReadOnlyList<ushort> glyphs, IReadOnlyList<double>? adjustAfter = null)
    {
        if (glyphs.Count == 0) return this;
        _sb.Append("[<");
        for (int i = 0; i < glyphs.Count; i++)
        {
            _sb.Append(PdfFormat.Hex4(glyphs[i]));
            if (i == glyphs.Count - 1) break;
            double adj = adjustAfter is null ? 0 : Math.Round(adjustAfter[i], 2, MidpointRounding.AwayFromZero);
            if (adj != 0) _sb.Append("> ").Append(PdfFormat.Num(adj)).Append(" <");
        }
        _sb.Append(">] ");
        return Op("TJ");
    }

    public bool IsEmpty => _sb.Length == 0;

    public byte[] ToBytes() => PdfFormat.Bytes(_sb.ToString());

    public override string ToString() => _sb.ToString();
}
