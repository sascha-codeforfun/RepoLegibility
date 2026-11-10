using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Media;
using RepoLegibility.Core.Pdf;

namespace RepoLegibility.Pdf;

/// <summary>A laid-out character with its box in page coordinates (DIP, origin top-left).</summary>
internal readonly record struct PlacedChar(char Ch, int Page, int Run, Rect Box);

/// <summary>
/// Turns one page visual into a PDF content stream. The content stream mirrors WPF's coordinate
/// system: a page-level matrix maps DIP (y down) to points (y up), and every visual / drawing group
/// pushes its own q … cm … Q, so drawing commands use local WPF coordinates unchanged.
/// </summary>
internal sealed class PageWalker
{
    public const double PointsPerDip = 72.0 / 96.0;
    private const double ItalicShear = 1.0 / 3.0;   // approximates WPF's italic simulation
    private const double BoldStrokeEm = 1.0 / 48.0; // approximates WPF's bold simulation

    private readonly PdfDocumentBuilder _doc;
    private readonly FontCollector _fonts;
    private PdfContentBuilder _cb = new();
    private int _page;
    private int _furniture; // > 0 while inside page furniture: its text is drawn and copyable, not searched for links

    public PageWalker(PdfDocumentBuilder doc, FontCollector fonts)
    {
        _doc = doc;
        _fonts = fonts;
    }

    /// <summary>Content that would be lost, with counts. Any entry stops the export.</summary>
    public Dictionary<string, int> Unsupported { get; } = new(StringComparer.Ordinal);

    /// <summary>Approximations that do not lose content (reported in Skipped).</summary>
    public List<string> Notes { get; } = new();

    public List<PlacedChar> Chars { get; } = new();
    public int GlyphRuns { get; private set; }

    /// <summary>Walks one page visual; <paramref name="pageHeightDip"/> is used for the y-axis flip.</summary>
    public byte[] WalkPage(Visual pageVisual, int pageIndex, double pageHeightDip)
    {
        _cb = new PdfContentBuilder();
        _page = pageIndex;
        _cb.SaveState();
        _cb.Transform(PointsPerDip, 0, 0, -PointsPerDip, 0, pageHeightDip * PointsPerDip);
        WalkVisual(pageVisual, Matrix.Identity, 1.0);
        _cb.RestoreState();
        return _cb.ToBytes();
    }

    // ---------------------------------------------------------------- visuals

    private void WalkVisual(Visual visual, Matrix parent, double opacity)
    {
        double op = opacity * VisualTreeHelper.GetOpacity(visual);
        if (op <= 0) return; // invisible; nothing is lost

        string where = visual.GetType().Name;
        if (VisualTreeHelper.GetOpacityMask(visual) is not null) Unsupported_($"opacity mask on {where}");
        if (VisualTreeHelper.GetEffect(visual) is not null) Unsupported_($"effect on {where}");

        Matrix local = VisualTreeHelper.GetTransform(visual)?.Value ?? Matrix.Identity;
        Vector offset = VisualTreeHelper.GetOffset(visual);
        local.Translate(offset.X, offset.Y);
        Matrix m = local * parent;

        bool furniture = visual.GetValue(FlowDocumentPdf.PageFurnitureProperty) is true;
        if (furniture) _furniture++;
        _cb.SaveState();
        if (!local.IsIdentity) _cb.Transform(local.M11, local.M12, local.M21, local.M22, local.OffsetX, local.OffsetY);

        Geometry? clip = VisualTreeHelper.GetClip(visual);
        if (clip is null || ApplyClip(clip))
        {
            DrawingGroup? drawing = VisualTreeHelper.GetDrawing(visual);
            if (drawing is not null) WalkDrawing(drawing, m, op);

            int n = VisualTreeHelper.GetChildrenCount(visual);
            for (int i = 0; i < n; i++)
            {
                if (VisualTreeHelper.GetChild(visual, i) is Visual child) WalkVisual(child, m, op);
                else Unsupported_($"3D or non-2D visual inside {where}");
            }
        }
        _cb.RestoreState();
        if (furniture) _furniture--;
    }

    /// <summary>Writes a clip path; returns false if the clip is empty (nothing inside is visible).</summary>
    private bool ApplyClip(Geometry clip)
    {
        if (clip.Bounds.IsEmpty) return false;
        bool evenOdd = WriteGeometry(clip);
        _cb.Clip(evenOdd);
        return true;
    }

    // --------------------------------------------------------------- drawings

    private void WalkDrawing(Drawing drawing, Matrix m, double opacity)
    {
        switch (drawing)
        {
            case DrawingGroup group:
                double op = opacity * group.Opacity;
                if (op <= 0) return;
                if (group.OpacityMask is not null) Unsupported_("opacity mask on a drawing group");
                Matrix local = group.Transform?.Value ?? Matrix.Identity;
                _cb.SaveState();
                if (!local.IsIdentity) _cb.Transform(local.M11, local.M12, local.M21, local.M22, local.OffsetX, local.OffsetY);
                if (group.ClipGeometry is null || ApplyClip(group.ClipGeometry))
                {
                    Matrix inner = local * m;
                    foreach (Drawing child in group.Children) WalkDrawing(child, inner, op);
                }
                _cb.RestoreState();
                break;
            case GlyphRunDrawing text:
                EmitGlyphRun(text, m, opacity);
                break;
            case GeometryDrawing shape:
                EmitGeometry(shape, opacity);
                break;
            default:
                Unsupported_(drawing.GetType().Name); // ImageDrawing, VideoDrawing, …
                break;
        }
    }

    private void EmitGeometry(GeometryDrawing shape, double opacity)
    {
        Geometry? geometry = shape.Geometry;
        if (geometry is null || geometry.Bounds.IsEmpty) return;

        bool fill = TryColor(shape.Brush, "fill", out var fc) && fc.A * opacity > 0;
        Pen? pen = shape.Pen;
        Rgba sc = default;
        bool stroke = pen is not null && pen.Thickness > 0 && TryColor(pen.Brush, "stroke", out sc) && sc.A * opacity > 0;
        if (!fill && !stroke) return;

        _cb.SaveState();
        double fa = fill ? fc.A * opacity : 1, sa = stroke ? sc.A * opacity : 1;
        if (fa < 1 || sa < 1) _cb.SetGraphicsState(_doc.AlphaState(fa, sa));
        if (fill) _cb.SetFillRgb(fc.R, fc.G, fc.B);
        if (stroke) ApplyPen(pen!, sc);
        bool evenOdd = WriteGeometry(geometry);
        if (fill && stroke) _cb.FillAndStroke(evenOdd);
        else if (fill) _cb.Fill(evenOdd);
        else _cb.Stroke();
        _cb.RestoreState();
    }

    private void ApplyPen(Pen pen, Rgba color)
    {
        _cb.SetStrokeRgb(color.R, color.G, color.B);
        _cb.SetLineWidth(pen.Thickness);
        _cb.SetLineCap(pen.StartLineCap switch
        {
            PenLineCap.Round => 1,
            PenLineCap.Square => 2,
            PenLineCap.Triangle => Note("triangle line caps drawn as flat caps", 0),
            _ => 0,
        });
        _cb.SetLineJoin(pen.LineJoin switch { PenLineJoin.Round => 1, PenLineJoin.Bevel => 2, _ => 0 });
        _cb.SetMiterLimit(Math.Max(1.0, pen.MiterLimit));
        var dashes = pen.DashStyle?.Dashes;
        if (dashes is { Count: > 0 })
        {
            var pattern = new double[dashes.Count];
            for (int i = 0; i < pattern.Length; i++) pattern[i] = Math.Max(0, dashes[i] * pen.Thickness);
            _cb.SetDash(pattern, pen.DashStyle!.Offset * pen.Thickness);
        }
    }

    /// <summary>Writes the geometry as path operators in its own coordinate space. Returns true for even-odd fill.</summary>
    private bool WriteGeometry(Geometry geometry)
    {
        PathGeometry path = PathGeometry.CreateFromGeometry(geometry);
        foreach (PathFigure figure in path.Figures)
        {
            foreach (PathSegment segment in figure.Segments)
            {
                if (segment is ArcSegment)
                {
                    path = geometry.GetFlattenedPathGeometry(0.05, ToleranceType.Absolute);
                    goto write;
                }
            }
        }
        write:
        Matrix t = path.Transform?.Value ?? Matrix.Identity;
        foreach (PathFigure figure in path.Figures)
        {
            Point p = t.Transform(figure.StartPoint);
            _cb.MoveTo(p.X, p.Y);
            Point current = figure.StartPoint;
            foreach (PathSegment segment in figure.Segments)
                current = WriteSegment(segment, current, t);
            if (figure.IsClosed) _cb.ClosePath();
        }
        return path.FillRule == FillRule.EvenOdd;
    }

    private Point WriteSegment(PathSegment segment, Point current, Matrix t)
    {
        switch (segment)
        {
            case LineSegment line:
                Line(line.Point);
                return line.Point;
            case PolyLineSegment poly:
                foreach (Point p in poly.Points) { Line(p); current = p; }
                return current;
            case BezierSegment bezier:
                Curve(bezier.Point1, bezier.Point2, bezier.Point3);
                return bezier.Point3;
            case PolyBezierSegment polyBezier:
                for (int i = 0; i + 2 < polyBezier.Points.Count; i += 3)
                {
                    Curve(polyBezier.Points[i], polyBezier.Points[i + 1], polyBezier.Points[i + 2]);
                    current = polyBezier.Points[i + 2];
                }
                return current;
            case QuadraticBezierSegment quad:
                Quad(current, quad.Point1, quad.Point2);
                return quad.Point2;
            case PolyQuadraticBezierSegment polyQuad:
                for (int i = 0; i + 1 < polyQuad.Points.Count; i += 2)
                {
                    Quad(current, polyQuad.Points[i], polyQuad.Points[i + 1]);
                    current = polyQuad.Points[i + 1];
                }
                return current;
            default:
                Unsupported_(segment.GetType().Name);
                return current;
        }

        void Line(Point p) { p = t.Transform(p); _cb.LineTo(p.X, p.Y); }
        void Curve(Point a, Point b, Point c)
        {
            a = t.Transform(a); b = t.Transform(b); c = t.Transform(c);
            _cb.CurveTo(a.X, a.Y, b.X, b.Y, c.X, c.Y);
        }
        void Quad(Point p0, Point q, Point p2) // quadratic → cubic: control points at 2/3 towards q
        {
            Curve(p0 + (q - p0) * (2.0 / 3.0), p2 + (q - p2) * (2.0 / 3.0), p2);
        }
    }

    // ------------------------------------------------------------------- text

    private void EmitGlyphRun(GlyphRunDrawing drawing, Matrix m, double opacity)
    {
        GlyphRun? run = drawing.GlyphRun;
        if (run is null || run.GlyphIndices.Count == 0) return;
        if (!TryColor(drawing.ForegroundBrush, "text", out var color) || color.A * opacity <= 0) return;
        if (run.IsSideways) { Unsupported_("sideways (vertical) text"); return; }

        GlyphRuns++;
        int runId = GlyphRuns;
        GlyphTypeface typeface = run.GlyphTypeface;
        double em = run.FontRenderingEmSize;
        FontEntry font = _fonts.Use(typeface);
        int count = run.GlyphIndices.Count;
        bool rtl = (run.BidiLevel & 1) == 1;

        // Glyph origins in local coordinates.
        var xs = new double[count];
        var ys = new double[count];
        bool simple = !rtl;
        double pen = run.BaselineOrigin.X;
        for (int i = 0; i < count; i++)
        {
            double adv = run.AdvanceWidths[i];
            Point off = run.GlyphOffsets is { Count: > 0 } offs && i < offs.Count ? offs[i] : default;
            if (off.X != 0 || off.Y != 0) simple = false;
            if (rtl) { pen -= adv; xs[i] = pen - off.X; }
            else { xs[i] = pen + off.X; pen += adv; }
            ys[i] = run.BaselineOrigin.Y - off.Y;
        }

        var glyphs = new ushort[count];
        for (int i = 0; i < count; i++) glyphs[i] = run.GlyphIndices[i];
        MapCharacters(run, font, xs, runId, m, em);

        StyleSimulations sim = typeface.StyleSimulations;
        double shear = (sim & StyleSimulations.ItalicSimulation) != 0 ? ItalicShear : 0;
        bool bold = (sim & StyleSimulations.BoldSimulation) != 0;

        _cb.SaveState();
        double alpha = color.A * opacity;
        if (alpha < 1) _cb.SetGraphicsState(_doc.AlphaState(alpha, alpha));
        _cb.SetFillRgb(color.R, color.G, color.B);
        if (bold) _cb.SetStrokeRgb(color.R, color.G, color.B).SetLineWidth(em * BoldStrokeEm);
        _cb.BeginText().SetFont(font.ResourceName, em);
        if (bold) _cb.SetTextRenderMode(2);
        if (simple)
        {
            // TJ number after glyph i = PDF width − actual WPF advance, in 1/1000 em.
            var adjust = new double[count];
            for (int i = 0; i < count; i++) adjust[i] = font.Width(glyphs[i]) - run.AdvanceWidths[i] / em * 1000.0;
            _cb.SetTextMatrix(1, 0, shear, -1, xs[0], ys[0]).ShowGlyphs(glyphs, adjust);
        }
        else
        {
            for (int i = 0; i < count; i++)
            {
                font.Width(glyphs[i]);
                _cb.SetTextMatrix(1, 0, shear, -1, xs[i], ys[i]).ShowGlyphs(new[] { glyphs[i] });
            }
        }
        _cb.EndText();
        _cb.RestoreState();
    }

    /// <summary>ToUnicode entries per cluster plus page boxes per character for link placement.</summary>
    private void MapCharacters(GlyphRun run, FontEntry font, double[] xs, int runId, Matrix m, double em)
    {
        IList<char>? chars = run.Characters;
        IList<ushort>? map = run.ClusterMap;
        int count = xs.Length;
        if (chars is null || chars.Count == 0)
        {
            Note($"text without character data on page {_page + 1} cannot be copied or searched", 0);
            return;
        }

        double ascent = run.GlyphTypeface.Baseline * em;
        double descent = (run.GlyphTypeface.Height - run.GlyphTypeface.Baseline) * em;
        double baseline = run.BaselineOrigin.Y;
        int ci = 0;
        while (ci < chars.Count)
        {
            int g0 = map is { Count: > 0 } ? map[ci] : Math.Min(ci, count - 1);
            int cj = ci + 1;
            while (cj < chars.Count && map is { Count: > 0 } && map[cj] == g0) cj++;
            if (map is null || map.Count == 0) cj = ci + 1;
            int g1 = cj < chars.Count ? (map is { Count: > 0 } ? map[cj] : Math.Min(cj, count)) : count;
            if (g1 <= g0) g1 = Math.Min(g0 + 1, count);
            if (g0 >= count) break;

            string text = string.Concat(Slice(chars, ci, cj));
            font.MapUnicode(run.GlyphIndices[g0], text);

            double left = double.MaxValue, right = double.MinValue;
            for (int g = g0; g < g1; g++)
            {
                left = Math.Min(left, xs[g]);
                right = Math.Max(right, xs[g] + run.AdvanceWidths[g]);
            }
            var box = new Rect(new Point(left, baseline - ascent), new Point(right, baseline + descent));
            box.Transform(m);
            if (_furniture == 0)
                foreach (char c in text) Chars.Add(new PlacedChar(c, _page, runId, box));
            ci = cj;
        }
    }

    private static IEnumerable<char> Slice(IList<char> chars, int from, int to)
    {
        for (int i = from; i < to; i++) yield return chars[i];
    }

    // ---------------------------------------------------------------- helpers

    private readonly record struct Rgba(double R, double G, double B, double A);

    private bool TryColor(Brush? brush, string use, out Rgba color)
    {
        color = default;
        if (brush is null) return false;
        if (brush is SolidColorBrush solid)
        {
            Color c = solid.Color;
            color = new Rgba(c.R / 255.0, c.G / 255.0, c.B / 255.0, c.A / 255.0 * brush.Opacity);
            return true;
        }
        Unsupported_($"{brush.GetType().Name} ({use})");
        return false;
    }

    private void Unsupported_(string what)
    {
        string key = $"{what} on page {_page + 1}";
        Unsupported[key] = Unsupported.TryGetValue(key, out int n) ? n + 1 : 1;
    }

    private int Note(string text, int value)
    {
        if (!Notes.Contains(text)) Notes.Add(text);
        return value;
    }
}
