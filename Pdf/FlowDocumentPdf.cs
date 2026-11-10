using System;
using System.Collections.Generic;
using System.IO;
using System.Diagnostics;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Documents;
using System.Windows.Media;
using System.Windows.Threading;
using RepoLegibility.Core.Pdf;

namespace RepoLegibility.Pdf;

/// <summary>Counts for a diagnostic line after an export.</summary>
/// <param name="Pages">Pages written.</param>
/// <param name="Fonts">Embedded fonts (each typeface / style simulation counts once).</param>
/// <param name="GlyphRuns">Text runs drawn.</param>
/// <param name="Links">Hyperlinks made clickable (one link may produce several annotations when it wraps).</param>
/// <param name="Skipped">Things not represented exactly: unlinked hyperlinks, approximations, full-font embedding.</param>
public sealed record PdfExportReport(int Pages, int Fonts, int GlyphRuns, int Links, IReadOnlyList<string> Skipped);

/// <summary>Thrown when the document contains something the PDF export cannot represent, or the file cannot be written.</summary>
public sealed class PdfExportException : Exception
{
    public PdfExportException() { }
    public PdfExportException(string message) : base(message) { }
    public PdfExportException(string message, Exception innerException) : base(message, innerException) { }
}

/// <summary>A laid-out page to write: its drawing and its size in DIP.</summary>
public readonly record struct PdfPage(Visual Visual, Size Size);

/// <summary>
/// Writes a FlowDocument to PDF using WPF's own pagination and glyph layout, so the PDF matches the
/// WPF preview. Hyperlinks become /Link annotations, one per laid-out line fragment: http(s) links open
/// the address, "#id" links jump to the block tagged with a <see cref="PdfAnchor"/> of that id. Anchors
/// of level 1 and 2 also become bookmarks.
/// </summary>
public static class FlowDocumentPdf
{
    private const string Producer = "RepoLegibility";

    /// <summary>
    /// Set to true on a visual added to a page that isn't the document's text: a footer, a header, a page
    /// number. Its text is drawn and can be copied, but links and anchors are never looked for in it, so a
    /// footer that repeats a heading's words can't catch the heading's bookmark.
    /// </summary>
    public static readonly DependencyProperty PageFurnitureProperty = DependencyProperty.RegisterAttached(
        "PageFurniture", typeof(bool), typeof(FlowDocumentPdf), new PropertyMetadata(false));

    public static bool GetPageFurniture(DependencyObject o) => (bool)o.GetValue(PageFurnitureProperty);
    public static void SetPageFurniture(DependencyObject o, bool value) => o.SetValue(PageFurnitureProperty, value);
    private const double A4WidthDip = 793.7007874015748;   // 210 mm
    private const double A4HeightDip = 1122.5196850393702; // 297 mm

    /// <summary>
    /// Writes <paramref name="document"/> to <paramref name="path"/>. Must be called on the document's
    /// UI thread. Throws <see cref="PdfExportException"/> with a plain-English message on anything it cannot
    /// represent; the target file is only replaced when the whole PDF was built successfully.
    /// </summary>
    public static PdfExportReport Save(FlowDocument document, string path) => Save(document, null, path);

    /// <summary>
    /// As <see cref="Save(FlowDocument, string)"/>, with the pages taken from <paramref name="paginator"/> — a
    /// paginator that wraps the document's own (e.g. one that adds a footer to every page). It must be
    /// set up already (page size, count); the document is then only read for its hyperlinks and anchors.
    /// </summary>
    public static PdfExportReport Save(FlowDocument document, DocumentPaginator? paginator, string path)
    {
        ArgumentNullException.ThrowIfNull(document);
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        document.VerifyAccess();
        string fullPath = FullPath(path);

        byte[] pdf;
        PdfExportReport report;
        try
        {
            (pdf, report) = paginator is null ? RenderOwnPages(document) : RenderPages(document, paginator);
        }
        catch (PdfExportException) { throw; }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            throw new PdfExportException("PDF export failed: " + ex.Message, ex);
        }

        WriteAtomically(fullPath, pdf);
        return report;
    }

    /// <summary>
    /// Writes pages already laid out (and shown, perhaps) without holding the UI thread: the pages are read
    /// a few at a time on <paramref name="ui"/>, between which the window keeps drawing and taking input,
    /// and the file is packed and written off it. Call it from any thread. <paramref name="pageDone"/> gets
    /// (pages read, pages) after each batch. On cancel it throws <see cref="OperationCanceledException"/>
    /// and writes nothing; the file is only replaced once the whole PDF is built.
    /// </summary>
    public static async Task<PdfExportReport> SaveAsync(FlowDocument document, IReadOnlyList<PdfPage> pages, string path,
        Dispatcher ui, Action<int, int>? pageDone = null, CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(document);
        ArgumentNullException.ThrowIfNull(pages);
        ArgumentNullException.ThrowIfNull(ui);
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        string fullPath = FullPath(path);
        if (pages.Count == 0) throw new PdfExportException("The document has no pages.");

        try
        {
            var export = await ui.InvokeAsync(() => new Export(document), DispatcherPriority.Background, token);
            int next = 0;
            while (next < pages.Count)
            {
                token.ThrowIfCancellationRequested();
                await ui.InvokeAsync(() =>
                {
                    var clock = Stopwatch.StartNew();
                    do { export.Walk(pages[next].Visual, pages[next].Size); next++; }
                    while (next < pages.Count && clock.ElapsedMilliseconds < 30);
                }, DispatcherPriority.Background, token);
                pageDone?.Invoke(next, pages.Count);
            }
            await ui.InvokeAsync(export.AddFonts, DispatcherPriority.Background, token);
            token.ThrowIfCancellationRequested();
            var (pdf, report) = await Task.Run(export.Finish, token);
            token.ThrowIfCancellationRequested(); // the last point to stop: after this the file is written whole
            WriteAtomically(fullPath, pdf);
            return report;
        }
        catch (Exception ex) when (ex is PdfExportException or OperationCanceledException) { throw; }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            throw new PdfExportException("PDF export failed: " + ex.Message, ex);
        }
    }

    private static string FullPath(string path)
    {
        try { return Path.GetFullPath(path); }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        { throw new PdfExportException($"The PDF path is not valid: {path}", ex); }
    }

    private static (byte[] Pdf, PdfExportReport Report) RenderOwnPages(FlowDocument document)
    {
        // Paginate at the document's own page size; A4 only where none is set. Restored afterwards.
        object oldWidth = document.ReadLocalValue(FlowDocument.PageWidthProperty);
        object oldHeight = document.ReadLocalValue(FlowDocument.PageHeightProperty);
        if (double.IsNaN(document.PageWidth)) document.PageWidth = A4WidthDip;
        if (double.IsNaN(document.PageHeight)) document.PageHeight = A4HeightDip;
        try
        {
            DocumentPaginator paginator = ((IDocumentPaginatorSource)document).DocumentPaginator;
            paginator.ComputePageCount();
            return RenderPages(document, paginator);
        }
        finally
        {
            Restore(document, FlowDocument.PageWidthProperty, oldWidth);
            Restore(document, FlowDocument.PageHeightProperty, oldHeight);
        }
    }

    private static (byte[] Pdf, PdfExportReport Report) RenderPages(FlowDocument document, DocumentPaginator paginator)
    {
        var export = new Export(document);
        if (!paginator.IsPageCountValid) paginator.ComputePageCount();
        for (int i = 0; i < paginator.PageCount; i++)
        {
            using DocumentPage page = paginator.GetPage(i);
            if (page == DocumentPage.Missing || page.Visual is null)
                throw new PdfExportException($"Page {i + 1} of the document could not be laid out.");
            export.Walk(page.Visual, page.Size);
        }
        export.AddFonts();
        return export.Finish();
    }

    /// <summary>
    /// One export in three steps: the pages are walked and the fonts gathered on the UI thread; then
    /// links, bookmarks and the file are made from what that gathered, on any thread.
    /// </summary>
    private sealed class Export
    {
        private readonly PdfDocumentBuilder _builder = new(Producer);
        private readonly FontCollector _fonts = new();
        private readonly PageWalker _walker;
        private readonly List<(byte[] Content, Size Size)> _pages = new();
        private readonly List<string> _skipped = new();
        private readonly List<LinkTarget> _links;
        private readonly List<(PdfAnchor Anchor, string Key)> _anchors;

        public Export(FlowDocument document)
        {
            document.VerifyAccess();
            _walker = new PageWalker(_builder, _fonts);
            _links = HyperlinkCollector.Collect(document, _skipped);
            _anchors = AnchorCollector.Collect(document);
        }

        public void Walk(Visual visual, Size size) => _pages.Add((_walker.WalkPage(visual, _pages.Count, size.Height), size));

        public void AddFonts()
        {
            if (_pages.Count == 0) throw new PdfExportException("The document has no pages.");
            if (_walker.Unsupported.Count > 0) throw new PdfExportException(UnsupportedMessage(_walker.Unsupported));
            _fonts.AddTo(_builder, _skipped);
            _skipped.AddRange(_walker.Notes);
        }

        public (byte[] Pdf, PdfExportReport Report) Finish()
        {
            var heights = new double[_pages.Count];
            for (int i = 0; i < _pages.Count; i++) heights[i] = _pages[i].Size.Height;
            var places = LinkPlacer.Locate(_anchors, _walker.Chars, _skipped);
            var annotations = LinkPlacer.Place(_links, _walker.Chars, heights, places, _skipped, out int placed);

            const double k = PageWalker.PointsPerDip;
            for (int i = 0; i < _pages.Count; i++)
                _builder.AddPage(_pages[i].Size.Width * k, _pages[i].Size.Height * k, _pages[i].Content, annotations[i]);
            foreach (var (anchor, _) in _anchors)
                if (anchor.Level is 1 or 2 && places.TryGetValue(anchor.Id, out var at) && ReferenceEquals(at.Anchor, anchor))
                    _builder.AddOutline(anchor.Title, anchor.Level, at.Page, (heights[at.Page] - Math.Max(0, at.Top - 6)) * k);

            var report = new PdfExportReport(_pages.Count, _builder.FontCount, _walker.GlyphRuns, placed, _skipped.AsReadOnly());
            return (_builder.Build(), report);
        }
    }

    private static void Restore(FlowDocument document, DependencyProperty property, object localValue)
    {
        if (localValue == DependencyProperty.UnsetValue) document.ClearValue(property);
        else document.SetValue(property, localValue);
    }

    private static string UnsupportedMessage(IReadOnlyDictionary<string, int> items)
    {
        var sb = new StringBuilder("The document contains content the PDF export cannot represent, so no PDF was written:");
        foreach (var (what, count) in items)
            sb.Append("\n- ").Append(what).Append(count > 1 ? $" ({count}×)" : "");
        return sb.ToString();
    }

    private static void WriteAtomically(string fullPath, byte[] pdf)
    {
        string temp = fullPath + ".partial";
        try
        {
            File.WriteAllBytes(temp, pdf);
            File.Move(temp, fullPath, overwrite: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            try { File.Delete(temp); } catch (IOException) { } catch (UnauthorizedAccessException) { }
            throw new PdfExportException($"Could not write the PDF to {fullPath}: {ex.Message}", ex);
        }
    }
}
