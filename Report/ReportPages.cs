using System.Diagnostics;
using System.Windows;
using System.Windows.Documents;
using System.Windows.Markup;
using System.Windows.Threading;
using BusyOverlayKit;
using RepoLegibility.Core;
using RepoLegibility.Pdf;

namespace RepoLegibility.Report;

/// <summary>
/// The report laid out once, for the screen and the PDF alike: the document (for its links and
/// places), each page with its footer, and the same pages as a fixed document for the preview. A
/// large repo makes hundreds of pages, so the layout runs a few pages per turn of the UI thread: the
/// window keeps drawing, the busy overlay keeps counting, and Cancel stops it between two turns.
/// </summary>
internal sealed class ReportPages
{
    private const int TurnMs = 40;

    private ReportPages(FlowDocument document, List<PdfPage> pages, FixedDocument shown)
    {
        Document = document;
        Pages = pages;
        Shown = shown;
    }

    public FlowDocument Document { get; }
    public IReadOnlyList<PdfPage> Pages { get; }
    public FixedDocument Shown { get; }

    /// <summary>Call from any thread but the UI's (the busy overlay's body runs on the pool).</summary>
    public static async Task<ReportPages> LayOutAsync(ScanReport r, Dispatcher ui, BusyReport say, CancellationToken token)
    {
        say.Say("Writing the report");
        var document = await ui.InvokeAsync(() => ReportDocument.Build(r), DispatcherPriority.Background, token);
        var paginator = await ui.InvokeAsync(() =>
        {
            var p = ((IDocumentPaginatorSource)document).DocumentPaginator;
            p.PageSize = ReportDocument.PageSize;
            return p;
        }, DispatcherPriority.Background, token);

        // The pages one after another: each GetPage lays out only up to that page, so a turn stays short.
        var laidOut = new List<DocumentPage>();
        bool end = false;
        while (!end)
        {
            token.ThrowIfCancellationRequested();
            await ui.InvokeAsync(() =>
            {
                var clock = Stopwatch.StartNew();
                do
                {
                    if (paginator.IsPageCountValid && laidOut.Count >= paginator.PageCount) { end = true; break; }
                    var page = paginator.GetPage(laidOut.Count);
                    if (page == DocumentPage.Missing || page.Visual is null) { end = true; break; }
                    laidOut.Add(page);
                }
                while (clock.ElapsedMilliseconds < TurnMs);
            }, DispatcherPriority.Background, token);
            say.Say($"Laying out the pages: {laidOut.Count:N0} so far");
        }
        if (laidOut.Count == 0) throw new InvalidOperationException("The report has no pages.");

        // Now the count is known: the footers ("page n of m") and the copy for the screen.
        string footer = ReportDocument.FooterText(r);
        var pages = new List<PdfPage>(laidOut.Count);
        var shown = await ui.InvokeAsync(() =>
        {
            var d = new FixedDocument();
            d.DocumentPaginator.PageSize = ReportDocument.PageSize;
            return d;
        }, DispatcherPriority.Background, token);
        int next = 0;
        while (next < laidOut.Count)
        {
            token.ThrowIfCancellationRequested();
            await ui.InvokeAsync(() =>
            {
                var clock = Stopwatch.StartNew();
                do
                {
                    var page = laidOut[next];
                    var visual = ReportDocument.WithFooter(page, footer, next, laidOut.Count);
                    pages.Add(new PdfPage(visual, page.Size));
                    shown.Pages.Add(OnScreen(visual, page.Size));
                    next++;
                }
                while (next < laidOut.Count && clock.ElapsedMilliseconds < TurnMs);
            }, DispatcherPriority.Background, token);
            say.Say($"Page {next:N0} of {laidOut.Count:N0}", next, laidOut.Count);
        }
        token.ThrowIfCancellationRequested(); // a Cancel during the last batch still stops it
        return new ReportPages(document, pages, shown);
    }

    /// <summary>A page for the preview: the same drawing the PDF is made from, on a white sheet.</summary>
    private static PageContent OnScreen(System.Windows.Media.Visual visual, Size size)
    {
        var fixedPage = new FixedPage { Width = size.Width, Height = size.Height, Background = Paper.White };
        fixedPage.Children.Add(new PageVisualHost(visual, size));
        var content = new PageContent();
        ((IAddChild)content).AddChild(fixedPage);
        return content;
    }

    /// <summary>Hosts a page's drawing as an element, so a fixed page can show it.</summary>
    private sealed class PageVisualHost : FrameworkElement
    {
        private readonly System.Windows.Media.Visual _visual;
        private readonly Size _size;

        public PageVisualHost(System.Windows.Media.Visual visual, Size size)
        {
            _visual = visual;
            _size = size;
            AddVisualChild(visual);
        }

        protected override int VisualChildrenCount => 1;

        protected override System.Windows.Media.Visual GetVisualChild(int index) =>
            index == 0 ? _visual : throw new ArgumentOutOfRangeException(nameof(index));

        protected override Size MeasureOverride(Size availableSize) => _size;
    }
}
