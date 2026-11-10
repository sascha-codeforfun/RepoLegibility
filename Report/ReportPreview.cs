using System.IO;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Markup;
using System.Windows.Media;
using BusyOverlayKit;
using HueThemeKit;
using RepoLegibility.Core;
using RepoLegibility.Pdf;

namespace RepoLegibility.Report;

/// <summary>
/// The report as it will print, with Save as PDF. Saving starts in the user's Documents folder, then
/// in the last folder used while the app runs; nothing is remembered after it closes.
/// </summary>
internal static class ReportPreview
{
    private static string? _lastFolder;

    /// <summary>Shows pages laid out by <see cref="ReportPages.LayOutAsync"/>; Save as PDF writes those same pages.</summary>
    public static void Show(Window owner, ScanReport report, ReportPages laidOut)
    {
        var shown = laidOut.Shown;

        var viewer = new DocumentViewer { Document = shown, Template = PagesOnly() };
        viewer.SetResourceReference(Control.BackgroundProperty, "Brush.Base");

        var window = new Window
        {
            Title = "Report: " + report.RepoName,
            Owner = owner,
            Width = 980,
            Height = Math.Min(1040, SystemParameters.WorkArea.Height * 0.92),
            ShowInTaskbar = false,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
        };
        window.SetResourceReference(FrameworkElement.StyleProperty, "Hue.Window");
        HueTitleBar.Attach(window);

        var note = new TextBlock
        {
            Text = $"{shown.Pages.Count} page{(shown.Pages.Count == 1 ? "" : "s")}, light for printing. The PDF names the zip's SHA-256, so it records exactly what was looked at.",
            TextWrapping = TextWrapping.Wrap,
            VerticalAlignment = VerticalAlignment.Center,
        };
        note.SetResourceReference(FrameworkElement.StyleProperty, "Text.Caption");

        var save = new Button { Content = "Save as PDF…", MinWidth = 130, Margin = new Thickness(12, 0, 0, 0) };
        save.SetResourceReference(FrameworkElement.StyleProperty, "Hue.Button.Primary");
        // Saving a long report takes a while: the overlay counts the pages and can stop it.
        var busy = new BusyOverlay { AnimateOverride = true };
        bool closeWhenDone = false;
        CancellationTokenSource? saving = null;
        save.Click += async (_, _) =>
        {
            if (busy.IsBusy) return;
            using var cancel = new CancellationTokenSource();
            saving = cancel;
            try { await SavePdf(window, busy, report, laidOut, cancel); }
            finally { saving = null; }
            if (closeWhenDone) window.Close();
        };
        // Closing mid-save stops the save first (nothing is written), then closes.
        window.Closing += (_, e) =>
        {
            if (!busy.IsBusy) return;
            e.Cancel = true;
            closeWhenDone = true;
            saving?.Cancel();
        };

        var close = new Button { Content = "Close", MinWidth = 100, Margin = new Thickness(12, 0, 0, 0), IsCancel = true };
        close.SetResourceReference(FrameworkElement.StyleProperty, "Hue.Button.Outline");
        close.Click += (_, _) => window.Close();

        var buttons = new StackPanel { Orientation = Orientation.Horizontal };
        buttons.Children.Add(save);
        buttons.Children.Add(close);
        var bar = new DockPanel { Margin = new Thickness(20, 12, 20, 12) };
        DockPanel.SetDock(buttons, Dock.Right);
        bar.Children.Add(buttons);
        bar.Children.Add(note);
        var barBorder = new Border { Child = bar, BorderThickness = new Thickness(0, 1, 0, 0) };
        barBorder.SetResourceReference(Border.BackgroundProperty, "Brush.Chrome");
        barBorder.SetResourceReference(Border.BorderBrushProperty, "Brush.LineSoft");

        var layout = new DockPanel();
        DockPanel.SetDock(barBorder, Dock.Bottom);
        layout.Children.Add(barBorder);
        var tools = Tools(viewer);
        DockPanel.SetDock(tools, Dock.Top);
        layout.Children.Add(tools);
        layout.Children.Add(viewer);
        var root = new Border { Child = layout };
        root.SetResourceReference(Border.BackgroundProperty, "Brush.Surface");
        var host = new Grid();
        host.Children.Add(root);
        host.Children.Add(busy);
        window.Content = host;

        window.Loaded += (_, _) => viewer.FitToWidth();
        window.ShowDialog();
    }

    /// <summary>
    /// The viewer without its built-in tool and search bars, which Windows draws light and the theme
    /// can't reach: only the scroll viewer that holds the pages.
    /// </summary>
    private static ControlTemplate PagesOnly() =>
        (ControlTemplate)XamlReader.Parse(
            "<ControlTemplate TargetType=\"DocumentViewer\" xmlns=\"http://schemas.microsoft.com/winfx/2006/xaml/presentation\" " +
            "xmlns:x=\"http://schemas.microsoft.com/winfx/2006/xaml\">" +
            "<Border Background=\"{TemplateBinding Background}\">" +
            "<ScrollViewer x:Name=\"PART_ContentHost\" CanContentScroll=\"True\" HorizontalScrollBarVisibility=\"Auto\" " +
            "VerticalScrollBarVisibility=\"Auto\" Focusable=\"False\" />" +
            "</Border></ControlTemplate>");

    /// <summary>The preview's own tool bar, in the app's theme: zoom, fit to width, a whole page, two pages.</summary>
    private static FrameworkElement Tools(DocumentViewer viewer)
    {
        var bar = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(16, 8, 16, 8) };
        void Add(string label, string tip, Action act)
        {
            var button = new Button { Content = label, MinWidth = 40, Margin = new Thickness(0, 0, 8, 0), ToolTip = tip };
            button.SetResourceReference(FrameworkElement.StyleProperty, "Hue.Button.Outline");
            button.Click += (_, _) => act();
            AutomationProperties.SetName(button, tip);
            bar.Children.Add(button);
        }

        Add("−", "Zoom out", viewer.DecreaseZoom);
        Add("+", "Zoom in", viewer.IncreaseZoom);
        Add("Fit width", "Fit the page to the window's width", viewer.FitToWidth);
        Add("Whole page", "Show one whole page", viewer.FitToHeight);
        Add("Two pages", "Show two pages side by side", () => viewer.FitToMaxPagesAcross(2));
        var root = new Border { Child = bar, BorderThickness = new Thickness(0, 0, 0, 1) };
        root.SetResourceReference(Border.BackgroundProperty, "Brush.Surface");
        root.SetResourceReference(Border.BorderBrushProperty, "Brush.Line");
        return root;
    }

    private static async Task SavePdf(Window owner, BusyOverlay busy, ScanReport report, ReportPages laidOut, CancellationTokenSource cancel)
    {
        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            Title = "Save the report as PDF",
            FileName = ReportDocument.SuggestedName(report),
            DefaultExt = ".pdf",
            Filter = "PDF document (*.pdf)|*.pdf",
            InitialDirectory = _lastFolder is { } folder && Directory.Exists(folder)
                ? folder
                : Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            OverwritePrompt = true,
        };
        if (dialog.ShowDialog(owner) != true) return;
        string path = dialog.FileName;
        var ui = owner.Dispatcher;

        try
        {
            // The pages on screen are the pages in the file: nothing is laid out twice.
            var result = await busy.RunAsync("Saving the PDF", say =>
                FlowDocumentPdf.SaveAsync(laidOut.Document, laidOut.Pages, path, ui,
                    (done, total) => say.Say(done < total ? $"Page {done:N0} of {total:N0}" : "Packing the file", done, total),
                    cancel.Token), cancel);
            _lastFolder = Path.GetDirectoryName(path);
            if (result.Skipped.Count > 0)
                HueMessage.Show(owner, "The PDF was saved, with notes", Notes(result.Skipped));
            else
                HueMessage.Show(owner, "The PDF was saved", $"{result.Pages} page{(result.Pages == 1 ? "" : "s")} in {path}");
        }
        catch (OperationCanceledException)
        {
            // Stopped: no file was written, and an existing one with that name is untouched.
        }
        catch (PdfExportException ex)
        {
            HueMessage.Show(owner, "The PDF could not be made", ex.Message);
        }
    }

    /// <summary>The notes as a list, the first dozen of them: a long report can have many of one kind.</summary>
    private static string Notes(IReadOnlyList<string> notes) =>
        string.Join(Environment.NewLine, notes.Take(12).Select(n => "• " + n))
        + (notes.Count > 12 ? $"{Environment.NewLine}… and {notes.Count - 12} more." : "");
}
