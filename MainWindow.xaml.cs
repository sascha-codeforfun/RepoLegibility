using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Automation;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Threading;
using HueThemeKit;
using RepoLegibility.Core;
using RepoLegibility.Report;
using RepoLegibility.Ui;

namespace RepoLegibility;

public partial class MainWindow : Window
{
    private ScanReport? _report;
    private List<FindingRow> _rows = new();
    private Dictionary<string, Combination> _combinations = new();
    /// <summary>Set by "Show these" on the Overview: the list shows only these until cleared.</summary>
    private HashSet<Finding>? _focus;
    // Where a Show button or a header pill came from: the tab and how far down it was scrolled.
    private (TabItem Tab, ScrollViewer Scroll, double Offset)? _back;
    private ICollectionView? _view;
    private readonly DispatcherTimer _tick = new() { Interval = TimeSpan.FromSeconds(1) };
    private readonly Stopwatch _scanClock = new();

    public MainWindow()
    {
        InitializeComponent();
        HueTitleBar.Attach(this);

        VersionText.Text = HueVersion.Text;
        SdkText.Text = "built with SDK " + (HueVersion.Sdk ?? "unknown");
        RuntimeText.Text = "runtime " + HueVersion.Runtime;

        _tick.Tick += (_, _) => ScanPill.Content = "Scan " + Clock(_scanClock.Elapsed, running: true);
        UpdateFilterLabels();

        // A zip named on the command line is read straight away.
        Loaded += async (_, _) =>
        {
            var arg = Environment.GetCommandLineArgs().Skip(1).FirstOrDefault(a => a.EndsWith(".zip", StringComparison.OrdinalIgnoreCase) && File.Exists(a));
            if (arg is not null) await ScanAsync(arg);
        };
    }

    // ---- opening a zip ---------------------------------------------------------------------------

    private async void Open_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Title = "Open a repo zip",
            Filter = "Zip archive (*.zip)|*.zip",
            CheckFileExists = true,
        };
        if (dialog.ShowDialog(this) == true) await ScanAsync(dialog.FileName);
    }

    private static string? DroppedZip(DragEventArgs e) =>
        e.Data.GetData(DataFormats.FileDrop) is string[] { Length: 1 } files
        && files[0].EndsWith(".zip", StringComparison.OrdinalIgnoreCase) && File.Exists(files[0])
            ? files[0]
            : null;

    private void Window_DragOver(object sender, DragEventArgs e)
    {
        e.Effects = !Busy.IsBusy && DroppedZip(e) is not null ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;
    }

    private async void Window_Drop(object sender, DragEventArgs e)
    {
        if (DroppedZip(e) is { } zip) await ScanAsync(zip);
    }

    private async Task ScanAsync(string path)
    {
        if (Busy.IsBusy) return;
        var name = Path.GetFileName(path);

        ScanPill.SetResourceReference(StyleProperty, "Hue.Pill.Warn");
        ScanPill.Content = "Scan 0 s";
        ScanPill.Visibility = Visibility.Visible;
        _scanClock.Restart();
        _tick.Start();
        SetStatus("Reading " + name + "…", "Brush.Warn");

        // After a scan, the pill and the status bar give the scan's own time, the same number in both.
        TimeSpan? took = null;
        try
        {
            var report = await Busy.RunAsync("Reading " + name, r => Analyzer.Analyze(path, HueVersion.Number, Throttled(r)));
            _scanClock.Stop();
            took = report.Took;
            Show(report);
            SetStatus($"Read {name}: {report.Findings.Count} finding{(report.Findings.Count == 1 ? "" : "s")} in {Clock(report.Took)}.", "Brush.Ok");
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException or UnauthorizedAccessException or NotSupportedException)
        {
            _scanClock.Stop();
            SetStatus("Couldn't read " + name + ".", "Brush.Error");
            HueMessage.Show(this, "The zip couldn't be read",
                ex is InvalidDataException ? name + " isn't a zip archive, or it's damaged." : ex.Message);
        }
        finally
        {
            _tick.Stop();
            ScanPill.Content = "Scan " + Clock(took ?? _scanClock.Elapsed);
            ScanPill.SetResourceReference(StyleProperty, "Hue.Pill.Stale");
        }
    }

    /// <summary>Progress at most every 80 ms: a report per file would flood the dispatcher and stall the rings.</summary>
    private static Action<string, int?, int?> Throttled(BusyOverlayKit.BusyReport report)
    {
        var clock = Stopwatch.StartNew();
        long last = -1000;
        return (detail, done, total) =>
        {
            long now = clock.ElapsedMilliseconds;
            if (now - Interlocked.Read(ref last) < 80) return;
            Interlocked.Exchange(ref last, now);
            report.Say(detail, done, total);
        };
    }

    /// <summary>"0.5 s" under a minute (whole seconds while it runs), "01:12" above, "1:02:03" past an hour.</summary>
    private static string Clock(TimeSpan t, bool running = false) =>
        // Under a tenth of a second: "< 0.1 s", so a fast scan doesn't read as nothing done.
        !running && t.TotalSeconds < 0.05 ? $"< {0.1:0.0} s"
        : Math.Round(t.TotalSeconds, 1) < 60 ? (running ? $"{(int)t.TotalSeconds} s" : $"{t.TotalSeconds:0.0} s")
        : t.TotalHours >= 1 ? t.ToString(@"h\:mm\:ss")
        : t.ToString(@"mm\:ss");

    // ---- showing a report ------------------------------------------------------------------------

    private void Show(ScanReport report)
    {
        _report = report;
        // What's worth knowing together comes first, in the order the rules go; then the findings.
        _combinations = report.Combinations.ToDictionary(c => c.Key);
        _rows = report.Combinations.Select((c, i) => new FindingRow(c.AsFinding(i - report.Combinations.Count)))
            .Concat(report.Findings.Select(f => new FindingRow(f))).ToList();
        _focus = null;
        _back = null;
        UpdateBar();

        var source = new CollectionViewSource { Source = _rows };
        _view = source.View;
        Sort(byPlace: false);
        _view.GroupDescriptions.Add(new PropertyGroupDescription(nameof(FindingRow.Group)));
        _view.Filter = o => o is FindingRow row && Visible(row);
        FindingList.ItemsSource = _view;

        Facts.DataContext = new FactsView(report);
        OverviewPanel.DataContext = new OverviewView(report);

        ZipText.Text = report.ZipName + "  ·  " + report.RepoName;
        ZipDetail.Text = $"SHA-256 {report.ZipSha256}  ·  {AiExport.Size(report.ZipBytes)}";
        ZipDetail.Visibility = Visibility.Visible;

        EmptyState.Visibility = Visibility.Collapsed;
        Tabs.Visibility = Visibility.Visible;
        // The plain-words page first: nobody gets the expert list before they ask for it.
        OverviewTab.IsSelected = true;
        CopyAiButton.IsEnabled = true;
        ReportButton.IsEnabled = true;

        ShowPills(report);
        UpdateFilterLabels();

        FindingList.SelectedIndex = _view.IsEmpty ? -1 : 0;
        if (FindingList.SelectedItem is not null) FindingList.ScrollIntoView(FindingList.SelectedItem);
        ShowDetail(FindingList.SelectedItem as FindingRow);
    }

    private void ShowPills(ScanReport r)
    {
        // The header says what needs attention now; the findings below say what was seen, each kind in its own
        // colour whatever its count. So here: red when there is any, green when there's none.
        Label(ObscuredButton, "Obscured " + r.Obscured + (r.Decoded > 0 ? $" · {r.Decoded} decoded" : ""));
        ObscuredPill.SetResourceReference(StyleProperty, r.Obscured > 0 ? "Hue.Pill.Error" : "Hue.Pill.Ok");
        ObscuredButton.Visibility = Visibility.Visible;
        Label(OpaqueButton, "Opaque " + r.Opaque);
        OpaquePill.SetResourceReference(StyleProperty, r.Opaque > 0 ? "Hue.Pill.Error" : "Hue.Pill.Ok");
        OpaqueButton.Visibility = Visibility.Visible;

        // Administrator rights Windows asks for are worth knowing before it runs, not an alarm: amber, and the
        // tooltip says how they're asked for.
        AdminButton.Visibility = r.Admin ? Visibility.Visible : Visibility.Collapsed;
        AdminButton.ToolTip = (r.AdminHow ?? "The app runs as administrator.") + " Click to show where.";
        AutomationProperties.SetName(AdminButton, "Admin");

        Label(WritesButton, "Writes " + r.Writes);
        WritesButton.Visibility = r.Writes > 0 ? Visibility.Visible : Visibility.Collapsed;
        Label(PathsButton, "Paths " + r.Paths);
        PathsButton.Visibility = r.Paths > 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    // ---- filtering -------------------------------------------------------------------------------

    private bool Visible(FindingRow row)
    {
        if (_focus is not null) return _focus.Contains(row.Finding);
        if (row.IsTest && ShowTests.IsChecked != true) return false;
        // The kit's rule (HuePill): nothing lit lets everything through; lit chips in a row add up; the rows narrow each other.
        var text = SearchBox.Text.Trim();
        // A finding with two directions passes when either is lit; one with none only while no direction is lit.
        var directions = Chips(DirectionChips);
        return HuePill.Lets(Chips(LegibilityChips), row.IsTogether ? "Together" : LegibilityKey(row.Legibility))
            && HuePill.Lets(Chips(ScopeChips), row.Scope.ToString())
            && (row.Directions.Count == 0 ? HuePill.Lets(directions, "None") : row.Directions.Any(d => HuePill.Lets(directions, d)))
            && (text.Length == 0 || row.Matches(text));
    }

    private static List<ToggleButton> Chips(Panel row) => row.Children.OfType<ToggleButton>().ToList();

    private static string LegibilityKey(Legibility legibility) => legibility switch
    {
        Legibility.Obscured => "Obscured",
        Legibility.Opaque => "Opaque",
        Legibility.Untraced => "Untraced",
        Legibility.PartlyClear => "RunTime",
        _ => "Clear"
    };

    /// <summary>Each chip names its count, zero included; its screen-reader name says the same.</summary>
    private void UpdateFilterLabels()
    {
        // The Together rows count on their own chip only: the others count findings.
        var shipped = _rows.Where(r => !r.IsTogether && (!r.IsTest || ShowTests.IsChecked == true)).ToList();
        FilterLabel(ShowTogether, "Together", _rows.Count(r => r.IsTogether));
        FilterLabel(ShowObscured, "Obscured", shipped.Count(r => r.Legibility == Legibility.Obscured));
        FilterLabel(ShowOpaque, "Opaque", shipped.Count(r => r.Legibility == Legibility.Opaque));
        FilterLabel(ShowUntraced, "Untraced", shipped.Count(r => r.Legibility == Legibility.Untraced));
        FilterLabel(ShowPartly, "Run time", shipped.Count(r => r.Legibility == Legibility.PartlyClear));
        FilterLabel(ShowClear, "Clear", shipped.Count(r => r.Legibility == Legibility.Clear));
        FilterLabel(ShowAdmin, "Admin", shipped.Count(r => r.Scope == Scope.Admin));
        FilterLabel(ShowWeb, "Web service", shipped.Count(r => r.Scope == Scope.WebService));
        FilterLabel(ShowUser, "User", shipped.Count(r => r.Scope == Scope.User));
        FilterLabel(ShowApp, "App", shipped.Count(r => r.Scope == Scope.App));
        FilterLabel(ShowReads, "Reads", shipped.Count(r => r.Finding.Direction.HasFlag(Direction.Reads)));
        FilterLabel(ShowChanges, "Changes", shipped.Count(r => r.Finding.Direction.HasFlag(Direction.Changes)));
        FilterLabel(ShowSends, "Sends", shipped.Count(r => r.Finding.Direction.HasFlag(Direction.Sends)));
        FilterLabel(ShowReceives, "Receives", shipped.Count(r => r.Finding.Direction.HasFlag(Direction.Receives)));
        FilterLabel(ShowRuns, "Runs", shipped.Count(r => r.Finding.Direction.HasFlag(Direction.Runs)));
        ShowTestsText.Text = $"Tests {_rows.Count(r => r.IsTest)}";
    }

    private readonly Dictionary<ToggleButton, object?> _chipTips = new();

    // The splitter between the findings list and the code. Its line shows while the pointer is on it, while it's
    // dragged or while it has the keyboard focus (the arrow keys move it then); a double-click gives the usual
    // 2 to 3 split back. Where it was isn't saved: the app writes nothing.
    private bool _splitterDragging;

    private void ShowSplitLine()
    {
        bool on = _splitterDragging || ListCodeSplitter.IsMouseOver || ListCodeSplitter.IsKeyboardFocused;
        if (on) SplitLine.SetResourceReference(Border.BackgroundProperty, "Brush.AccentEdge");
        else SplitLine.Background = System.Windows.Media.Brushes.Transparent;
    }

    private void Splitter_Hover(object sender, MouseEventArgs e) => ShowSplitLine();

    private void Splitter_Focus(object sender, KeyboardFocusChangedEventArgs e) => ShowSplitLine();

    private void Splitter_Drag(object sender, RoutedEventArgs e)
    {
        _splitterDragging = e is DragStartedEventArgs;
        ShowSplitLine();
    }

    private void Splitter_Reset(object sender, MouseButtonEventArgs e)
    {
        ListColumn.Width = new GridLength(2, GridUnitType.Star);
        CodeColumn.Width = new GridLength(3, GridUnitType.Star);
        e.Handled = true;
    }

    /// <summary>
    /// A filter pill with its count. At 0 it can't show anything, so it's disabled: the kit takes its colour
    /// out (colour means there's something here), the tooltip says there are none, and so does its
    /// screen-reader name. It comes back when the count does (test code switched on, another repo). A lit
    /// pill is never disabled (the kit's rule: it couldn't be turned off again); it goes once it's unlit.
    /// </summary>
    private void FilterLabel(ToggleButton chip, string name, int count)
    {
        Label(chip, $"{name} {count}");
        if (!_chipTips.ContainsKey(chip)) _chipTips[chip] = chip.ToolTip;
        chip.IsEnabled = count > 0 || chip.IsChecked == true;
        ToolTipService.SetShowOnDisabled(chip, true);
        chip.ToolTip = count > 0 ? _chipTips[chip]
            : chip.IsChecked == true ? $"{name}: none in this repo now. Click to turn it off." : $"{name}: none in this repo";
        if (count == 0) AutomationProperties.SetName(chip, $"{name}, none");
    }

    private static void Label(ToggleButton chip, string text)
    {
        if (chip.Content is ContentControl pill) pill.Content = text;
        AutomationProperties.SetName(chip, text);
    }

    private void Filter_Changed(object sender, RoutedEventArgs e)
    {
        HuePill.Dim(Chips(LegibilityChips));
        HuePill.Dim(Chips(ScopeChips));
        HuePill.Dim(Chips(DirectionChips));
        // A pill picks from every finding again.
        ClearFocus();
        UpdateFilterLabels();
        Refresh();
    }

    private void Search_Changed(object sender, TextChangedEventArgs e)
    {
        // Typing searches every finding again: the Overview's selection was a starting point, not a filter to keep.
        if (_focus is not null && SearchBox.Text.Length > 0) ClearFocus();
        Refresh();
    }

    /// <summary>"Show these" on the Overview: Findings, with only those findings, and a bar that says so.</summary>
    private void ShowThese_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: ShowRequest request })
            ShowFocus(request.Title, request.Findings, request.CombinationKey);
    }

    /// <summary>A header pill: Findings with what it counts. Opaque lights its filter pill; the others use the bar.</summary>
    private void HeaderPill_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not ToggleButton { Tag: string which } pill || _report is null || _view is null) return;
        pill.IsChecked = false;   // a shortcut, not a filter: it never stays lit
        RememberWayBack();
        switch (which)
        {
            case "Obscured" or "Opaque":
                ResetFilters();
                (which == "Obscured" ? ShowObscured : ShowOpaque).IsChecked = true;
                HuePill.Dim(Chips(LegibilityChips));
                UpdateFilterLabels();
                FindingsTab.IsSelected = true;
                UpdateBar();
                Refresh();
                break;
            case "Admin":
                ShowFocus("Administrator rights", _report.Counted.Where(f => (f.Kind == FindingKind.Elevation || f.AsAdministrator) && f.Scope == Scope.Admin).ToList());
                break;
            case "Writes":
                ShowFocus("Writes", _report.Counted.Where(f => Names.Writes(f.Kind)).ToList());
                break;
            case "Paths":
                var writes = _report.Counted.Where(f => Names.Writes(f.Kind)).ToList();
                ShowFocus("Paths", writes, byPlace: true,
                    label: $"Paths: {_report.Paths} place{(_report.Paths == 1 ? "" : "s")}, written by {writes.Count} passage{(writes.Count == 1 ? "" : "s")}, sorted by place");
                break;
        }
        if (FindingList.SelectedItem is not null) FindingList.ScrollIntoView(FindingList.SelectedItem);
    }

    /// <summary>Every filter pill off and the search empty.</summary>
    private void ResetFilters()
    {
        foreach (var chip in Chips(LegibilityChips).Concat(Chips(ScopeChips)).Concat(Chips(DirectionChips))) chip.IsChecked = false;
        HuePill.Dim(Chips(LegibilityChips));
        HuePill.Dim(Chips(ScopeChips));
        HuePill.Dim(Chips(DirectionChips));
        SearchBox.Text = "";
        ClearFocus();
    }

    /// <summary>Findings with only these, and the bar that says so; sorted by place for the Paths pill.</summary>
    private void ShowFocus(string title, IReadOnlyList<Finding> findings, string? combinationKey = null, bool byPlace = false, string? label = null)
    {
        if (_view is null) return;
        RememberWayBack();
        ResetFilters();
        _focus = findings.ToHashSet();
        var together = combinationKey is { } key ? _rows.FirstOrDefault(r => r.IsTogether && r.Key == key) : null;
        if (together is not null) _focus.Add(together.Finding);
        if (byPlace) Sort(byPlace: true);
        FocusText.Text = label ?? $"{title}: {findings.Count} finding{(findings.Count == 1 ? "" : "s")}";
        UpdateFilterLabels();
        FindingsTab.IsSelected = true;
        UpdateBar();
        Refresh();
        if (together is not null) FindingList.SelectedItem = together;
        if (FindingList.SelectedItem is not null) FindingList.ScrollIntoView(FindingList.SelectedItem);
    }

    /// <summary>The list's order: by group and legibility, or (for the Paths pill) by the place written to.</summary>
    private void Sort(bool byPlace)
    {
        if (_view is null) return;
        using (_view.DeferRefresh())
        {
            _view.SortDescriptions.Clear();
            _view.SortDescriptions.Add(new SortDescription(nameof(FindingRow.GroupOrder), ListSortDirection.Ascending));
            if (byPlace) _view.SortDescriptions.Add(new SortDescription(nameof(FindingRow.Target), ListSortDirection.Ascending));
            _view.SortDescriptions.Add(new SortDescription(nameof(FindingRow.Legibility), ListSortDirection.Descending));
            _view.SortDescriptions.Add(new SortDescription(nameof(FindingRow.Unused), ListSortDirection.Ascending));   // can ranks below does
            _view.SortDescriptions.Add(new SortDescription(nameof(FindingRow.NotCalledByApp), ListSortDirection.Ascending)); // what the app does first
            _view.SortDescriptions.Add(new SortDescription(nameof(FindingRow.Id), ListSortDirection.Ascending));
        }
    }

    private void ClearFocus_Click(object sender, RoutedEventArgs e)
    {
        ClearFocus();
        Refresh();
    }

    private void ClearFocus()
    {
        if (_focus is null) return;
        _focus = null;
        FocusText.Text = "";
        UpdateBar();
        Sort(byPlace: false);
    }

    /// <summary>
    /// Notes the tab a jump to Findings starts from, and how far down it was. From Findings itself (a
    /// header pill while there) the way back stays what it was.
    /// </summary>
    private void RememberWayBack()
    {
        if (OverviewTab.IsSelected) _back = (OverviewTab, OverviewScroll, OverviewScroll.VerticalOffset);
        else if (FactsTab.IsSelected) _back = (FactsTab, FactsScroll, FactsScroll.VerticalOffset);
    }

    /// <summary>The bar above the list: the way back where there is one, what's shown, and Show all while a selection is on.</summary>
    private void UpdateBar()
    {
        BackButton.Visibility = _back is null ? Visibility.Collapsed : Visibility.Visible;
        if (_back is { } back)
        {
            BackButton.Content = "Back to " + back.Tab.Header;
            BackButton.ToolTip = $"Back to where you were on {back.Tab.Header}";
        }
        ShowAllButton.Visibility = _focus is null ? Visibility.Collapsed : Visibility.Visible;
        FocusBar.Visibility = _focus is null && _back is null ? Visibility.Collapsed : Visibility.Visible;
    }

    /// <summary>Back to the tab the jump came from, scrolled to where it was; the selection on Findings stays.</summary>
    private void Back_Click(object sender, RoutedEventArgs e)
    {
        if (_back is not { } back) return;
        _back = null;
        UpdateBar();
        back.Tab.IsSelected = true;
        // After the tab's content is back in the window and laid out, or the offset has nothing to scroll.
        Dispatcher.InvokeAsync(() => back.Scroll.ScrollToVerticalOffset(back.Offset), DispatcherPriority.Loaded);
    }

    /// <summary>Leaving Findings by its tab ends the way back: the next jump sets its own.</summary>
    private void Tabs_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!ReferenceEquals(e.OriginalSource, Tabs) || FindingsTab.IsSelected || _back is null) return;
        _back = null;
        UpdateBar();
    }

    private void Refresh()
    {
        if (_view is null) return;
        var selected = FindingList.SelectedItem;
        _view.Refresh();
        if (selected is not null && _view.Cast<object>().Contains(selected)) FindingList.SelectedItem = selected;
        else FindingList.SelectedIndex = _view.IsEmpty ? -1 : 0;
    }

    // ---- the selected finding --------------------------------------------------------------------

    private void FindingList_SelectionChanged(object sender, SelectionChangedEventArgs e) =>
        ShowDetail(FindingList.SelectedItem as FindingRow);

    private void ShowDetail(FindingRow? row)
    {
        Detail.DataContext = row;
        DetailScroll.Visibility = row is null ? Visibility.Collapsed : Visibility.Visible;
        NoSelection.Visibility = row is null ? Visibility.Visible : Visibility.Collapsed;
        DetailScroll.ScrollToTop();
    }

    /// <summary>The code box scrolls sideways only; the wheel goes on to the page around it.</summary>
    private void PassWheelToPage(object sender, MouseWheelEventArgs e)
    {
        if (e.Handled) return;
        e.Handled = true;
        DetailScroll.RaiseEvent(new MouseWheelEventArgs(e.MouseDevice, e.Timestamp, e.Delta) { RoutedEvent = MouseWheelEvent, Source = sender });
    }

    // ---- exports ---------------------------------------------------------------------------------

    private void CopyAi_Click(object sender, RoutedEventArgs e)
    {
        if (_report is null) return;
        var text = AiExport.Build(_report);
        if (Copy(text, CopyAiText, "Copy for AI"))
            SetStatus($"Copied the report for an AI assistant: {text.Length:N0} characters.", "Brush.Ok");
    }

    private void CopyFinding_Click(object sender, RoutedEventArgs e)
    {
        if (_report is null || Detail.DataContext is not FindingRow row) return;
        if (row.IsTogether && _combinations.TryGetValue(row.Key, out var combination))
        {
            if (Copy(AiExport.BuildCombination(_report, combination), CopyFindingText, "Copy this one"))
                SetStatus($"Copied {combination.Title.ToLowerInvariant()} ({combination.Key}) for an AI assistant.", "Brush.Ok");
            return;
        }
        if (Copy(AiExport.BuildOne(_report, row.Finding), CopyFindingText, "Copy this one"))
            SetStatus($"Copied finding #{row.Id} for an AI assistant.", "Brush.Ok");
    }

    /// <summary>Puts text on the clipboard and shows "Copied" on the button for two seconds.</summary>
    private bool Copy(string text, TextBlock label, string normal)
    {
        try
        {
            Clipboard.SetText(text);
        }
        catch (System.Runtime.InteropServices.ExternalException)
        {
            SetStatus("The clipboard is in use by another program; try again.", "Brush.Warn");
            return false;
        }

        label.Text = "Copied";
        var timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
        timer.Tick += (_, _) => { timer.Stop(); label.Text = normal; };
        timer.Start();
        return true;
    }

    /// <summary>
    /// Lays the report out under the busy overlay (a large repo makes hundreds of pages), then shows it.
    /// Cancel stops the layout; nothing is shown then.
    /// </summary>
    private async void Report_Click(object sender, RoutedEventArgs e)
    {
        if (_report is not { } report || Busy.IsBusy) return;
        using var cancel = new CancellationTokenSource();
        ReportPages laidOut;
        try
        {
            laidOut = await Busy.RunAsync("Making the report", say => ReportPages.LayOutAsync(report, Dispatcher, say, cancel.Token), cancel);
        }
        catch (OperationCanceledException)
        {
            return;
        }
        ReportPreview.Show(this, report, laidOut);
    }

    // ---- status ----------------------------------------------------------------------------------

    private void SetStatus(string text, string dotBrush)
    {
        StatusText.Text = text;
        StatusDot.SetResourceReference(ForegroundProperty, dotBrush);
    }
}
