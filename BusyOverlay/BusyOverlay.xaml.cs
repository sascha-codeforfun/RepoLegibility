// HueTheme kit 1.1.5

using System;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media.Animation;
using System.Windows.Threading;

namespace BusyOverlayKit;

/// <summary>
/// Full-window busy overlay: two counter-rotating rings, title, detail line, optional bar
/// and cancel button.
/// Contract: the body passed to RunAsync runs on a worker and touches no control. WPF
/// animates on the dispatcher, so work on the UI thread freezes the rings. That is why
/// RunAsync returns a value: the caller draws it on the UI thread after the overlay is down.
/// </summary>
public partial class BusyOverlay : UserControl
{
    private CancellationTokenSource? _cancel;
    private DispatcherTimer? _delay;
    private string _title = string.Empty;
    private (string Detail, int? Done, int? Total) _latest;

    public BusyOverlay()
    {
        InitializeComponent();
    }

    /// <summary>True between the start and end of a run, whether or not the overlay is yet visible.</summary>
    public bool IsBusy { get; private set; }

    /// <summary>
    /// How long work must run before the overlay shows. An overlay that flashes up and away
    /// reads as a glitch. <see cref="TimeSpan.Zero"/> shows it at once.
    /// </summary>
    public TimeSpan AppearAfter { get; set; } = TimeSpan.FromMilliseconds(350);

    /// <summary>
    /// Whether the rings turn; null follows the system. A set value wins either way, not an
    /// AND: Windows turns animation off in remote sessions by itself, and the user would
    /// otherwise have no way to get it back. With motion off the rings still show, still.
    /// </summary>
    public bool? AnimateOverride { get; set; }

    private bool Animating => AnimateOverride ?? SystemParameters.ClientAreaAnimation;

    // ------------------------------------------------------------- appearance
    //
    // Colours come from HueTheme tokens in BusyOverlay.xaml; only the size is a property.

    public static readonly DependencyProperty MarkSizeProperty =
        DependencyProperty.Register(nameof(MarkSize), typeof(double), typeof(BusyOverlay),
            new PropertyMetadata(104.0));

    /// <summary>Diameter of the rings in device-independent pixels. Default 104.</summary>
    public double MarkSize { get => (double)GetValue(MarkSizeProperty); set => SetValue(MarkSizeProperty, value); }

    // ------------------------------------------------------------- running

    /// <summary>Runs synchronous work on a worker thread with the overlay up.</summary>
    public async Task<T> RunAsync<T>(string title, Func<BusyReport, T> body,
                                     CancellationTokenSource? cancel = null) =>
        await RunAsync(title, report => Task.Run(() => body(report)), cancel);

    /// <summary>
    /// For work that is already async. Its own overload so callers never block on a task
    /// inside the body, which deadlocks once a synchronisation context is involved.
    /// </summary>
    public async Task<T> RunAsync<T>(string title, Func<BusyReport, Task<T>> body,
                                     CancellationTokenSource? cancel = null)
    {
        Begin(title, cancel);

        try
        {
            // Below Render, so frequent reports cannot starve the rings of frames.
            var report = new BusyReport((detail, done, total) =>
                Dispatcher.BeginInvoke(DispatcherPriority.Background,
                    new Action(() => Update(detail, done, total))));

            // Task.Run, not a bare await: awaited directly, the body would start on the UI
            // thread and resume there after every await.
            return await Task.Run(async () => await body(report));
        }
        finally
        {
            // An overlay left up after a failure locks the app out of itself.
            End();
        }
    }

    /// <summary>Runs work that returns nothing.</summary>
    /// <remarks>
    /// The <c>(object?)</c> cast is load-bearing: a bare null would bind the lambda to the
    /// async overload, which then awaits null and throws.
    /// </remarks>
    public async Task RunAsync(string title, Action<BusyReport> body,
                               CancellationTokenSource? cancel = null) =>
        await RunAsync<object?>(title, report => { body(report); return (object?)null; }, cancel);

    // ------------------------------------------------------------- internals

    private void Begin(string title, CancellationTokenSource? cancel)
    {
        IsBusy = true;
        _cancel = cancel;
        _title = title;
        _latest = (string.Empty, null, null);

        _delay?.Stop();

        if (AppearAfter <= TimeSpan.Zero)
        {
            Reveal();
            return;
        }

        // This constructor starts the timer.
        _delay = new DispatcherTimer(AppearAfter, DispatcherPriority.Normal,
            (_, _) => Reveal(), Dispatcher);
    }

    private void Reveal()
    {
        _delay?.Stop();
        _delay = null;

        if (!IsBusy || Visibility == Visibility.Visible) return;

        TitleText.Text = _title;
        Bar.Visibility = Visibility.Collapsed;

        CancelButton.Visibility = _cancel is null ? Visibility.Collapsed : Visibility.Visible;
        CancelButton.IsEnabled = _cancel is not null;

        Visibility = Visibility.Visible;

        // Reports that arrived during the delay.
        Update(_latest.Detail, _latest.Done, _latest.Total);

        if (Animating) ((Storyboard)Resources["BusySpin"]).Begin(this, true);
    }

    private void Update(string detail, int? done, int? total)
    {
        _latest = (detail, done, total);

        if (Visibility != Visibility.Visible) return;

        DetailText.Text = detail;

        if (done is not { } d || total is not { } t || t <= 0) return;

        Bar.Visibility = Visibility.Visible;
        Bar.Maximum = t;
        Bar.Value = Math.Min(d, t);
    }

    /// <summary>
    /// Requests a stop and says so. The overlay stays up until the work really stops (the
    /// finally in RunAsync); taking it down here would hand back a window that is still busy.
    /// </summary>
    private void OnCancelClick(object sender, RoutedEventArgs e)
    {
        if (_cancel is null) return;

        CancelButton.IsEnabled = false;
        DetailText.Text = "Stopping…";
        _cancel.Cancel();
    }

    private void End()
    {
        IsBusy = false;
        _delay?.Stop();
        _delay = null;

        // A hidden storyboard still costs frames. Unconditional: the setting may have changed.
        ((Storyboard)Resources["BusySpin"]).Stop(this);

        Visibility = Visibility.Collapsed;
        Bar.Visibility = Visibility.Collapsed;
        CancelButton.Visibility = Visibility.Collapsed;
        _cancel = null;
    }
}
