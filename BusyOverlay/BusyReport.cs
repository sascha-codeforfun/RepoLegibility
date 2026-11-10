// HueTheme kit 1.1.5

using System;

namespace BusyOverlayKit;

/// <summary>
/// Progress channel handed to the RunAsync body. A plain callback, not IProgress&lt;T&gt;, so
/// the overlay can post updates below Render priority and keep the rings turning.
/// </summary>
public sealed class BusyReport
{
    private readonly Action<string, int?, int?> _to;

    internal BusyReport(Action<string, int?, int?> to) => _to = to;

    /// <summary>
    /// The detail line, and a position only when it is real: no count, no bar, rather than a
    /// bar that invents one.
    /// </summary>
    public void Say(string detail, int? done = null, int? total = null) => _to(detail, done, total);
}
