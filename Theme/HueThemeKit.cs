// HueTheme kit 1.1.5
// Changed inside an app? Follow the guide's "Changing the kit inside an app": the line above
// becomes "HueTheme kit x.y.z · modified by <App>", and every change sits between APP markers.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using Microsoft.Win32;

namespace HueThemeKit;

// The code half of HueTheme.xaml: what XAML cannot do. Drop-in file; keep the namespace.
//
//   App.OnStartup:        HueContrast.Follow(this);
//   each window's ctor:   InitializeComponent(); HueTitleBar.Attach(this);
//   switches that ask:    <kit:HueSwitch StateChanging="..." />, with HueConfirm.Ask(...)
//   messages:             HueMessage.Show(...), HueMessage.Choose(...)
//   header version block: HueVersion.Text, HueVersion.Sdk, HueVersion.Runtime
//   filter pills:         <ToggleButton Style="{StaticResource Hue.PillToggle}" kit:HuePill.Dimmed="..." />,
//                         HuePill.Lets(...) to filter, HuePill.Dim(group) after each click
//
// Hue prefix on every class: C# resolves the app's own namespace before any using, so an
// app helper with the same name would silently shadow the kit's.

/// <summary>
/// While a Windows contrast theme is on, maps every theme brush to a system colour, turns
/// glows off and hands the title bar back to Windows. Brushes only, not styles, so layout,
/// focus and selection keep working in the user's colours. Follows the setting live.
/// </summary>
public static class HueContrast
{
    private static ResourceDictionary? _overrides;
    private static Application? _app;

    /// <summary>True while Windows has a contrast theme on.</summary>
    public static bool IsActive => SystemParameters.HighContrast;

    /// <summary>Raised on the UI thread after the brushes have been swapped either way.</summary>
    public static event EventHandler? Changed;

    public static void Follow(Application app)
    {
        if (_app is not null) return;
        _app = app;

        SystemParameters.StaticPropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(SystemParameters.HighContrast)) Refresh();
        };
        // Switching from one contrast theme to another changes colours, not HighContrast.
        SystemEvents.UserPreferenceChanged += (_, e) =>
        {
            if (e.Category is UserPreferenceCategory.Color or UserPreferenceCategory.Accessibility) Refresh();
        };

        Update();
    }

    private static void Refresh() => _app?.Dispatcher.BeginInvoke(new Action(Update));

    private static void Update()
    {
        if (_app is null) return;
        var merged = _app.Resources.MergedDictionaries;

        if (_overrides is not null)
        {
            merged.Remove(_overrides);
            _overrides = null;
        }

        if (IsActive)
        {
            // Added last, so it wins over the theme and anything merged before it.
            _overrides = Build();
            merged.Add(_overrides);
        }

        foreach (Window window in _app.Windows)
            HueTitleBar.Apply(window);

        Changed?.Invoke(null, EventArgs.Empty);
    }

    private static ResourceDictionary Build()
    {
        var window = SystemColors.WindowBrush;
        var text = SystemColors.WindowTextBrush;
        var gray = SystemColors.GrayTextBrush;
        var face = SystemColors.ControlBrush;
        var highlight = SystemColors.HighlightBrush;
        var onHighlight = SystemColors.HighlightTextBrush;

        var d = new ResourceDictionary();
        void Set(Brush brush, params string[] keys)
        {
            foreach (var key in keys) d[key] = brush;
        }

        Set(window, "Brush.Base", "Brush.Chrome", "Brush.Surface", "Brush.Hover",
            "Brush.AccentSoft", "Brush.AccentSoftHover", "Busy.Scrim", "Brush.OnStatus",
            "Brush.OkSoft", "Brush.WarnSoft", "Brush.LimitSoft", "Brush.ErrorSoft", "Brush.StaleSoft",
            "Brush.OkSoftHover", "Brush.WarnSoftHover", "Brush.ErrorSoftHover",
            "Brush.LinuxSoft", "Brush.LinuxSoftHover");
        Set(face, "Brush.Raised");
        Set(text, "Brush.LineSoft", "Brush.Line", "Brush.LineStrong", "Brush.ControlEdge",
            "Brush.Text", "Brush.TextDim", "Brush.TextMuted",
            "Brush.Syntax.Keyword", "Brush.Syntax.Type", "Brush.Syntax.String", "Brush.Syntax.Number", "Brush.Syntax.Comment",
            "Brush.Ok", "Brush.OkText", "Brush.OkEdge", "Brush.Warn", "Brush.WarnText", "Brush.WarnEdge",
            "Brush.Limit", "Brush.LimitText", "Brush.LimitEdge", "Brush.Error", "Brush.ErrorText", "Brush.ErrorEdge",
            "Brush.Stale", "Brush.StaleText", "Brush.StaleEdge",
            "Brush.Linux", "Brush.LinuxText", "Brush.LinuxEdge");
        Set(gray, "Brush.TextDisabled");
        Set(highlight, "Brush.Accent", "Brush.AccentMid", "Brush.AccentLight", "Brush.AccentText",
            "Brush.AccentFill", "Brush.AccentFillHover", "Brush.AccentEdge", "Brush.Glow",
            "Brush.ErrorSolid", "Brush.ErrorSolidHover", "Brush.LinuxSolid", "Brush.LinuxSolidHover",
            "Busy.Ring", "Busy.RingAccent");
        Set(onHighlight, "Brush.OnAccent", "Brush.OnError", "Brush.OnLinux");

        d["Glow.Opacity"] = 0.0;
        return d;
    }
}

/// <summary>
/// Dark title bar via DWM. Caption = Brush.Chrome, so title bar and menu read as one strip.
/// Caption colours need Windows 11; older builds ignore them and keep plain dark mode.
/// Brushes are read once: call <see cref="Apply"/> again after they change.
/// </summary>
public static class HueTitleBar
{
    private const int DwmwaUseImmersiveDarkModeOld = 19;
    private const int DwmwaUseImmersiveDarkMode = 20;
    private const int DwmwaBorderColor = 34;
    private const int DwmwaCaptionColor = 35;
    private const int DwmwaTextColor = 36;
    private const int DwmwaColorDefault = unchecked((int)0xFFFFFFFF);

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);

    public static void Attach(Window window)
    {
        if (new WindowInteropHelper(window).Handle != IntPtr.Zero)
            Apply(window);
        else
            window.SourceInitialized += (_, _) => Apply(window);
    }

    public static void Apply(Window window)
    {
        var hwnd = new WindowInteropHelper(window).Handle;
        if (hwnd == IntPtr.Zero) return;

        if (SystemParameters.HighContrast)
        {
            int off = 0;
            if (DwmSetWindowAttribute(hwnd, DwmwaUseImmersiveDarkMode, ref off, sizeof(int)) != 0)
                DwmSetWindowAttribute(hwnd, DwmwaUseImmersiveDarkModeOld, ref off, sizeof(int));
            foreach (var attribute in new[] { DwmwaCaptionColor, DwmwaTextColor, DwmwaBorderColor })
            {
                int system = DwmwaColorDefault;
                DwmSetWindowAttribute(hwnd, attribute, ref system, sizeof(int));
            }
            return;
        }

        int on = 1;
        if (DwmSetWindowAttribute(hwnd, DwmwaUseImmersiveDarkMode, ref on, sizeof(int)) != 0)
            DwmSetWindowAttribute(hwnd, DwmwaUseImmersiveDarkModeOld, ref on, sizeof(int));

        var chrome = Find(window, "Brush.Chrome");
        var text = Find(window, "Brush.Text");
        var accent = Find(window, "Brush.Accent");

        if (chrome is { } c) Set(hwnd, DwmwaCaptionColor, c);
        if (text is { } t) Set(hwnd, DwmwaTextColor, t);
        if (chrome is { } bg && accent is { } fg) Set(hwnd, DwmwaBorderColor, Blend(bg, fg, 0.55));
    }

    private static Color? Find(Window window, string key) =>
        (window.TryFindResource(key) as SolidColorBrush)?.Color;

    private static void Set(IntPtr hwnd, int attribute, Color color)
    {
        int colorRef = color.R | (color.G << 8) | (color.B << 16);   // COLORREF is 0x00BBGGRR
        DwmSetWindowAttribute(hwnd, attribute, ref colorRef, sizeof(int));
    }

    private static Color Blend(Color from, Color to, double amount) => Color.FromRgb(
        (byte)Math.Round(from.R + (to.R - from.R) * amount),
        (byte)Math.Round(from.G + (to.G - from.G) * amount),
        (byte)Math.Round(from.B + (to.B - from.B) * amount));
}

/// <summary>
/// A switch whose user clicks are requests: <see cref="StateChanging"/> fires first and can
/// cancel. Changes from code or bindings apply directly.
/// Three-state (false / null / true): track click goes to the third clicked, label click and
/// Space step along, Left / Right step towards that side.
/// </summary>
public class HueSwitch : ToggleButton
{
    public static readonly RoutedEvent StateChangingEvent = EventManager.RegisterRoutedEvent(
        nameof(StateChanging), RoutingStrategy.Bubble, typeof(HueSwitchChangingEventHandler), typeof(HueSwitch));

    private static readonly bool?[] Order = { false, null, true };

    private FrameworkElement? _track;
    private double? _clickX;

    public HueSwitch()
    {
        SetResourceReference(StyleProperty, "Hue.Switch");
    }

    /// <summary>Raised before a user-initiated change. Set Cancel to keep the current state.</summary>
    public event HueSwitchChangingEventHandler StateChanging
    {
        add => AddHandler(StateChangingEvent, value);
        remove => RemoveHandler(StateChangingEvent, value);
    }

    public override void OnApplyTemplate()
    {
        base.OnApplyTemplate();
        _track = GetTemplateChild("Track") as FrameworkElement;
    }

    protected override void OnMouseLeftButtonUp(MouseButtonEventArgs e)
    {
        // By position, not IsMouseOver: under mouse capture WPF reports IsMouseOver false for
        // the track.
        _clickX = null;
        if (_track is { ActualWidth: > 0, ActualHeight: > 0 } track)
        {
            var p = e.GetPosition(track);
            if (p.X >= 0 && p.X <= track.ActualWidth && p.Y >= 0 && p.Y <= track.ActualHeight)
                _clickX = p.X;
        }
        try
        {
            base.OnMouseLeftButtonUp(e);
        }
        finally
        {
            _clickX = null;
        }
    }

    /// <summary>Replaces WPF's built-in "move to the next state" with a request.</summary>
    protected override void OnToggle()
    {
        if (!IsThreeState)
        {
            Request(IsChecked != true);
            return;
        }

        if (_clickX is { } x && _track is { ActualWidth: > 0 } track)
        {
            var third = track.ActualWidth / 3;
            bool? target = x < third ? false : x > 2 * third ? true : (bool?)null;
            Request(target);
            return;
        }

        Request(Order[(Array.IndexOf(Order, IsChecked) + 1) % Order.Length]);
    }

    protected override void OnKeyDown(KeyEventArgs e)
    {
        if (IsThreeState && e.Key is Key.Left or Key.Right)
        {
            var i = Array.IndexOf(Order, IsChecked) + (e.Key == Key.Right ? 1 : -1);
            if (i >= 0 && i < Order.Length) Request(Order[i]);
            e.Handled = true;
            return;
        }
        base.OnKeyDown(e);
    }

    private void Request(bool? target)
    {
        if (target == IsChecked) return;
        if (!IsThreeState && target is null) return;

        var args = new HueSwitchChangingEventArgs(StateChangingEvent, this, IsChecked, target);
        RaiseEvent(args);

        // SetCurrentValue, so a binding on IsChecked survives and receives the new value.
        if (!args.Cancel) SetCurrentValue(IsCheckedProperty, target);
    }
}

public delegate void HueSwitchChangingEventHandler(object sender, HueSwitchChangingEventArgs e);

public sealed class HueSwitchChangingEventArgs : RoutedEventArgs
{
    internal HueSwitchChangingEventArgs(RoutedEvent routedEvent, object source, bool? from, bool? to)
        : base(routedEvent, source)
    {
        From = from;
        To = to;
    }

    /// <summary>The current state: false (off, -1), null (not set, 0) or true (on, +1).</summary>
    public bool? From { get; }

    /// <summary>The state the user asked for.</summary>
    public bool? To { get; }

    /// <summary>True keeps the current state. The handler may set IsChecked itself later,
    /// e.g. after slow or elevated work succeeds.</summary>
    public bool Cancel { get; set; }

    protected override void InvokeEventHandler(Delegate genericHandler, object genericTarget) =>
        ((HueSwitchChangingEventHandler)genericHandler)(genericTarget, this);
}

/// <summary>
/// Filter pills (Hue.PillToggle): the one rule every filter row follows, and the attached
/// properties the style reads.
/// <list type="bullet">
/// <item>Nothing lit shows everything. Lit chips of one group add up (OR); groups combine (AND).</item>
/// <item>While a chip of its group is lit, an unlit chip is dimmed.</item>
/// <item>Every row starts with none lit. A click toggles one chip and nothing else.</item>
/// <item>Disable a chip only when the whole list has none of its items, never because of
/// what other chips filter, and never while it is lit: a disabled lit chip can't be turned off.</item>
/// </list>
/// Drive <see cref="DimmedProperty"/> from a view model (bind it) or from code-behind
/// (<see cref="Dim"/> after each click). Keys are compared ignoring case.
/// </summary>
public static class HuePill
{
    /// <summary>The chip is dimmed: its group has a lit chip and this one isn't lit.</summary>
    public static readonly DependencyProperty DimmedProperty = DependencyProperty.RegisterAttached(
        "Dimmed", typeof(bool), typeof(HuePill), new FrameworkPropertyMetadata(false));

    public static bool GetDimmed(DependencyObject o) => (bool)o.GetValue(DimmedProperty);
    public static void SetDimmed(DependencyObject o, bool value) => o.SetValue(DimmedProperty, value);

    /// <summary>Optional: the key of the items a chip stands for, for <see cref="Lets(IEnumerable{ToggleButton}, string)"/>.</summary>
    public static readonly DependencyProperty KeyProperty = DependencyProperty.RegisterAttached(
        "Key", typeof(string), typeof(HuePill), new FrameworkPropertyMetadata(null));

    public static string? GetKey(DependencyObject o) => (string?)o.GetValue(KeyProperty);
    public static void SetKey(DependencyObject o, string? value) => o.SetValue(KeyProperty, value);

    /// <summary>
    /// Set by Hue.PillToggle while the chip is dimmed, and inherited by the pill inside, whose
    /// template fades its fill, border and dot. Not for apps to set.
    /// </summary>
    public static readonly DependencyProperty FadedProperty = DependencyProperty.RegisterAttached(
        "Faded", typeof(bool), typeof(HuePill), new FrameworkPropertyMetadata(false, FrameworkPropertyMetadataOptions.Inherits));

    public static bool GetFaded(DependencyObject o) => (bool)o.GetValue(FadedProperty);
    public static void SetFaded(DependencyObject o, bool value) => o.SetValue(FadedProperty, value);

    /// <summary>
    /// Set by Hue.PillToggle while the chip is disabled, and inherited by the pill inside, whose
    /// template drops its colour: neutral shape, grey dot, dim but readable text. Wins over
    /// <see cref="FadedProperty"/>. Not for apps to set.
    /// </summary>
    public static readonly DependencyProperty OffProperty = DependencyProperty.RegisterAttached(
        "Off", typeof(bool), typeof(HuePill), new FrameworkPropertyMetadata(false, FrameworkPropertyMetadataOptions.Inherits));

    public static bool GetOff(DependencyObject o) => (bool)o.GetValue(OffProperty);
    public static void SetOff(DependencyObject o, bool value) => o.SetValue(OffProperty, value);

    /// <summary>
    /// True on a pill whose template fades itself (every Hue.Pill and Hue.Tag style). A pill
    /// without it is dimmed whole by the toggle, to opacity 0.8. An app pill that is BasedOn
    /// Hue.Pill or Hue.Tag but replaces the template sets it back to false.
    /// </summary>
    public static readonly DependencyProperty FadesProperty = DependencyProperty.RegisterAttached(
        "Fades", typeof(bool), typeof(HuePill), new FrameworkPropertyMetadata(false));

    public static bool GetFades(DependencyObject o) => (bool)o.GetValue(FadesProperty);
    public static void SetFades(DependencyObject o, bool value) => o.SetValue(FadesProperty, value);

    /// <summary>Whether a group lets an item with <paramref name="key"/> through (keys compared ignoring case).</summary>
    public static bool Lets(IEnumerable<(string Key, bool Lit)> group, string key)
    {
        bool anyLit = false;
        foreach (var (chipKey, lit) in group)
        {
            if (lit)
            {
                anyLit = true;
                if (string.Equals(chipKey, key, StringComparison.OrdinalIgnoreCase)) return true;
            }
        }
        return !anyLit;
    }

    /// <summary>The same rule for any chip type: <paramref name="isItems"/> says whether a chip stands for the item.</summary>
    public static bool Lets<T>(IEnumerable<T> group, Func<T, bool> isLit, Func<T, bool> isItems)
    {
        bool anyLit = false;
        foreach (var chip in group)
        {
            if (isLit(chip))
            {
                anyLit = true;
                if (isItems(chip)) return true;
            }
        }
        return !anyLit;
    }

    /// <summary>The same rule for toggles that carry <see cref="KeyProperty"/>.</summary>
    public static bool Lets(IEnumerable<ToggleButton> group, string key) =>
        Lets(group, t => t.IsChecked == true, t => string.Equals(GetKey(t), key, StringComparison.OrdinalIgnoreCase));

    /// <summary>Whether a chip is dimmed: not lit while another of its group is.</summary>
    public static bool Dimmed(IEnumerable<bool> groupLit, bool lit) => !lit && groupLit.Any(l => l);

    /// <summary>Sets <see cref="DimmedProperty"/> on every chip of a group, for code-behind.</summary>
    public static void Dim(IEnumerable<ToggleButton> group)
    {
        var chips = group.ToList();
        var lit = chips.Select(t => t.IsChecked == true).ToList();
        foreach (var chip in chips)
            SetDimmed(chip, Dimmed(lit, chip.IsChecked == true));
    }
}

/// <summary>
/// Themed confirmation (MessageBox is drawn light). Cancel takes focus, Enter and Escape, so
/// confirming needs a deliberate click or Tab.
/// </summary>
public static class HueConfirm
{
    /// <summary>Returns true only if the user confirms.</summary>
    /// <param name="confirmText">The action, as a verb: "Allow", "Delete", "Apply".</param>
    /// <param name="destructive">True paints the confirm button as Hue.Button.Danger.</param>
    public static bool Ask(Window? owner, string title, string message, string confirmText, bool destructive = false)
    {
        var frame = new HueDialogFrame(owner, title, message);
        var cancel = frame.AddButton("Cancel", null, HueChoice.Cancel);
        cancel.IsCancel = true;
        cancel.IsDefault = true;
        frame.AddButton(confirmText, destructive ? "Hue.Button.Danger" : "Hue.Button.Primary", HueChoice.Yes);
        return frame.Show(focus: cancel) == HueChoice.Yes;
    }
}

public enum HueChoice { Yes, No, Cancel }

/// <summary>Themed notice and three-way choice. Name buttons by what they do, never Yes / No.</summary>
public static class HueMessage
{
    /// <summary>A notice with a single button. Enter and Escape both close it.</summary>
    public static void Show(Window? owner, string title, string message, string okText = "OK")
    {
        var frame = new HueDialogFrame(owner, title, message);
        var ok = frame.AddButton(okText, "Hue.Button.Primary", HueChoice.Yes);
        ok.IsDefault = true;
        ok.IsCancel = true;
        frame.Show(focus: ok);
    }

    /// <summary>
    /// E.g. Save / Don't save / Cancel; closing the window returns Cancel. Yes is primary and
    /// takes Enter; with <paramref name="destructive"/> it is the danger button and Cancel
    /// takes Enter.
    /// </summary>
    public static HueChoice Choose(Window? owner, string title, string message,
                                   string yesText, string noText, string cancelText = "Cancel",
                                   bool destructive = false)
    {
        var frame = new HueDialogFrame(owner, title, message);
        var cancel = frame.AddButton(cancelText, null, HueChoice.Cancel);
        cancel.IsCancel = true;
        frame.AddButton(noText, null, HueChoice.No);
        var yes = frame.AddButton(yesText, destructive ? "Hue.Button.Danger" : "Hue.Button.Primary", HueChoice.Yes);

        if (destructive) cancel.IsDefault = true;
        else yes.IsDefault = true;

        return frame.Show(focus: destructive ? cancel : yes);
    }
}

/// <summary>The window every kit dialog shares: rim, title band, message, buttons on the right.</summary>
internal sealed class HueDialogFrame
{
    private readonly Window _window;
    private readonly StackPanel _buttons;
    private HueChoice _result = HueChoice.Cancel;

    public HueDialogFrame(Window? owner, string title, string message)
    {
        _window = new Window
        {
            Title = title,
            Owner = owner,
            SizeToContent = SizeToContent.WidthAndHeight,
            ResizeMode = ResizeMode.NoResize,
            ShowInTaskbar = false,
            WindowStartupLocation = owner is null ? WindowStartupLocation.CenterScreen : WindowStartupLocation.CenterOwner,
        };
        _window.SetResourceReference(FrameworkElement.StyleProperty, "Hue.Window");
        HueTitleBar.Attach(_window);

        // The guide's "Dialogs" structure: a 2 px rim in the family colour (drawn here, because
        // Windows 10 ignores frame colours), a Chrome head band with the title, a Raised body
        // one step lighter than the cards behind, buttons bottom right.
        var heading = new TextBlock { Text = title, TextWrapping = TextWrapping.Wrap, Width = ContentWidth };
        heading.SetResourceReference(FrameworkElement.StyleProperty, "Text.Heading");

        var band = new Border { Padding = new Thickness(28, 20, 28, 18), BorderThickness = new Thickness(0, 0, 0, 1), Child = heading };
        band.SetResourceReference(Border.BackgroundProperty, "Brush.Chrome");
        band.SetResourceReference(Border.BorderBrushProperty, "Brush.LineSoft");

        var body = new TextBlock { Text = message, TextWrapping = TextWrapping.Wrap, Width = ContentWidth };
        body.SetResourceReference(FrameworkElement.StyleProperty, "Text.Body");

        _buttons = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            Margin = new Thickness(0, 24, 0, 0),
        };

        var content = new StackPanel { Margin = new Thickness(28, 20, 28, 24) };
        content.Children.Add(body);
        content.Children.Add(_buttons);

        var layout = new DockPanel();
        DockPanel.SetDock(band, Dock.Top);
        layout.Children.Add(band);
        layout.Children.Add(content);

        var rim = new Border { BorderThickness = new Thickness(2), Child = layout };
        rim.SetResourceReference(Border.BackgroundProperty, "Brush.Raised");
        rim.SetResourceReference(Border.BorderBrushProperty, "Brush.AccentEdge");
        _window.Content = rim;
    }

    private const double ContentWidth = 420;

    /// <summary>Adds a button; <paramref name="styleKey"/> null means the default button.</summary>
    public Button AddButton(string text, string? styleKey, HueChoice choice)
    {
        var button = new Button
        {
            Content = text,
            MinWidth = 96,
            Margin = new Thickness(_buttons.Children.Count == 0 ? 0 : 10, 0, 0, 0),
        };
        if (styleKey is not null) button.SetResourceReference(FrameworkElement.StyleProperty, styleKey);
        button.Click += (_, _) =>
        {
            _result = choice;
            // IsCancel already closes the dialog; closing here too would race WPF's close.
            if (!button.IsCancel) _window.DialogResult = true;
        };
        _buttons.Children.Add(button);
        return button;
    }

    public HueChoice Show(Button focus)
    {
        _window.Loaded += (_, _) => focus.Focus();
        _window.ShowDialog();
        return _result;
    }
}

/// <summary>
/// The header's version block. <see cref="Number"/> is Major.Minor.Build from the csproj's
/// &lt;Version&gt;: read from the assembly version, so it never carries the "+commit" suffix
/// the SDK appends to the informational version. <see cref="Sdk"/> is the SDK that built
/// the exe, stamped in by the csproj:
/// <code>&lt;AssemblyMetadata Include="SdkVersion" Value="$(NETCoreSdkVersion)" /&gt;</code>
/// It is null without that line. <see cref="Runtime"/> is the .NET runtime the exe runs on.
/// </summary>
public static class HueVersion
{
    private static readonly Assembly EntryAssembly = Assembly.GetEntryAssembly() ?? Assembly.GetExecutingAssembly();

    /// <summary>"1.31.0".</summary>
    public static string Number { get; } = ReadNumber();

    /// <summary>"version 1.31.0": the block's first line.</summary>
    public static string Text => "version " + Number;

    /// <summary>"10.0.401", or null if the csproj does not stamp it.</summary>
    public static string? Sdk { get; } = EntryAssembly.GetCustomAttributes<AssemblyMetadataAttribute>()
        .FirstOrDefault(a => a.Key == "SdkVersion" && !string.IsNullOrWhiteSpace(a.Value))?.Value;

    /// <summary>"10.0.12".</summary>
    public static string Runtime { get; } = Environment.Version.ToString(3);

    private static string ReadNumber()
    {
        var v = EntryAssembly.GetName().Version;
        return v is null ? "0.0.0" : $"{v.Major}.{v.Minor}.{Math.Max(0, v.Build)}";
    }
}
