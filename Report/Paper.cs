using System.Windows.Media;

namespace RepoLegibility.Report;

/// <summary>
/// The print palette: dark text on white, marks as light backgrounds that survive greyscale
/// printing. Paper isn't the screen, so the dark theme's tokens don't apply here; these are the
/// only colours the app sets in code, and they appear only in the report document.
/// </summary>
internal static class Paper
{
    public static readonly Brush White = Frozen(0xFF, 0xFF, 0xFF);
    public static readonly Brush Ink = Frozen(0x1A, 0x1A, 0x1A);
    public static readonly Brush Muted = Frozen(0x55, 0x5B, 0x66);
    public static readonly Brush Rule = Frozen(0xD0, 0xD5, 0xDD);
    public static readonly Brush CardBack = Frozen(0xF3, 0xF5, 0xF8);
    public static readonly Brush CodeBack = Frozen(0xF6, 0xF7, 0xF9);
    public static readonly Brush Link = Frozen(0x1F, 0x4E, 0xA8);
    public static readonly Brush FocusBack = Frozen(0xFF, 0xF2, 0xB3);

    // Obscured: written so it can't be read. Red, read first.
    public static readonly Brush ObscuredBack = Frozen(0xFC, 0xDE, 0xDE);
    public static readonly Brush ObscuredInk = Frozen(0x9B, 0x12, 0x12);
    public static readonly Brush OpaqueBack = Frozen(0xFD, 0xE4, 0xD3);
    public static readonly Brush OpaqueInk = Frozen(0x8A, 0x3B, 0x00);
    public static readonly Brush PartlyBack = Frozen(0xFE, 0xF0, 0xC0);
    public static readonly Brush PartlyInk = Frozen(0x6E, 0x52, 0x00);
    // Untraced isn't a verdict on the code: neutral slate, neither warning nor pass.
    public static readonly Brush UntracedBack = Frozen(0xE3, 0xE7, 0xEE);
    public static readonly Brush UntracedInk = Frozen(0x34, 0x40, 0x54);
    public static readonly Brush ClearBack = Frozen(0xE6, 0xF4, 0xEA);
    public static readonly Brush ClearInk = Frozen(0x16, 0x65, 0x34);
    public static readonly Brush AdminInk = Frozen(0x8B, 0x10, 0x10);

    public static readonly FontFamily Body = new("Segoe UI");
    public static readonly FontFamily Mono = new("Consolas");

    private static Brush Frozen(byte r, byte g, byte b)
    {
        var brush = new SolidColorBrush(Color.FromRgb(r, g, b));
        brush.Freeze();
        return brush;
    }
}
