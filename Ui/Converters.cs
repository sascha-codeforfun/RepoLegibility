using System.Globalization;
using System.Windows;
using System.Windows.Data;
using RepoLegibility.Core;

namespace RepoLegibility.Ui;

/// <summary>
/// Picks one of the theme's own pill and tag styles for a value, so rows use the theme's styles as
/// they are instead of re-colouring a copy of them.
/// </summary>
public sealed class ThemeStyleConverter : IValueConverter
{
    public object? Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var key = value switch
        {
            // Findings that mean more together: the app's own accent, not a verdict.
            "TogetherPill" => "Hue.Pill.Accent",
            "Together" => "Hue.Tag.Accent",
            Legibility.Obscured => "Hue.Pill.Error",
            Legibility.Opaque => "Hue.Pill.Limit",
            Legibility.PartlyClear => "Hue.Pill.Warn",
            // Not a verdict on the code: the scan stopped. Neutral, so it doesn't read as a warning or a pass.
            Legibility.Untraced => "Hue.Pill",
            Legibility.Clear => "Hue.Pill.Ok",
            // Scope as a ladder, mildest first: its own folder green, the user's profile neutral, a web
            // service amber (it leaves the machine), the whole computer red.
            Scope.App => "Hue.Tag.Safe",
            Scope.User => "Hue.Tag",
            Scope.WebService => "Hue.Tag.Caution",
            Scope.Admin => "Hue.Tag.Unsafe",
            // A list group's name.
            "App scope" => "Hue.Tag.Safe",
            "User scope" => "Hue.Tag",
            "Web service scope" => "Hue.Tag.Caution",
            "Admin scope" => "Hue.Tag.Unsafe",
            _ => "Hue.Tag"
        };
        return Application.Current.TryFindResource(key);
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

/// <summary>Visible when the value is false: an "empty" line shown only while there's nothing else.</summary>
/// <summary>A kit icon's resource key ("Icon.File") to its geometry; nothing for an empty key.</summary>
public sealed class IconGeometryConverter : IValueConverter
{
    public object? Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is string { Length: > 0 } key ? Application.Current.TryFindResource(key) as System.Windows.Media.Geometry : null;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

/// <summary>
/// True shows it; false hides it but keeps its room, so a row without a button stands as tall and as
/// wide as one with it, and the rows of a list keep one rhythm.
/// </summary>
public sealed class BoolToHiddenConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is true ? Visibility.Visible : Visibility.Hidden;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

public sealed class InverseBoolToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is true ? Visibility.Collapsed : Visibility.Visible;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}
