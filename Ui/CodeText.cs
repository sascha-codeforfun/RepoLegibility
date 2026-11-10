using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using RepoLegibility.Core;

namespace RepoLegibility.Ui;

/// <summary>
/// Fills a TextBlock with a code line's coloured pieces: ui:CodeText.Spans="{Binding Spans}".
/// Colours are the kit's Brush.Syntax brushes by reference, so they follow the theme and its contrast
/// mode (the guide's "Code in an app"); plain code keeps the line's own colour (Brush.Text).
/// </summary>
public static class CodeText
{
    public static readonly DependencyProperty SpansProperty = DependencyProperty.RegisterAttached(
        "Spans", typeof(IReadOnlyList<CodeSpan>), typeof(CodeText), new PropertyMetadata(null, Changed));

    public static IReadOnlyList<CodeSpan>? GetSpans(DependencyObject d) => (IReadOnlyList<CodeSpan>?)d.GetValue(SpansProperty);

    public static void SetSpans(DependencyObject d, IReadOnlyList<CodeSpan>? value) => d.SetValue(SpansProperty, value);

    private static void Changed(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is not TextBlock block) return;
        block.Inlines.Clear();
        if (e.NewValue is not IReadOnlyList<CodeSpan> spans) return;

        foreach (var span in spans)
        {
            var run = new Run(span.Text);
            string? key = span.Kind switch
            {
                SpanKind.Keyword => "Brush.Syntax.Keyword",
                SpanKind.String => "Brush.Syntax.String",
                SpanKind.Number => "Brush.Syntax.Number",
                SpanKind.Type => "Brush.Syntax.Type",
                SpanKind.Comment => "Brush.Syntax.Comment",
                _ => null
            };
            if (key is not null) run.SetResourceReference(TextElement.ForegroundProperty, key);
            if (span.Kind == SpanKind.Comment) run.FontStyle = FontStyles.Italic;
            block.Inlines.Add(run);
        }
    }
}
