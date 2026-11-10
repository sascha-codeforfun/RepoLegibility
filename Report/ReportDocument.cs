using System.Globalization;
using System.Windows;
using System.Windows.Documents;
using System.Windows.Media;
using RepoLegibility.Core;
using RepoLegibility.Pdf;
using DocRun = System.Windows.Documents.Run;

namespace RepoLegibility.Report;

/// <summary>
/// The report as a document for paper and PDF: A4, light, text only. Written for someone who files
/// it as the record that a repo was looked into before it was used: what was scanned (with the
/// zip's hash), what the code does, how clear that is, and room to sign it off.
/// </summary>
internal static class ReportDocument
{
    public static readonly Size PageSize = new(793.7007874015748, 1122.5196850393702); // A4 in DIP

    public static FlowDocument Build(ScanReport r)
    {
        var doc = new FlowDocument
        {
            PageWidth = PageSize.Width,
            PageHeight = PageSize.Height,
            PagePadding = new Thickness(56, 56, 56, 80), // room for the footer
            ColumnWidth = PageSize.Width,
            FontFamily = Paper.Body,
            FontSize = 11.5,
            Foreground = Paper.Ink,
            Background = Paper.White,
            TextAlignment = TextAlignment.Left,
        };

        var counted = r.Counted.ToList();
        var nav = new Nav();

        doc.Blocks.Add(new Paragraph(new DocRun("RepoLegibility report")) { FontSize = 11, Foreground = Paper.Muted, Margin = new Thickness(0) });
        doc.Blocks.Add(new Paragraph(new DocRun(r.RepoName)) { FontSize = 24, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 2, 0, 10) });

        doc.Blocks.Add(Facts(
            ("Zip", $"{r.ZipName} ({AiExport.Size(r.ZipBytes)})"),
            ("SHA-256", r.ZipSha256),
            ("Scanned", $"{r.ScannedAt:yyyy-MM-dd HH:mm} with RepoLegibility {r.ToolVersion}")));

        // The contents, filled in at the end when every section is known. The whole block is one place,
        // so its lines aren't taken for the headings they name.
        var contents = new Section { Tag = new PdfAnchor("contents", "Contents", 1) };
        doc.Blocks.Add(contents);

        // The first page in plain words, for someone who doesn't read code; the detail follows on the next.
        if (r.Overview is { } o)
        {
            var plain = nav.Heading("In plain words");
            plain.BreakPageBefore = true;
            doc.Blocks.Add(plain);
            doc.Blocks.Add(new Paragraph(new DocRun(o.Headline)) { FontSize = 13, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 8) });
            doc.Blocks.Add(Facts(o.Answers.Select(a => (a.Question, a.Answer)).ToArray()));
            if (o.Lines.Count > 0)
            {
                doc.Blocks.Add(nav.Sub("What it reads and changes"));
                doc.Blocks.Add(Facts(o.Lines.Select(l => (
                    l.Area + (l.Reach.Length > 0 ? ", " + l.Reach : "") + (l.Tech.Length > 0 ? $" ({l.Tech})" : ""),
                    string.Join("\n", new[] { l.Changes?.Line, l.Reads?.Line }.Where(x => x is not null)))).ToArray()));
            }
            if (r.Combinations.Count > 0)
            {
                doc.Blocks.Add(nav.Sub("Worth knowing together"));
                doc.Blocks.Add(Note(Combined.DeclaredIsNotSafe));
                foreach (var c in r.Combinations)
                {
                    var p = new Paragraph { Margin = new Thickness(0, 2, 0, 6) };
                    var (back, ink) = c.Declaration.Kind switch
                    {
                        // Declared or mentioned: neutral, never the "clear" green; a README doesn't make anything safe.
                        DeclarationKind.Declared when c.Expected => (Paper.UntracedBack, Paper.UntracedInk),
                        DeclarationKind.Mentioned => (Paper.UntracedBack, Paper.UntracedInk),
                        _ => (Paper.PartlyBack, Paper.PartlyInk)
                    };
                    p.Inlines.Add(Badge(c.Standing, back, ink));
                    p.Inlines.Add(new DocRun("  " + c.Sentence));
                    p.Inlines.Add(new LineBreak());
                    p.Inlines.Add(new DocRun(c.Declaration.Text) { Foreground = Paper.Muted, FontSize = 10 });
                    p.Inlines.Add(new LineBreak());
                    p.Inlines.Add(new DocRun("Before building: " + c.Check) { Foreground = Paper.Muted, FontSize = 10 });
                    if (c.Members.Count > 0)
                    {
                        p.Inlines.Add(new LineBreak());
                        p.Inlines.Add(new DocRun("The findings: ") { Foreground = Paper.Muted, FontSize = 10 });
                        for (int i = 0; i < c.Members.Count; i++)
                        {
                            if (i > 0) p.Inlines.Add(new DocRun(", ") { Foreground = Paper.Muted, FontSize = 10 });
                            p.Inlines.Add(KeyLink(c.Members[i]));
                        }
                    }
                    doc.Blocks.Add(p);
                }
            }
            // What to read before building, by when it runs.
            var checklist = Combined.Checklist(r);
            if (checklist.Count > 0)
            {
                doc.Blocks.Add(nav.Sub("Before building"));
                foreach (var g in checklist)
                {
                    doc.Blocks.Add(Minor(g.Heading));
                    var list = new List { MarkerStyle = TextMarkerStyle.Disc, Margin = new Thickness(0, 0, 0, 4), Padding = new Thickness(18, 0, 0, 0) };
                    foreach (var item in g.Items) list.ListItems.Add(new ListItem(new Paragraph(new DocRun(item)) { Margin = new Thickness(0, 0, 0, 2), FontSize = 10.5 }));
                    doc.Blocks.Add(list);
                }
            }
        }

        // The kinds that occur, in plain words: the glossary for the first page.
        if (r.Overview is not null)
        {
            var kinds = counted.Select(f => f.Kind).Distinct().OrderBy(k => Names.Of(k), StringComparer.Ordinal).ToList();
            if (kinds.Count > 0)
            {
                doc.Blocks.Add(nav.Sub("What the words mean"));
                doc.Blocks.Add(Facts(kinds.Select(k => (Names.Of(k), Names.Explain(k)))
                    .Concat(Enumerable.Reverse(Enum.GetValues<Legibility>()).Select(l => (Names.Of(l), Names.Explain(l)))).ToArray()));
            }
        }

        var about = nav.Heading("About this report");
        about.BreakPageBefore = true;
        doc.Blocks.Add(about);
        doc.Blocks.Add(new Paragraph(new DocRun(
            $"This report lists what the C# source in {r.ZipName} (SHA-256 above) touches: files, the registry, the network, " +
            "programs and credentials, and whether it asks for administrator rights. Each finding has a scope and a legibility: " +
            "Clear, Run time, Untraced, Opaque or Obscured. Obscured and Opaque mark code a person has to read; neither is a verdict. The scan reads the " +
            "source without compiling or running it. It doesn't read NuGet packages, binaries in the repo, or code fetched or " +
            "generated at run time, and some traces stop before the source shows where a value comes from; each says where. " +
            "Findings marked \"not called by the app\" sit in code only the repo's tests call. " +
            "This is a map of what the code involves, not a verdict on whether it is safe."))
        { FontSize = 10, Margin = new Thickness(0, 0, 0, 4) });

        doc.Blocks.Add(nav.Heading("Summary"));
        doc.Blocks.Add(Facts(
            ("Findings", $"{counted.Count} outside tests: {r.Obscured} obscured, {r.Opaque} opaque, {r.Untraced} untraced, {r.PartlyClear} run time, {r.Clear} clear" +
                         (r.Findings.Count > counted.Count ? $"; {r.Findings.Count - counted.Count} in tests" : "")),
            ("By scope", string.Join(" · ", Enum.GetValues<Scope>().Select(s => $"{Names.Of(s)} {counted.Count(f => f.Scope == s)}"))),
            ("Administrator", r.Admin ? "Yes: the app runs elevated or asks for elevation." : "No elevation found."),
            ("Writes", $"{r.Writes} code passages write or delete, to {r.Paths} distinct places"),
            ("Findings (app)", $"{r.AppDensity.ToString("0.0", CultureInfo.CurrentCulture)} per {1000:N0} lines of C# ({r.CodeFindings:N0} in {r.Metrics.AppSloc:N0} lines)"),
            ("Findings (build, CI, config)", $"{r.OtherFindings:N0}, not counted in the density"),
            ("Findings (tests)", r.Metrics.TestSloc == 0 ? "No test code" : $"{r.TestDensity.ToString("0.0", CultureInfo.CurrentCulture)} per {1000:N0} lines ({r.TestFindings:N0} in {r.Metrics.TestSloc:N0} lines)"),
            ("Code", $"{r.Metrics.Sloc:N0} lines of C#, {r.Metrics.CommentLines:N0} comment lines, {r.Metrics.XamlLines:N0} lines of XAML"),
            ("Reading time", $"{AiExport.Hours(r.Metrics.ReviewHours.Low)} to {AiExport.Hours(r.Metrics.ReviewHours.High)} for a careful review (200–400 lines an hour)"),
            ("Black boxes", r.BlackBoxes.Count == 0 ? "None." : $"{r.BlackBoxes.Count} compiled file(s) or archive(s); see Facts."),
            ("Dependencies", $"{r.Packages.Count(p => !p.TestOnly)} NuGet package(s) in shipped code, {r.Packages.Count(p => p.TestOnly)} in tests")));

        doc.Blocks.Add(new Paragraph(new DocRun(
            "Scope is how far a finding reaches: App (its own folder), User (the user's profile, HKCU, the user's credentials), " +
            "Admin (needs administrator rights: machine-wide changes, services, the firewall, elevated starts; a read any user can do is User), Web service (remote endpoints). Legibility is how well the source shows it: " +
            "Clear (what and where are in the source), Run time (the kind of action is known; the target is decided when the " +
            "app runs, by settings, input or the command line), Untraced (the scan stopped before it found where a value comes from; the reasons say " +
            "where), Opaque (the source can't show what happens, by nature: a computed name, loaded code), Obscured (the source holds it, " +
            "but written so it can't be read: encoded, built from character codes or fragments). The scan reads the source and runs nothing."))
        { FontSize = 10, Foreground = Paper.Muted, Margin = new Thickness(0, 6, 0, 4) });

        var obscured = counted.Where(f => f.Legibility == Legibility.Obscured).ToList();
        var opaque = counted.Where(f => f.Legibility == Legibility.Opaque).ToList();
        var untraced = counted.Where(f => f.Legibility == Legibility.Untraced).ToList();
        var partly = counted.Where(f => f.Legibility == Legibility.PartlyClear).ToList();
        var clear = counted.Where(f => f.Legibility == Legibility.Clear).ToList();
        var tests = r.Findings.Where(f => f.Origin == Origin.Tests).ToList();

        if (obscured.Count > 0)
        {
            doc.Blocks.Add(nav.Heading($"Obscured findings ({obscured.Count})"));
            doc.Blocks.Add(Note("Written so the source doesn't show them plainly. Read these first; where the scan worked out the value, it's shown."));
            foreach (var f in obscured) doc.Blocks.Add(Card(f, withCode: true));
        }

        doc.Blocks.Add(nav.Heading($"Opaque findings ({opaque.Count})"));
        if (opaque.Count == 0) doc.Blocks.Add(Note("None."));
        foreach (var f in opaque) doc.Blocks.Add(Card(f, withCode: true));

        doc.Blocks.Add(nav.Heading($"Untraced findings ({untraced.Count})"));
        if (untraced.Count == 0) doc.Blocks.Add(Note("None."));
        else doc.Blocks.Add(Note("The scan didn't reach where a value comes from. Each says where it stopped; the code is shown so a reader can take it from there."));
        foreach (var f in untraced) doc.Blocks.Add(Card(f, withCode: true));

        doc.Blocks.Add(nav.Heading($"Run-time findings ({partly.Count})"));
        if (partly.Count == 0) doc.Blocks.Add(Note("None."));
        foreach (var f in partly) doc.Blocks.Add(Card(f, withCode: false));

        doc.Blocks.Add(nav.Heading($"Clear findings ({clear.Count})"));
        if (clear.Count == 0) doc.Blocks.Add(Note("None."));
        else doc.Blocks.Add(Compact(clear));

        if (tests.Count > 0)
        {
            doc.Blocks.Add(nav.Heading($"In tests ({tests.Count})"));
            doc.Blocks.Add(Note("Test code doesn't ship, but it runs on every machine that runs the tests."));
            doc.Blocks.Add(Compact(tests));
        }

        // The facts in the same four groups as the window, after the same sentence.
        doc.Blocks.Add(nav.Heading("Facts"));
        doc.Blocks.Add(new Paragraph(new DocRun(FactsText.Headline(r))) { FontSize = 12, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 6) });

        doc.Blocks.Add(nav.Sub("How big is it"));
        var size = FactsText.Size(r);
        if (r.Metrics.Sloc > 0) size.Insert(1, ("Lines of C#", FactsText.SplitText(r)));
        doc.Blocks.Add(Facts(size.ToArray()));
        if (r.Metrics.Largest.Count > 0)
            doc.Blocks.Add(Facts(r.Metrics.Largest.Select(l => (l.Path, $"{l.Sloc:N0} lines")).ToArray()));

        doc.Blocks.Add(nav.Sub("How it's built"));
        var projects = r.Projects.Select(p => (p.Path, $"{p.Kind}: {FactsText.ProjectKind(p.Kind)} {string.Join(", ", p.Frameworks)}{(p.Ui.Length > 0 ? ", " + p.Ui : "")}, {p.Sloc:N0} lines")).ToArray();
        doc.Blocks.Add(projects.Length == 0 ? Note("No project files found.") : Facts(projects));
        if (r.Metrics.ByExtension.Count > 0)
            doc.Blocks.Add(Facts(("File types", string.Join(", ", r.Metrics.ByExtension.Take(12).Select(e => $"{e.Extension} {e.Count:N0}")))));

        doc.Blocks.Add(nav.Sub("What comes from outside"));
        doc.Blocks.Add(Note("Code and addresses this repo depends on but doesn't contain. Each is a link you take on with the repo."));

        doc.Blocks.Add(Minor("Dependencies"));
        var deps = r.Packages.Select(p => ($"NuGet {p.Name}", $"{p.Version} in {p.Project}{(p.TestOnly ? " (tests only)" : "")}"))
            .Concat(r.References.Where(x => x.Kind != "Project").Select(x => (x.Kind + " " + x.Name, "in " + x.From)))
            .Concat(r.CiActions.Select(a => ("CI " + a.Uses, a.Pinned ? "pinned to a commit" : "not pinned to a commit")))
            .ToArray();
        doc.Blocks.Add(deps.Length == 0 ? Note("None.") : Facts(deps));

        doc.Blocks.Add(Minor("Black boxes"));
        doc.Blocks.Add(r.BlackBoxes.Count == 0 ? Note("None: no compiled code or archives in the zip.")
            : Facts(r.BlackBoxes.Select(b => (b.Path, $"{b.Kind}, {AiExport.Size(b.Bytes)}, SHA-256 {b.Sha256}")).ToArray()));

        doc.Blocks.Add(Minor("Web addresses named in the code and its configuration"));
        doc.Blocks.Add(r.Endpoints.Count == 0 ? Note("None.")
            : Facts(r.Endpoints.Take(150).Select(e => (e.Display, string.Join(", ", e.Where.Take(2)))).ToArray()));
        if (r.Endpoints.Count > 150) doc.Blocks.Add(Note($"… and {r.Endpoints.Count - 150} more."));

        doc.Blocks.Add(nav.Sub("What the scan covered"));
        doc.Blocks.Add(Facts(FactsText.Coverage(r).ToArray()));
        doc.Blocks.Add(Minor("Not covered by the scan"));
        if (r.NotCovered.Count == 0) doc.Blocks.Add(Note("Nothing reported."));
        else
        {
            var list = new List { MarkerStyle = TextMarkerStyle.Disc, Margin = new Thickness(0, 2, 0, 6), Padding = new Thickness(18, 0, 0, 0) };
            foreach (var n in r.NotCovered) list.ListItems.Add(new ListItem(new Paragraph(new DocRun(n)) { Margin = new Thickness(0, 0, 0, 2) }));
            doc.Blocks.Add(list);
        }

        doc.Blocks.Add(nav.Heading("Review"));
        doc.Blocks.Add(new Paragraph(new DocRun("Reviewed by ______________________________    Date ______________"))
        { Margin = new Thickness(0, 18, 0, 22) });
        doc.Blocks.Add(new Paragraph(new DocRun("Decision and notes"))
        { Foreground = Paper.Muted, Margin = new Thickness(0, 0, 0, 60), BorderBrush = Paper.Rule, BorderThickness = new Thickness(0, 0, 0, 1), Padding = new Thickness(0, 0, 0, 60) });

        FillContents(contents, nav);
        return doc;
    }

    public static string SuggestedName(ScanReport r) =>
        $"{Safe(r.RepoName)}-RepoLegibility-{r.ScannedAt:yyyy-MM-dd}.pdf";

    private static string Safe(string name) =>
        string.Concat(name.Select(c => System.IO.Path.GetInvalidFileNameChars().Contains(c) ? '_' : c));

    // ---- places and links in the PDF ---------------------------------------------------------------

    /// <summary>
    /// Headings that are places in the PDF: a section is a top-level bookmark and a line in the contents,
    /// a sub-heading a bookmark under it. Finding cards and table rows are places too, under their key.
    /// </summary>
    private sealed class Nav
    {
        private int _n;
        public List<(string Id, string Title)> Sections { get; } = new();

        public Paragraph Heading(string text)
        {
            var p = ReportDocument.Heading(text);
            string id = "s" + (++_n).ToString(CultureInfo.InvariantCulture);
            p.Tag = new PdfAnchor(id, text, 1);
            Sections.Add((id, text));
            return p;
        }

        public Paragraph Sub(string text)
        {
            var p = ReportDocument.Sub(text);
            p.Tag = new PdfAnchor("s" + (++_n).ToString(CultureInfo.InvariantCulture), text, 2);
            return p;
        }
    }

    private static void FillContents(Section contents, Nav nav)
    {
        contents.Blocks.Add(new Paragraph(new DocRun("Contents")) { FontSize = 16, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 18, 0, 6) });
        foreach (var (id, title) in nav.Sections)
            contents.Blocks.Add(new Paragraph(Link(title, id)) { Margin = new Thickness(0, 1, 0, 1) });
        contents.Blocks.Add(new Paragraph(new DocRun(
            "In the PDF each line jumps to its section, a finding's key jumps to the finding, and the bookmarks list every section and finding."))
        { FontSize = 10, Foreground = Paper.Muted, Margin = new Thickness(0, 8, 0, 0) });
    }

    /// <summary>A jump to a place in the PDF: plain on screen and paper, a link in the file.</summary>
    private static Hyperlink Link(string text, string id) =>
        new(new DocRun(text)) { NavigateUri = new Uri("#" + id, UriKind.Relative), Foreground = Paper.Link, TextDecorations = null };

    /// <summary>A finding's number and key, linked to its card or its row.</summary>
    private static Inline KeyLink(Finding f)
    {
        var link = Link($"#{f.Id} {f.Key}", f.Key);
        link.FontSize = 10;
        return link;
    }

    private static string Short(string s) => s.Length > 90 ? s[..87] + "…" : s;

    // ---- blocks ----------------------------------------------------------------------------------

    private static Paragraph Heading(string text) =>
        new(new DocRun(text)) { FontSize = 16, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 18, 0, 6), KeepWithNext = true };

    private static Paragraph Sub(string text) =>
        new(new DocRun(text)) { FontSize = 12.5, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 10, 0, 4), KeepWithNext = true };

    private static Paragraph Minor(string text) =>
        new(new DocRun(text)) { FontSize = 11, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 8, 0, 3), KeepWithNext = true };

    private static Paragraph Note(string text) =>
        new(new DocRun(text)) { Foreground = Paper.Muted, Margin = new Thickness(0, 0, 0, 6) };

    /// <summary>Label and value rows.</summary>
    private static Table Facts(params (string Label, string Value)[] rows)
    {
        var table = new Table { CellSpacing = 0, Margin = new Thickness(0, 0, 0, 6) };
        table.Columns.Add(new TableColumn { Width = new GridLength(150) });
        table.Columns.Add(new TableColumn { Width = GridLength.Auto });
        var group = new TableRowGroup();
        foreach (var (label, value) in rows)
        {
            var row = new TableRow();
            row.Cells.Add(new TableCell(new Paragraph(new DocRun(label)) { Foreground = Paper.Muted, Margin = new Thickness(0, 1, 10, 1) }));
            row.Cells.Add(new TableCell(new Paragraph(new DocRun(value)) { Margin = new Thickness(0, 1, 0, 1) }));
            group.Rows.Add(row);
        }
        table.RowGroups.Add(group);
        return table;
    }

    private static (Brush Back, Brush Ink) Mark(Legibility l) => l switch
    {
        Legibility.Obscured => (Paper.ObscuredBack, Paper.ObscuredInk),
        Legibility.Opaque => (Paper.OpaqueBack, Paper.OpaqueInk),
        Legibility.PartlyClear => (Paper.PartlyBack, Paper.PartlyInk),
        Legibility.Untraced => (Paper.UntracedBack, Paper.UntracedInk),
        _ => (Paper.ClearBack, Paper.ClearInk)
    };

    private static Inline Badge(string text, Brush back, Brush ink) =>
        new DocRun(" " + text + " ") { Background = back, Foreground = ink, FontWeight = FontWeights.SemiBold, FontSize = 10 };

    /// <summary>One finding in full: what, where, where it's decided, notes, the trace and (for opaque ones) the code.</summary>
    private static Section Card(Finding f, bool withCode)
    {
        var (back, ink) = Mark(f.Legibility);
        var section = new Section
        {
            Background = Paper.CardBack,
            BorderBrush = Paper.Rule,
            BorderThickness = new Thickness(0, 0, 0, 0),
            Padding = new Thickness(12, 8, 12, 8),
            Margin = new Thickness(0, 0, 0, 8),
        };
        // A stripe in the legibility's colour on the left: readable in greyscale too, and the badge says the word.
        section.BorderBrush = ink;
        section.BorderThickness = new Thickness(3, 0, 0, 0);

        var head = new Paragraph
        {
            Margin = new Thickness(0, 0, 0, 3),
            KeepWithNext = true,
            Tag = new PdfAnchor(f.Key, Short($"#{f.Id} {f.Summary}"), 2, $"#{f.Id} · {f.Key}")
        };
        head.Inlines.Add(new DocRun($"#{f.Id} · {f.Key}  ") { Foreground = Paper.Muted, FontSize = 10 });
        head.Inlines.Add(Badge(Names.Of(f.Legibility), back, ink));
        head.Inlines.Add(new DocRun("  "));
        head.Inlines.Add(new DocRun(Names.Of(f.Scope)) { FontWeight = FontWeights.SemiBold, Foreground = f.Scope == Scope.Admin ? Paper.AdminInk : Paper.Ink, FontSize = 10 });
        head.Inlines.Add(new DocRun("  ·  " + Names.Of(f.Kind) + (f.Origin != Origin.App ? "  ·  " + Names.Of(f.Origin) : "")
            + string.Concat(f.Marks().Select(m => "  ·  " + m))) { FontSize = 10, Foreground = Paper.Muted });
        section.Blocks.Add(head);

        section.Blocks.Add(new Paragraph(new DocRun(f.Summary)) { FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 3) });
        if (f.LooksInside is { } inside)
            section.Blocks.Add(new Paragraph(new DocRun("Looks inside: " + inside)) { Margin = new Thickness(0, 0, 0, 1), FontSize = 10.5 });
        if (f.WhoDecides is { } who)
            section.Blocks.Add(new Paragraph(new DocRun("Who decides: " + who)) { Margin = new Thickness(0, 0, 0, 3), FontSize = 10.5 });

        var where = new Paragraph { Margin = new Thickness(0, 0, 0, 3), FontSize = 10.5 };
        where.Inlines.Add(new DocRun($"{f.File}:{f.Line}") { FontFamily = Paper.Mono });
        if (f.Excerpt?.Member is { } member) where.Inlines.Add(new DocRun("  in " + member) { Foreground = Paper.Muted });
        where.Inlines.Add(new DocRun("   ") );
        where.Inlines.Add(new DocRun(f.Call) { FontFamily = Paper.Mono, Foreground = Paper.Muted });
        section.Blocks.Add(where);

        foreach (var reason in f.Reasons)
            section.Blocks.Add(new Paragraph(new DocRun("Decided: " + reason)) { Margin = new Thickness(0, 0, 0, 1), FontSize = 10.5 });
        foreach (var note in f.Notes)
            section.Blocks.Add(new Paragraph(new DocRun("Note: " + note)) { Margin = new Thickness(0, 0, 0, 1), FontSize = 10.5, Foreground = Paper.Muted });

        if (f.Calls.Count > 0)
        {
            var calls = new Paragraph { Margin = new Thickness(0, 4, 0, 0), FontSize = 9.5 };
            calls.Inlines.Add(new DocRun($"Calls that decide it ({f.Calls.Count + f.CallsNotFollowed})") { Foreground = Paper.Muted });
            foreach (var c in f.Calls.Take(withCode ? 12 : 6))
            {
                var (cb, ci) = Mark(c.Legibility);
                calls.Inlines.Add(new LineBreak());
                calls.Inlines.Add(new DocRun($"{c.File}:{c.Line}  ") { Foreground = Paper.Muted, FontFamily = Paper.Mono });
                calls.Inlines.Add(Badge(Names.Of(c.Legibility), cb, ci));
                calls.Inlines.Add(new DocRun("  " + c.Target + (c.Reason is { Length: > 0 } why ? " · " + why : "")));
            }
            int left = f.Calls.Count - Math.Min(f.Calls.Count, withCode ? 12 : 6) + f.CallsNotFollowed;
            if (left > 0)
            {
                calls.Inlines.Add(new LineBreak());
                calls.Inlines.Add(new DocRun($"… {left} more") { Foreground = Paper.Muted });
            }
            section.Blocks.Add(calls);
        }

        if (f.Trace.Count > 0)
        {
            var trace = new Paragraph { Margin = new Thickness(0, 4, 0, 0), FontSize = 9.5 };
            trace.Inlines.Add(new DocRun("Trace, nearest first") { Foreground = Paper.Muted });
            foreach (var step in f.Trace.Take(withCode ? 8 : 4))
            {
                trace.Inlines.Add(new LineBreak());
                trace.Inlines.Add(new DocRun($"{step.File}:{step.Line}  ") { Foreground = Paper.Muted, FontFamily = Paper.Mono });
                trace.Inlines.Add(new DocRun(step.Code) { FontFamily = Paper.Mono });
            }
            if (f.Trace.Count > (withCode ? 8 : 4))
            {
                trace.Inlines.Add(new LineBreak());
                trace.Inlines.Add(new DocRun($"… {f.Trace.Count - (withCode ? 8 : 4)} more steps") { Foreground = Paper.Muted });
            }
            section.Blocks.Add(trace);
        }

        if (withCode && f.Excerpt is { } x)
            section.Blocks.Add(Code(x, f.File));

        return section;
    }

    /// <summary>The code around a finding. C# and XML are marked for print without colour: keywords and tag names bold, comments grey italic.</summary>
    private static Section Code(Excerpt x, string file)
    {
        var spans = file.EndsWith(".cs", StringComparison.OrdinalIgnoreCase) ? Highlight.Lines(x.Lines)
            : Highlight.IsXml(file) ? Highlight.Xml(x.Lines) : null;
        var box = new Section { Background = Paper.CodeBack, BorderBrush = Paper.Rule, BorderThickness = new Thickness(1), Padding = new Thickness(8, 6, 8, 6), Margin = new Thickness(0, 6, 0, 0) };
        int width = (x.FirstLine + x.Lines.Count).ToString(CultureInfo.InvariantCulture).Length;
        for (int i = 0; i < x.Lines.Count; i++)
        {
            int line = x.FirstLine + i;
            var p = new Paragraph { FontFamily = Paper.Mono, FontSize = 8.5, Margin = new Thickness(0), LineHeight = 11.5 };
            if (line == x.Focus) p.Background = Paper.FocusBack;
            p.Inlines.Add(new DocRun(line.ToString(CultureInfo.InvariantCulture).PadLeft(width) + "  ") { Foreground = Paper.Muted });
            if (spans is null) p.Inlines.Add(new DocRun(x.Lines[i].Replace("\t", "    ")));
            else
                foreach (var span in spans[i])
                    p.Inlines.Add(span.Kind switch
                    {
                        SpanKind.Keyword => new DocRun(span.Text) { FontWeight = FontWeights.Bold },
                        SpanKind.Comment => new DocRun(span.Text) { Foreground = Paper.Muted, FontStyle = FontStyles.Italic },
                        _ => new DocRun(span.Text)
                    });
            box.Blocks.Add(p);
        }
        return box;
    }

    /// <summary>Many findings in one table: legibility, scope, kind, where, target.</summary>
    private static Table Compact(IEnumerable<Finding> findings)
    {
        var table = new Table { CellSpacing = 0, Margin = new Thickness(0, 0, 0, 8), FontSize = 9.5 };
        table.Columns.Add(new TableColumn { Width = new GridLength(34) });
        table.Columns.Add(new TableColumn { Width = new GridLength(84) });
        table.Columns.Add(new TableColumn { Width = new GridLength(96) });
        table.Columns.Add(new TableColumn { Width = new GridLength(1, GridUnitType.Star) });
        var group = new TableRowGroup();

        var header = new TableRow();
        foreach (var h in new[] { "#", "Scope", "Kind", "Where and target" })
            header.Cells.Add(new TableCell(new Paragraph(new DocRun(h)) { Foreground = Paper.Muted, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 6, 3) })
            { BorderBrush = Paper.Rule, BorderThickness = new Thickness(0, 0, 0, 1) });
        group.Rows.Add(header);

        foreach (var f in findings)
        {
            var row = new TableRow();
            var key = Cell(new DocRun("#" + f.Id + " " + f.Key) { Foreground = Paper.Muted });
            key.Blocks.FirstBlock.Tag = new PdfAnchor(f.Key, f.Key, 0, "#" + f.Id + " " + f.Key);
            row.Cells.Add(key);
            row.Cells.Add(Cell(new DocRun(Names.Short(f.Scope)) { Foreground = f.Scope == Scope.Admin ? Paper.AdminInk : Paper.Ink }));
            row.Cells.Add(Cell(new DocRun(Names.Of(f.Kind))));
            var where = new Paragraph { Margin = new Thickness(0, 2, 0, 2) };
            where.Inlines.Add(new DocRun($"{f.File}:{f.Line}") { FontFamily = Paper.Mono });
            where.Inlines.Add(new LineBreak());
            where.Inlines.Add(new DocRun(f.Target) { Foreground = Paper.Muted });
            row.Cells.Add(new TableCell(where) { BorderBrush = Paper.Rule, BorderThickness = new Thickness(0, 0, 0, 1) });
            group.Rows.Add(row);
        }
        table.RowGroups.Add(group);
        return table;
    }

    private static TableCell Cell(Inline content) =>
        new(new Paragraph(content) { Margin = new Thickness(0, 2, 6, 2) }) { BorderBrush = Paper.Rule, BorderThickness = new Thickness(0, 0, 0, 1) };

    /// <summary>The footer line before the page number: app, repo, hash. Plain text, not a format string: a repo name can hold braces.</summary>
    public static string FooterText(ScanReport r) =>
        $"RepoLegibility {r.ToolVersion} · {r.RepoName} · zip SHA-256 {r.ZipSha256[..16]}… · page ";

    /// <summary>A laid-out page with the footer drawn under it: app, repo, hash, page n of m.</summary>
    public static ContainerVisual WithFooter(DocumentPage page, string footer, int index, int count)
    {
        var container = new ContainerVisual();
        container.Children.Add(page.Visual);
        var drawn = new DrawingVisual();
        using (var dc = drawn.RenderOpen())
        {
            var line = footer + (index + 1).ToString(CultureInfo.InvariantCulture) + " of " + count.ToString(CultureInfo.InvariantCulture);
            var text = new FormattedText(line, CultureInfo.InvariantCulture, FlowDirection.LeftToRight,
                new Typeface(Paper.Body, FontStyles.Normal, FontWeights.Normal, FontStretches.Normal), 9, Paper.Muted, 1.0);
            dc.DrawText(text, new Point(56, page.Size.Height - 48));
        }
        FlowDocumentPdf.SetPageFurniture(drawn, true); // the footer repeats the repo name: never a link's or a bookmark's place
        container.Children.Add(drawn);
        return container;
    }
}
