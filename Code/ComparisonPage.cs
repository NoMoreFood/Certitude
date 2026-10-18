//
// Copyright (c) Bryan Berns.
// Licensed under GPLv3. See LICENSE.md.
//

using System;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;

namespace Certitude
{
    internal sealed class ComparisonPage : WorkspacePage
    {
        private readonly ComparisonDocument[] documents = new ComparisonDocument[2];
        private readonly ComparisonSource[] sources = new ComparisonSource[2];
        private readonly TextBlock[] labels = new TextBlock[2];
        private readonly StackPanel header = new StackPanel();
        private readonly DataGrid grid = new DataGrid { SelectionMode = DataGridSelectionMode.Single };
        private readonly CheckBox differences = new CheckBox { Content = "_Differences Only", IsChecked = true,
            VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 12, 4) };
        private readonly CheckBox encoding = new CheckBox { Content = "Show _Encoding", IsChecked = false,
            VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 12, 4) };
        private readonly TextBox search = new TextBox { Width = 220, Margin = new Thickness(0, 0, 8, 4) };
        private readonly TextBlock status = new TextBlock { TextWrapping = TextWrapping.Wrap };
        private readonly TextBox preview = new TextBox { IsReadOnly = true, AcceptsReturn = true,
            TextWrapping = TextWrapping.Wrap, VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            VerticalContentAlignment = VerticalAlignment.Top, Height = 115, Margin = new Thickness(0, 5, 0, 5) };
        private readonly Button cancel, export;
        private ComparisonRow[] rows = Array.Empty<ComparisonRow>();
        private CancellationTokenSource cancellation;

        public ComparisonPage()
        {
            // Keep both source snapshots in this page while the user visits other tools to select another artifact.
            Title = "Comparison";
            var layout = new DockPanel { Margin = new Thickness(8) };
            DockPanel.SetDock(header, Dock.Top);
            layout.Children.Add(header);
            Dialogs.Note(header, "Compare certificates, CSRs, templates and CRLs. Certificate and CSR fields align " +
                "for request-to-issuance checks. " +
                "Comparisons do not validate signatures, trust or effective permissions.");
            var slots = new Grid();
            slots.ColumnDefinitions.Add(new ColumnDefinition());
            slots.ColumnDefinitions.Add(new ColumnDefinition());
            header.Children.Add(slots);
            for (var index = 0; index < 2; index++)
            {
                var side = index;
                var panel = new StackPanel { Margin = new Thickness(side == 0 ? 0 : 8, 0, side == 0 ? 8 : 0, 6) };
                Grid.SetColumn(panel, side);
                slots.Children.Add(panel);
                panel.Children.Add(new TextBlock { Text = side == 0 ? "Basis" : "Comparison", FontSize = 15,
                    FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 5) });
                labels[side] = new TextBlock { TextWrapping = TextWrapping.Wrap, MinHeight = 38,
                    TextTrimming = TextTrimming.CharacterEllipsis, MaxHeight = 70 };
                panel.Children.Add(labels[side]);
                var buttons = new WrapPanel { Margin = new Thickness(0, 5, 0, 0) };
                panel.Children.Add(buttons);
                Dialogs.Button(buttons, side == 0 ? "_File…" : "F_ile…", async () =>
                {
                    var picker = new FilePicker { Filter = ComparisonData.FileFilter, Owner = this };
                    if (await picker.ShowAsync() == true) await Load(side, ComparisonSource.File(picker.FileName));
                });
                Dialogs.Button(buttons, side == 0 ? "Locate On _CA…" : "Locate On C_A…", async () =>
                {
                    var picker = new ComparisonCaPicker { Owner = this };
                    if (await picker.ShowAsync() == true) await Load(side, picker.Source);
                });
                Dialogs.Button(buttons, side == 0 ? "_Template…" : "Tem_plate…", async () =>
                {
                    var picker = new ComparisonTemplatePicker { Owner = this };
                    if (await picker.ShowAsync() == true) await Load(side, picker.Source);
                });
                Dialogs.Button(buttons, "Clear", () =>
                {
                    documents[side] = null;
                    sources[side] = null;
                    Rebuild();
                });
            }

            // Keep filtering and source swapping above a virtualized table of aligned properties.
            var filters = new WrapPanel { Margin = new Thickness(0, 4, 0, 6) };
            header.Children.Add(filters);
            filters.Children.Add(differences);
            filters.Children.Add(encoding);
            var searchLabel = Glyphs.Label("Search", true);
            searchLabel.Target = search;
            filters.Children.Add(searchLabel);
            filters.Children.Add(search);
            Dialogs.Button(filters, "_Swap", () =>
            {
                (documents[0], documents[1]) = (documents[1], documents[0]);
                (sources[0], sources[1]) = (sources[1], sources[0]);
                Rebuild();
            });
            Dialogs.Button(filters, "_Refresh", async () =>
            {
                // Refresh each selected source and stop after a failure or cancellation.
                var selected = sources.ToArray();
                for (var side = 0; side < 2; side++)
                    if (selected[side] != null && !await Load(side, selected[side])) break;
            });
            export = Dialogs.Button(filters, "E_xport CSV…", async () => await Export());
            differences.Click += (sender, e) => Filter();
            encoding.Click += (sender, e) => Filter();
            search.TextChanged += (sender, e) => Filter();

            // Show the complete values of the selected row below compact, resizable table columns.
            var footer = new StackPanel();
            DockPanel.SetDock(footer, Dock.Bottom);
            layout.Children.Add(footer);
            footer.Children.Add(preview);
            var progress = new DockPanel();
            footer.Children.Add(progress);
            cancel = Dialogs.Button(progress, "Ca_ncel", () =>
            {
                cancellation?.Cancel();
                cancel.IsEnabled = false;
                status.Text = "Cancelling After The Current Read Finishes…";
            });
            DockPanel.SetDock(cancel, Dock.Right);
            progress.Children.Add(status);
            Column("Section", nameof(ComparisonRow.Group), 115);
            Column("Property", nameof(ComparisonRow.Property), 200);
            Column("Result", nameof(ComparisonRow.Result), 120);
            Column("Basis", nameof(ComparisonRow.Basis), 1, true);
            Column("Comparison", nameof(ComparisonRow.Compared), 1, true);
            var resultStyle = new Style(typeof(TextBlock), DataGridTextColumn.DefaultElementStyle);
            var changed = new DataTrigger { Binding = new Binding(nameof(ComparisonRow.Different)), Value = true };
            changed.Setters.Add(new Setter(TextBlock.FontWeightProperty, FontWeights.Bold));
            changed.Setters.Add(new Setter(TextBlock.ForegroundProperty, new DynamicResourceExtension("Accent")));
            resultStyle.Triggers.Add(changed);
            ((DataGridTextColumn)grid.Columns[2]).ElementStyle = resultStyle;
            grid.SelectionChanged += (sender, e) => Preview();
            BusyCursor.OnSorting(grid);
            layout.Children.Add(grid);
            Content = layout;
            Dialogs.ScrollHeader(layout, header, 200);
            Closing += (sender, e) =>
            {
                if (cancellation == null) return;
                cancellation.Cancel();
                status.Text = "Waiting For The Current Read To Finish…";
                e.Cancel = true;
            };
            TimeChanged += previousUtc => { grid.Items.Refresh(); Preview(); };
            Loaded += (sender, e) => { grid.Items.Refresh(); Preview(); };
            Rebuild();
        }

        private void Column(string title, string property, double width, bool stretch = false)
        {
            // Keep long encoded values compact while exposing their complete contents in the selected-row preview.
            var style = new Style(typeof(TextBlock), DataGridTextColumn.DefaultElementStyle);
            style.Setters.Add(new Setter(TextBlock.TextTrimmingProperty, TextTrimming.CharacterEllipsis));
            grid.Columns.Add(new DataGridTextColumn { Header = title, Binding = new Binding(property),
                ElementStyle = style,
                Width = new DataGridLength(width, stretch ? DataGridLengthUnitType.Star : DataGridLengthUnitType.Pixel),
                MinWidth = stretch ? 100 : 70 });
        }

        internal async Task<bool> Load(int side, ComparisonSource source)
        {
            if (cancellation != null || source == null) return false;
            using var cursor = BusyCursor.Enter();
            using var operation = new CancellationTokenSource();
            cancellation = operation;
            sources[side] = source;
            documents[side] = null;
            Rebuild();
            header.IsEnabled = false;
            cancel.IsEnabled = true;
            status.Text = "Reading " + source.Label + "…";
            try
            {
                // Publish a complete snapshot only after decoding and any directory or CA calls have finished.
                var document = await Task.Run(() => source.Read(operation.Token), operation.Token);
                operation.Token.ThrowIfCancellationRequested();
                documents[side] = document;
                Rebuild();
                return true;
            }
            catch (OperationCanceledException) { status.Text = "Comparison Read Cancelled."; }
            catch (Exception error) { status.Text = CaAdministration.Error(error); }
            finally
            {
                cancellation = null;
                header.IsEnabled = true;
                cancel.IsEnabled = false;
                labels[side].Text = documents[side] == null ? "Not Loaded · " + source.Label :
                    documents[side].Kind + " · " + documents[side].Source;
                labels[side].ToolTip = labels[side].Text;
            }
            return false;
        }

        private void Rebuild()
        {
            // Clear stale results whenever either slot changes and retain source identity outside the diff.
            rows = ComparisonDocument.Compare(documents[0], documents[1]);
            for (var side = 0; side < 2; side++)
            {
                labels[side].Text = documents[side] == null ? sources[side]?.Label ?? "Choose A Source" :
                    documents[side].Kind + " · " + documents[side].Source;
                labels[side].ToolTip = labels[side].Text;
            }
            Filter();
        }

        private void Filter()
        {
            // Filter display and export together without removing matches from the stored comparison.
            var text = search.Text.Trim();
            var visible = rows.Where(row => (differences.IsChecked != true || row.Different) &&
                (encoding.IsChecked == true || row.Group != "Encoding") && (text.Length == 0 || new[]
                    { row.Group, row.Property, row.Result, row.Basis, row.Compared }.Any(value =>
                        value.IndexOf(text, StringComparison.OrdinalIgnoreCase) >= 0))).ToArray();
            grid.ItemsSource = visible;
            preview.Clear();
            export.IsEnabled = rows.Length > 0;
            cancel.IsEnabled = cancellation != null;
            status.Text = documents.Any(document => document == null) ? "Choose A Basis And A Comparison Source." :
                $"{rows.Count(row => row.Different && row.Group != "Encoding"):N0} Different Fields · " +
                $"{visible.Length:N0} Rows Shown · Snapshots Retained Until Replaced Or Refreshed";
        }

        private void Preview()
        {
            preview.Text = grid.SelectedItem is ComparisonRow row ? row.Group + " · " + row.Property + " · " +
                row.Result + (row.Different && row.First != null && row.Second != null && row.Basis == row.Compared ?
                    "\r\nThe displayed values match, but their underlying encodings differ." : "") +
                "\r\n\r\nBasis:\r\n" + row.Basis + "\r\n\r\nComparison:\r\n" + row.Compared : "";
        }

        private async Task Export()
        {
            // Export the displayed properties with source labels and spreadsheet formula protection.
            var selected = grid.Items.Cast<ComparisonRow>().ToArray();
            var first = documents[0]?.Source;
            var second = documents[1]?.Source;
            var picker = new FilePicker(true) { Owner = this, FileName = "Comparison.csv", Filter = "CSV|*.csv" };
            if (await picker.ShowAsync() != true) return;
            try
            {
                string Csv(string value)
                {
                    value ??= "";
                    if (value.TrimStart().Length > 0 && "=+-@".Contains(value.TrimStart()[0])) value = "'" + value;
                    return "\"" + value.Replace("\"", "\"\"") + "\"";
                }
                var text = new StringBuilder(
                    "Basis Source,Comparison Source,Section,Property,Result,Basis,Comparison\r\n");
                foreach (var row in selected) text.AppendLine(string.Join(",", new[] { first, second, row.Group,
                    row.Property, row.Result, row.Basis, row.Compared }.Select(Csv)));
                await Task.Run(() => CertificateUtilities.WriteAtomic(picker.FileName,
                    Encoding.UTF8.GetPreamble().Concat(Encoding.UTF8.GetBytes(text.ToString())).ToArray()));
                status.Text = $"Exported {selected.Length:N0} Rows.";
            }
            catch (Exception error) { status.Text = CaAdministration.Error(error); }
        }
    }

    internal sealed class ComparisonCaPicker : WorkspacePage
    {
        private readonly StackPanel header = new StackPanel();
        private readonly ComboBox ca = new ComboBox { IsEditable = true, IsTextSearchEnabled = false, Width = 360 };
        private readonly ComboBox kind = new ComboBox { SelectedIndex = 0, Width = 145,
            ItemsSource = new[] { "Certificate", "CSR", "Base CRL", "Delta CRL" },
            Margin = new Thickness(8, 0, 0, 4) };
        private readonly ComboBox field = new ComboBox { ItemsSource = new[] { "Request ID", "Common Name", "Requester",
            "Template", "Serial Number" }, SelectedIndex = 0, Width = 145, Margin = new Thickness(0, 0, 8, 4) };
        private readonly TextBox search = new TextBox { Width = 250, Margin = new Thickness(0, 0, 8, 4) };
        private readonly DataGrid grid = new DataGrid { SelectionMode = DataGridSelectionMode.Single };
        private readonly TextBlock status = new TextBlock { TextWrapping = TextWrapping.Wrap };
        private readonly TextBox index = new TextBox { Text = "0", Width = 70 };
        private readonly WrapPanel recordInputs = new WrapPanel(), crlInputs = new WrapPanel();
        private readonly Button next, use, cancel;
        private QuerySpec query;
        private CertificatePage page;
        private string loadedCa;
        private CancellationTokenSource cancellation;
        public ComparisonSource Source { get; private set; }

        public ComparisonCaPicker()
        {
            // Locate records independently of the main browser's selected CA or filters.
            Title = "Locate Comparison Source On CA";
            var main = (MainWindow)Application.Current.MainWindow;
            ca.ItemsSource = main.ComparisonAuthorities;
            ca.Text = main.ComparisonAuthority;
            var layout = new DockPanel { Margin = new Thickness(8) };
            DockPanel.SetDock(header, Dock.Top);
            layout.Children.Add(header);
            Dialogs.Note(header, "Choose Certificate for the issued result or CSR for the original stored request. " +
                "Search by request ID or certificate metadata; a blank search shows recent records.");
            header.Children.Add(Glyphs.Label("Certificate Authority"));
            var target = new WrapPanel { Margin = new Thickness(0, 0, 0, 8) };
            target.Children.Add(ca);
            target.Children.Add(kind);
            header.Children.Add(target);
            recordInputs.Children.Add(field);
            recordInputs.Children.Add(search);
            Dialogs.Button(recordInputs, "_Search", async () => await Search(false));
            next = Dialogs.Button(recordInputs, "_Older", async () => await Search(true));
            header.Children.Add(recordInputs);
            var indexLabel = Glyphs.Label("CA Certificate Index", true);
            indexLabel.Target = index;
            crlInputs.Children.Add(indexLabel);
            crlInputs.Children.Add(index);
            header.Children.Add(crlInputs);

            // Keep selection and cancellation actions available below the record table.
            var footer = new StackPanel();
            DockPanel.SetDock(footer, Dock.Bottom);
            layout.Children.Add(footer);
            var actions = new WrapPanel();
            footer.Children.Add(actions);
            use = Dialogs.Button(actions, "_Use Selected", Accept);
            cancel = Dialogs.Button(actions, "_Cancel Read", () => cancellation?.Cancel());
            Dialogs.Button(actions, "_Back", Close);
            footer.Children.Add(status);
            foreach (var column in new[] { new[] { "Request ID", "RequestId" }, new[] { "Common Name", "CommonName" },
                new[] { "Requester", "Requester" }, new[] { "Template", "TemplateDisplayName" },
                new[] { "Status", "Status" } })
                grid.Columns.Add(new DataGridTextColumn { Header = column[0], Binding = new Binding(column[1]),
                    Width = new DataGridLength(column[1] == "RequestId" ? 0.6 : 1, DataGridLengthUnitType.Star),
                    MinWidth = 70 });
            BusyCursor.OnSorting(grid);
            layout.Children.Add(grid);
            Content = layout;
            Dialogs.ScrollHeader(layout, header);
            grid.SelectionChanged += (sender, e) => Update();
            grid.MouseDoubleClick += (sender, e) =>
            {
                if (ItemsControl.ContainerFromElement(grid, e.OriginalSource as DependencyObject) is DataGridRow)
                    Accept();
            };
            search.KeyDown += async (sender, e) =>
            {
                if (e.Key != Key.Enter) return;
                e.Handled = true;
                await Search(false);
            };
            ca.AddHandler(TextBox.TextChangedEvent, new TextChangedEventHandler((sender, e) => Clear()));
            search.TextChanged += (sender, e) => Clear();
            field.SelectionChanged += (sender, e) => Clear();
            kind.SelectionChanged += (sender, e) => Clear();
            Closing += (sender, e) => { if (cancellation != null) { cancellation.Cancel(); e.Cancel = true; } };
            Clear();
        }

        private void Clear()
        {
            query = null;
            page = null;
            grid.ItemsSource = null;
            status.Text = "Search The CA Or Select A CRL.";
            Update();
        }

        private void Update()
        {
            var crl = kind.SelectedIndex >= 2;
            crlInputs.Visibility = crl ? Visibility.Visible : Visibility.Collapsed;
            recordInputs.Visibility = grid.Visibility = crl ? Visibility.Collapsed : Visibility.Visible;
            next.IsEnabled = cancellation == null && page?.HasMore == true;
            cancel.IsEnabled = cancellation != null;
            use.IsEnabled = cancellation == null && (crl || grid.SelectedItem is CertificateRow row &&
                (kind.SelectedIndex == 1 || row.NotAfter.HasValue));
        }

        private async Task Search(bool older)
        {
            if (cancellation != null || kind.SelectedIndex >= 2 || older && page?.HasMore != true) return;
            using var cursor = BusyCursor.Enter();
            using var operation = new CancellationTokenSource();
            cancellation = operation;
            header.IsEnabled = false;
            try
            {
                // Apply the same bounded, cancellable metadata queries as the certificate browser.
                var target = ca.Text.Trim();
                int? before = older ? page.Rows.LastOrDefault()?.RequestId : null;
                if (!older) query = new QuerySpec { Disposition = null, PageSize = 200,
                    Field = new[] { "RequestID", "CommonName", "RequesterName", "CertificateTemplate", "SerialNumber" }
                        [field.SelectedIndex], Value = search.Text.Trim(),
                    Match = field.SelectedIndex is 0 or 4 ? SearchMatch.Exact : SearchMatch.Contains };
                query.Validate();
                page = null;
                grid.ItemsSource = null;
                Update();
                status.Text = "Searching " + target + "…";
                var found = await Task.Run(() => new CertificateStore(target).ReadPage(query, before, operation.Token),
                    operation.Token);
                operation.Token.ThrowIfCancellationRequested();
                page = found;
                loadedCa = target;
                grid.ItemsSource = page.Rows;
                status.Text = $"{page.Rows.Count:N0} Records" + (page.HasMore ? " · Older Records Available" : "");
            }
            catch (OperationCanceledException) { status.Text = "Search Cancelled."; }
            catch (Exception error) { status.Text = CaAdministration.Error(error); }
            finally { cancellation = null; header.IsEnabled = true; Update(); }
        }

        private void Accept()
        {
            if (cancellation != null || !use.IsEnabled) return;
            try
            {
                if (kind.SelectedIndex >= 2)
                {
                    new CertificateStore(ca.Text.Trim());
                    if (!int.TryParse(index.Text, NumberStyles.None, CultureInfo.InvariantCulture, out var number))
                        throw new ArgumentException("Enter a CA certificate index of zero or greater.");
                    Source = ComparisonSource.Crl(ca.Text.Trim(), number, kind.SelectedIndex == 3);
                }
                else if (grid.SelectedItem is CertificateRow row)
                    Source = ComparisonSource.Record(loadedCa, row.RequestId, kind.SelectedIndex == 1);
                else return;
                DialogResult = true;
            }
            catch (Exception error) { status.Text = CaAdministration.Error(error); }
        }
    }

    internal sealed class ComparisonTemplatePicker : WorkspacePage
    {
        private readonly StackPanel header = new StackPanel();
        private readonly TextBox target = new TextBox { Width = 360, Margin = new Thickness(0, 0, 8, 4) };
        private readonly TextBox search = new TextBox { Width = 320, Margin = new Thickness(0, 0, 8, 6) };
        private readonly TextBlock status = new TextBlock { TextWrapping = TextWrapping.Wrap };
        private readonly DataGrid grid = new DataGrid { SelectionMode = DataGridSelectionMode.Single };
        private readonly Button use, cancel;
        private OidDirectory directory;
        private ComparisonTemplate[] templates = Array.Empty<ComparisonTemplate>();
        private CancellationTokenSource cancellation;
        public ComparisonSource Source { get; private set; }

        public ComparisonTemplatePicker()
        {
            // Allow each side to select its own forest without changing the application's CA connection.
            Title = "Select Comparison Template";
            var layout = new DockPanel { Margin = new Thickness(8) };
            DockPanel.SetDock(header, Dock.Top);
            layout.Children.Add(header);
            header.Children.Add(Glyphs.Label("Domain / Domain Controller (Blank = Automatic)"));
            var connection = new WrapPanel();
            connection.Children.Add(target);
            Dialogs.Button(connection, "_Load Directory", async () => await Load());
            header.Children.Add(connection);
            header.Children.Add(Glyphs.Label("Search Name / OID"));
            header.Children.Add(search);
            var footer = new StackPanel();
            DockPanel.SetDock(footer, Dock.Bottom);
            layout.Children.Add(footer);
            var actions = new WrapPanel();
            footer.Children.Add(actions);
            use = Dialogs.Button(actions, "_Use Template", Accept);
            cancel = Dialogs.Button(actions, "_Cancel Read", () => cancellation?.Cancel());
            Dialogs.Button(actions, "_Back", Close);
            footer.Children.Add(status);
            foreach (var column in new[] { new[] { "Display Name", "DisplayName" }, new[] { "Internal Name", "Name" },
                new[] { "OID", "Oid" } })
                grid.Columns.Add(new DataGridTextColumn { Header = column[0], Binding = new Binding(column[1]),
                    Width = new DataGridLength(1, DataGridLengthUnitType.Star), MinWidth = 100 });
            layout.Children.Add(grid);
            Content = layout;
            Dialogs.ScrollHeader(layout, header);
            BusyCursor.OnSorting(grid);
            grid.SelectionChanged += (sender, e) => use.IsEnabled = cancellation == null && grid.SelectedItem != null;
            grid.MouseDoubleClick += (sender, e) =>
            {
                if (ItemsControl.ContainerFromElement(grid, e.OriginalSource as DependencyObject) is DataGridRow)
                    Accept();
            };
            search.TextChanged += (sender, e) => Filter();
            target.TextChanged += (sender, e) =>
            {
                directory = null;
                templates = Array.Empty<ComparisonTemplate>();
                Filter();
                status.Text = "Load The Directory To Select A Template.";
            };
            Closing += (sender, e) => { if (cancellation != null) { cancellation.Cancel(); e.Cancel = true; } };
            use.IsEnabled = cancel.IsEnabled = false;
            status.Text = "Load The Directory To Select A Template.";
        }

        private void Filter()
        {
            var text = search.Text.Trim();
            grid.ItemsSource = templates.Where(item => new[] { item.Name, item.DisplayName, item.Oid }
                .Any(value => value.IndexOf(text, StringComparison.OrdinalIgnoreCase) >= 0)).ToArray();
        }

        private async Task Load()
        {
            if (cancellation != null) return;
            using var cursor = BusyCursor.Enter();
            using var operation = new CancellationTokenSource();
            cancellation = operation;
            header.IsEnabled = false;
            use.IsEnabled = false;
            cancel.IsEnabled = true;
            templates = Array.Empty<ComparisonTemplate>();
            Filter();
            status.Text = "Reading Templates…";
            var server = target.Text.Trim();
            try
            {
                var result = await Task.Run(() =>
                {
                    var connected = OidDirectory.Connect(server);
                    return (Directory: connected, Templates: ComparisonData.Templates(connected, operation.Token));
                }, operation.Token);
                operation.Token.ThrowIfCancellationRequested();
                directory = result.Directory;
                templates = result.Templates;
                Filter();
                status.Text = $"{templates.Length:N0} Templates · {directory.Server}";
            }
            catch (OperationCanceledException) { status.Text = "Directory Read Cancelled."; }
            catch (Exception error) { status.Text = CaAdministration.Error(error); }
            finally { cancellation = null; header.IsEnabled = true; cancel.IsEnabled = false; }
        }

        private void Accept()
        {
            if (cancellation != null || directory == null ||
                grid.SelectedItem is not ComparisonTemplate selected) return;
            Source = ComparisonSource.Template(directory.Server, selected.DistinguishedName);
            DialogResult = true;
        }
    }
}
