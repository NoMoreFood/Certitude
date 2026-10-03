//
// Copyright (c) Bryan Berns.
// Licensed under GPLv3. See LICENSE.md.
//

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;

namespace Certitude
{
    internal sealed class StatisticsPage : WorkspacePage
    {
        private readonly CertificateStore store;
        private readonly Button refresh;
        private readonly Button cancel;
        private readonly TextBlock status = new TextBlock { TextWrapping = TextWrapping.Wrap };
        private readonly TabControl tabs = new TabControl();
        private readonly List<DataGrid> grids = new List<DataGrid>();
        private readonly TextBlock[] cards = new TextBlock[6];
        private readonly DataGrid states, expiry, templates, requesters, requests, types, months;
        private readonly DataGrid authority, server, storage, files;
        private CancellationTokenSource cancellation;
        private bool initialized;
        private string recordsError;
        private bool IsBusy => cancellation != null;
        private CaStatistics Snapshot { get; set; }

        public StatisticsPage(CertificateStore store)
        {
            // Create a statistics workspace tied to the selected CA connection.
            this.store = store;
            Title = "Statistics";
            var layout = new DockPanel { Margin = new Thickness(4) };
            var header = new StackPanel();
            DockPanel.SetDock(header, Dock.Top);
            layout.Children.Add(header);

            // Provide refresh and cancellation controls and identify the snapshot scope.
            var toolbar = new DockPanel { Margin = new Thickness(0, 0, 0, 5) };
            header.Children.Add(toolbar);
            var buttons = Dialogs.RightActions(toolbar);
            refresh = Dialogs.Button(buttons, "_Refresh", async () => await Refresh());
            cancel = Dialogs.Button(buttons, "_Cancel", Cancel);
            cancel.IsEnabled = false;
            toolbar.Children.Add(new TextBlock { Text = store.Configuration +
                "\nEntire CA · All Pages And Dispositions · Browser Filters Do Not Apply",
                TextWrapping = TextWrapping.Wrap, VerticalAlignment = VerticalAlignment.Center });

            // Create summary cards for the principal request and storage metrics.
            var tiles = new WrapPanel();
            header.Children.Add(tiles);
            var labels = new[] { "Database Records", "Currently Valid", "Expires Within 30 Days",
                "Revoked", "Pending", "Database Files" };
            for (var i = 0; i < cards.Length; i++)
            {
                var tile = new StackPanel { Margin = new Thickness(8, 5, 8, 5) };
                var label = Glyphs.Label(labels[i]);
                label.Margin = new Thickness(0);
                label.Padding = new Thickness(0);
                label.FontSize = 10;
                tile.Children.Add(label);
                cards[i] = new TextBlock { Text = "—", FontSize = 22, FontWeight = FontWeights.SemiBold };
                cards[i].SetResourceReference(TextBlock.ForegroundProperty, "Accent");
                tile.Children.Add(cards[i]);
                var border = new Border { Width = 156, Margin = new Thickness(0, 0, 5, 5), Child = tile };
                border.SetResourceReference(Border.BackgroundProperty, "SurfaceAlt");
                tiles.Children.Add(border);
            }
            // Keep collection status and snapshot limitations visible below the statistics tabs.
            var footer = new StackPanel { Margin = new Thickness(0, 5, 0, 0) };
            DockPanel.SetDock(footer, Dock.Bottom);
            layout.Children.Add(footer);
            footer.Children.Add(status);
            var note = new TextBlock { Text = "Read-Only Snapshot · CA Data May Change During Collection · Time Zone: UTC",
                FontSize = 10, TextWrapping = TextWrapping.Wrap };
            TimeDisplay.Label(note, TextBlock.TextProperty, note.Text);
            note.SetResourceReference(TextBlock.ForegroundProperty, "Muted");
            footer.Children.Add(note);
            layout.Children.Add(tabs);
            Content = layout;

            // Keep table rows readable when the summary cards exceed the available work area.
            Dialogs.ScrollHeader(layout, header, 220, 40);

            // Organize disposition, expiry, template, and requester breakdowns into tabs.
            states = Counts("Disposition");
            expiry = Counts("Issued Certificate Expiry");
            Tab("Overview", Pair(states, expiry), "Disposition totals include every database row. Expiry intervals " +
                "are exclusive, include future-dated issued certificates, and exclude revoked certificates. " +
                "Currently Valid checks dates only; it does not establish trust or deployment.");
            templates = Breakdown("Template Name / OID");
            Tab("Templates", templates, "Largest 100 Template Groups · All Dispositions · Expired And Due Within " +
                "30 Days Are Subsets Of Issued · Names And OIDs Resolve To The Same Template Group");
            requesters = Breakdown("Requester");
            Tab("Requesters", requesters, "Largest 100 Requester Groups · All Dispositions · Expired And Due Within " +
                "30 Days Are Subsets Of Issued");

            // Group request timing, format, and submission history for comparison.
            requests = Details();
            types = Counts("Request Format");
            months = Counts("Submission Month (UTC)");
            TimeDisplay.Label(months.Columns[0], DataGridColumn.HeaderProperty, "Submission Month (UTC)");
            TimeChanged += previousUtc =>
            {
                foreach (var grid in grids) grid.Items.Refresh();
                if (Snapshot != null) months.ItemsSource = Snapshot.Months;
            };
            Tab("Requests", Pair(requests, Pair(types, months, true)), "Submission activity includes imported records. " +
                "Processing time uses resolved minus submitted timestamps where both are present and ordered. " +
                "Imported records and manual approvals affect this average.", 320);

            // Expose server and storage details alongside CA metadata.
            authority = Details();
            Tab("CA", authority, "Properties And Current Signing Certificate Reported By The Connected CA");
            server = Details();
            Tab("Server", server, "Metrics Come From The Selected CA Server Using Your Windows Identity. " +
                "Unavailable Values Usually Indicate Permissions, WMI Connectivity Or Missing Data.");
            storage = Details();
            files = Table();
            Column(files, "File", "Path", 3);
            Column(files, "Type", "Kind", 1);
            Column(files, "Size", "Size", 2);
            Tab("Storage", Pair(storage, files, true), "Logical File Lengths In Configured CA Folders, Without " +
                "Recursing Or Double Counting Shared Folders. Database Size Includes *.edb Files; It Is Not " +
                "Certificate Payload Size Or Reclaimable Space. Folder Totals May Include Unrelated Files.", 320);

            // Start collection once and request cancellation before leaving a busy page.
            Loaded += async (sender, e) =>
            {
                if (initialized) return;
                initialized = true;
                await Refresh();
            };
            Closing += (sender, e) =>
            {
                if (!IsBusy) return;
                Cancel();
                e.Cancel = true;
            };
        }

        private async Task Refresh()
        {
            // Clear the previous snapshot and mark the page as collecting fresh statistics.
            if (IsBusy) return;
            OidNames.Invalidate();
            using var cursor = BusyCursor.Enter();
            refresh.IsEnabled = false;
            cancel.IsEnabled = true;
            Snapshot = null;
            recordsError = null;
            foreach (var grid in grids) grid.ItemsSource = null;
            foreach (var card in cards) { card.Text = "…"; card.ToolTip = null; }
            status.Text = "Reading The Entire CA And Server Metadata…";

            // Collect record aggregates and server metadata concurrently under one cancellation token.
            using (cancellation = new CancellationTokenSource())
            {
                try
                {
                    await Task.WhenAll(LoadRecords(cancellation.Token), LoadServer(cancellation.Token));
                    TimeDisplay.Text(status, () => Snapshot == null ?
                        "Record Statistics Unavailable — " + recordsError :
                        $"{Snapshot.Total:N0} Records · {Snapshot.TemplateCount:N0} Template Groups · " +
                        $"{Snapshot.RequesterCount:N0} Requester Groups · Scan {Snapshot.Elapsed.TotalSeconds:N2}s · " +
                        "As Of " + CaServerStatistics.Date(Snapshot.AsOf) + " · " + store.SearchStatus);
                }
                catch (OperationCanceledException)
                {
                    status.Text = "Collection Cancelled. Completed Sections Remain Visible; Refresh To Collect Again.";
                }
                catch (Exception error) { status.Text = "Statistics Unavailable — " + CaAdministration.Error(error); }
                finally
                {
                    // Restore controls and mark any unfinished summary cards as unavailable.
                    cancellation = null;
                    refresh.IsEnabled = true;
                    cancel.IsEnabled = false;
                    foreach (var card in cards) if (card.Text == "…") card.Text = "Unavailable";
                }
            }
        }

        private async Task LoadRecords(CancellationToken token)
        {
            try
            {
                // Report scan progress while collecting request aggregates off the UI thread.
                var progress = new Progress<long>(count =>
                {
                    if (IsBusy && Snapshot == null && !token.IsCancellationRequested)
                        status.Text = $"Analysed {count:N0} Records…";
                });
                var value = await Task.Run(() => store.ReadStatistics(token,
                    count => ((IProgress<long>)progress).Report(count)), token);
                token.ThrowIfCancellationRequested();

                // Publish summary cards and disposition counts only after the scan completes.
                Snapshot = value;
                cards[0].Text = value.Total.ToString("N0");
                cards[1].Text = value.Valid.ToString("N0");
                cards[2].Text = (value.Expiry[0] + value.Expiry[1]).ToString("N0");
                cards[3].Text = value.Count(21).ToString("N0");
                cards[4].Text = value.Count(9).ToString("N0");
                states.ItemsSource = value.Dispositions.OrderByDescending(pair => pair.Value).Select(pair =>
                    new StatisticsGroup { Name = Dialogs.Caption(CertificateRow.State(pair.Key)), Count = pair.Value,
                        Percent = value.Total == 0 ? 0 : 100.0 * pair.Value / value.Total }).ToArray();

                // Build exclusive expiry buckets and calculate their share of issued certificates.
                var expiryNames = new[] { "Expired", "Within 7 Days", ">7 To 30 Days", ">30 To 60 Days",
                    ">60 To 90 Days", "Beyond 90 Days", "No Expiry Recorded" };
                var expiryCounts = new[] { value.Expired }.Concat(value.Expiry).Concat(new[] {
                    value.Count(20) - value.Expired - value.Expiry.Sum() }).ToArray();
                expiry.ItemsSource = expiryNames.Select((name, i) => new StatisticsGroup { Name = name,
                    Count = expiryCounts[i], Percent = value.Count(20) == 0 ? 0 :
                        100.0 * expiryCounts[i] / value.Count(20) }).ToArray();

                // Bind grouped results and prepare detailed request activity metrics.
                templates.ItemsSource = value.Templates;
                requesters.ItemsSource = value.Requesters;
                types.ItemsSource = value.Types;
                months.ItemsSource = value.Months;
                var details = new List<DetailValue>();
                void Add(string name, object text) => CaServerStatistics.Add(details, name, text);

                // Describe request volume, submission bounds, and the pending backlog.
                Add("Request ID Range", value.FirstId.HasValue ?
                    $"{value.FirstId:N0} – {value.LastId:N0}" : "No Records");
                Add("Submitted Within 24 Hours / 7 Days / 30 Days",
                    string.Join(" / ", value.Recent.Select(count => count.ToString("N0"))));
                Add("First Submission", value.FirstSubmission);
                Add("Latest Submission", value.LastSubmission);
                Add("Submission Date Not Recorded", value.MissingSubmission.ToString("N0"));
                Add("Oldest Pending Submission", value.OldestPending);

                // Add resolution timing, certificate lifetime, and revocation-reason totals.
                Add("Average / Longest Resolution", value.TimedResolutions == 0 ? "Not Recorded" :
                    $"{value.ResolutionSeconds / value.TimedResolutions:N2}s / {value.LongestResolutionSeconds:N2}s");
                Add("Records With Resolution Timing", value.TimedResolutions.ToString("N0"));
                Add("Issued, Not Yet Valid", value.Future.ToString("N0"));
                Add("Issued, Incomplete Validity Dates", value.MissingValidity.ToString("N0"));
                Add("Average Certificate Lifetime", value.DatedCertificates == 0 ? "Not Recorded" :
                    $"{value.ValidityDays / value.DatedCertificates:N1} Days / " +
                    $"{value.DatedCertificates:N0} Issued Or Revoked Certificates");
                foreach (var reason in value.Reasons) Add("Revoked — " + reason.Name, reason.Count.ToString("N0"));
                requests.ItemsSource = details;
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception error) { recordsError = CaAdministration.Error(error); }
        }

        private async Task LoadServer(CancellationToken token)
        {
            // Publish server and storage results after their independent lookup completes.
            var value = await Task.Run(() => store.ReadServerStatistics(token), token);
            token.ThrowIfCancellationRequested();
            authority.ItemsSource = value.Authority;
            server.ItemsSource = value.Server;
            storage.ItemsSource = value.Storage;
            files.ItemsSource = value.Files.OrderByDescending(file => file.Bytes).ToArray();

            // Show a compact database-size card with full size details in its tooltip.
            cards[5].Text = !value.DatabaseBytes.HasValue ? "Unavailable" : value.DatabaseBytes >= 1073741824 ?
                $"{value.DatabaseBytes / 1073741824.0:N2} GiB" : $"{value.DatabaseBytes / 1048576.0:N1} MiB";
            cards[5].ToolTip = value.DatabaseBytes.HasValue ? CaServerStatistics.Size(value.DatabaseBytes.Value) :
                "See Storage For Availability Details.";
        }

        private void Cancel()
        {
            // Signal cancellation and explain that the current native call must return first.
            cancellation?.Cancel();
            cancel.IsEnabled = false;
            status.Text = "Cancelling After The Current CA Or Server Call Returns…";
        }

        private DataGrid Table()
        {
            // Track variable-height tables so each snapshot refresh can clear them together.
            var grid = new DataGrid { RowHeight = double.NaN, ColumnHeaderHeight = double.NaN,
                CanUserResizeRows = false, Margin = new Thickness(2), MinRowHeight = 24 };
            grids.Add(grid);
            return grid;
        }

        private static void Column(DataGrid grid, string title, string field, double width, string format = null)
        {
            // Use wrapping cells and headers to keep long metric values readable.
            var text = new Style(typeof(TextBlock));
            text.Setters.Add(new Setter(TextBlock.TextWrappingProperty, TextWrapping.Wrap));
            text.Setters.Add(new Setter(FrameworkElement.MarginProperty, new Thickness(0, 3, 0, 3)));
            grid.Columns.Add(new DataGridTextColumn { Header = title,
                Binding = new Binding(field) { StringFormat = format },
                Width = new DataGridLength(width, DataGridLengthUnitType.Star), MinWidth = 45,
                ElementStyle = text,
                HeaderStyle = (Style)Application.Current.FindResource("DetailsColumnHeaderStyle") });
        }

        private DataGrid Details()
        {
            // Create a consistent two-column metric and value table.
            var grid = Table();
            Column(grid, "Metric", "Name", 2);
            Column(grid, "Value", "Value", 3);
            return grid;
        }

        private DataGrid Counts(string title)
        {
            // Create a count table with both absolute totals and percentages.
            var grid = Table();
            Column(grid, title, "Name", 3);
            Column(grid, "Records", "Count", 1, "{0:N0}");
            Column(grid, "Share", "Percent", 1, "{0:N1}%");
            return grid;
        }

        private DataGrid Breakdown(string title)
        {
            // Show issued, revoked, expired, and upcoming-expiry counts for each group.
            var grid = Table();
            Column(grid, title, "Name", 3);
            Column(grid, "Records", "Count", 1, "{0:N0}");
            Column(grid, "Issued", "Issued", 1, "{0:N0}");
            Column(grid, "Revoked", "Revoked", 1, "{0:N0}");
            Column(grid, "Expired", "Expired", 1, "{0:N0}");
            Column(grid, "Due In 30 Days", "DueSoon", 1, "{0:N0}");
            return grid;
        }

        private static Grid Pair(UIElement first, UIElement second, bool vertical = false)
        {
            // Arrange related tables with equal space in the chosen orientation.
            var grid = new Grid();
            if (vertical)
            {
                grid.RowDefinitions.Add(new RowDefinition());
                grid.RowDefinitions.Add(new RowDefinition());
                Grid.SetRow(second, 1);
            }
            else
            {
                grid.ColumnDefinitions.Add(new ColumnDefinition());
                grid.ColumnDefinitions.Add(new ColumnDefinition());
                Grid.SetColumn(second, 1);
            }
            grid.Children.Add(first);
            grid.Children.Add(second);
            return grid;
        }

        private void Tab(string title, FrameworkElement content, string note, double minimumHeight = 160)
        {
            // Attach explanatory text to a statistics tab without covering its content.
            var panel = new DockPanel();
            var description = new TextBlock { Text = note, TextWrapping = TextWrapping.Wrap,
                FontSize = 10, Margin = new Thickness(5) };
            description.SetResourceReference(TextBlock.ForegroundProperty, "Muted");
            DockPanel.SetDock(description, Dock.Bottom);
            panel.Children.Add(description);

            // Scroll compact views without shrinking table rows or removing their virtualization bounds.
            var scroll = new ScrollViewer { Content = content, VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled };
            content.Height = minimumHeight;
            scroll.ScrollChanged += (sender, e) =>
            {
                if (e.OriginalSource == scroll && e.ViewportHeightChange != 0)
                    content.Height = Math.Max(minimumHeight,
                        e.ViewportHeight - content.Margin.Top - content.Margin.Bottom);
            };
            panel.Children.Add(scroll);
            tabs.Items.Add(new TabItem { Header = title, Content = panel });
        }
    }
}
