//
// Copyright (c) Bryan Berns.
// Licensed under GPLv3. See LICENSE.md.
//

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Threading;

namespace Certitude
{
    public partial class MainWindow : Window
    {
        private readonly List<CertificateRow> cursors = new List<CertificateRow> { null };
        private readonly DispatcherTimer filterTimer = new DispatcherTimer
            { Interval = TimeSpan.FromMilliseconds(400) };
        private readonly SemaphoreSlim queryGate = new SemaphoreSlim(1, 1);
        private CertificateStore store;
        private CertificatePage page;
        private QuerySpec query;
        private string sortField = nameof(CertificateRow.RequestId);
        private ListSortDirection sortDirection = ListSortDirection.Descending;
        private CertificateRow[] sortedRows;
        private string cachedSortField;
        private ListSortDirection cachedSortDirection;
        private int cachedUnavailableCount;
        private CancellationTokenSource cancellation;
        private CancellationTokenSource queryCancellation;
        private int queryLoads;
        private bool filtersDirty;
        private int pageIndex;
        private bool busy;
        private bool discovering;
        private bool restoringView;
        private string[] configurations = Array.Empty<string>();
        private readonly List<WorkspacePage> workspace = new List<WorkspacePage>();

        public MainWindow()
        {
            // Initialize version and row actions before sizing the browser for the available screen.
            InitializeComponent();
            VersionText.Text = "Version " + typeof(App).Assembly.GetName().Version.ToString(3);
            BuildContextMenu();
            UpdateContextMenu();

            // Keep the initial window within the current desktop work area.
            var bounds = SystemParameters.WorkArea;
            MinWidth = Math.Min(MinWidth, bounds.Width);
            MinHeight = Math.Min(MinHeight, bounds.Height);
            Width = Math.Min(Width, bounds.Width);
            Height = Math.Min(Height, bounds.Height);

            // Debounce filter edits and preselect the local CA when one is installed.
            filterTimer.Tick += (sender, e) => RefreshClick(sender, new RoutedEventArgs());
            try { ConfigurationBox.Text = CertificateStore.LocalConfiguration(); }
            catch (Exception error) { Record(CaAdministration.Error(error)); }
            UpdateAuthorities(Array.Empty<string>());
        }

        private async void WindowLoaded(object sender, RoutedEventArgs e)
        {
            // Discover available authorities before connecting to the preselected local CA.
            await DiscoverAuthorities();
            if (ConfigurationBox.Text.Length > 0) await Connect();
        }

        private async void ConnectClick(object sender, RoutedEventArgs e) => await Connect();

        private async Task Connect()
        {
            // Connect only after active work and workspace navigation allow a target change.
            if (busy || discovering || queryLoads > 0 || !ReturnToBrowser()) return;
            try
            {
                // Create the selected single-CA or combined connection and update its identity display.
                filterTimer.Stop();
                var configuration = ConfigurationBox.Text.Trim();
                store = configuration.Equals(CaDirectory.AllAuthorities, StringComparison.OrdinalIgnoreCase) ?
                    new AllCertificateStore(configurations.Select(value => new CertificateStore(value))) :
                    new CertificateStore(configuration);
                TargetText.Text = store.IsAllAuthorities ? $"All CAs · {configurations.Length:N0} authorities" :
                    store.Configuration;
                TargetText.ToolTip = store.IsAllAuthorities ? string.Join(Environment.NewLine, configurations) :
                    store.Configuration;
                Title = "Certitude — " + store.Configuration;

                // Reset CA-name sorting when switching back to a single authority.
                if (!store.IsAllAuthorities && sortField == nameof(CertificateRow.Configuration))
                {
                    sortField = nameof(CertificateRow.RequestId);
                    sortDirection = ListSortDirection.Descending;
                }
                // Discard the previous query, rows, and page cursors before the first lookup.
                page = null;
                query = null;
                sortedRows = null;
                Certificates.ItemsSource = null;
                EmptyText.Visibility = Visibility.Collapsed;
                cursors.Clear();
                cursors.Add(null);
                pageIndex = 0;
                filtersDirty = true;
                UpdateControls();

                // Remember successful single-CA connections in the authority selector.
                if (await LoadPage(ReadQuery(), null, 0, true) && !store.IsAllAuthorities)
                    UpdateAuthorities(new[] { store.Configuration });
            }
            catch (Exception error) { ShowError(error); }
        }

        private QuerySpec ReadQuery()
        {
            // Capture and validate browser controls as a single query specification.
            var tag = Convert.ToString(((ListBoxItem)Views.SelectedItem).Tag);
            var spec = new QuerySpec
            {
                Disposition = tag.Length == 0 ? null : (int?)int.Parse(tag),
                Field = Convert.ToString(((ComboBoxItem)SearchField.SelectedItem).Tag),
                Value = SearchBox.Text.Trim(),
                Match = (SearchMatch)MatchMode.SelectedIndex,
                ExpiresFrom = ReadDate(ExpiresFrom), ExpiresBefore = ReadDate(ExpiresBefore),
                PageSize = int.Parse(Convert.ToString(((ComboBoxItem)PageSize.SelectedItem).Content))
            };
            spec.Validate();
            return spec;
        }

        private static DateTime? ReadDate(TextBox picker)
        {
            // Interpret an entered expiry date as a UTC day boundary.
            if (string.IsNullOrWhiteSpace(picker.Text)) return null;
            if (!DateTime.TryParse(picker.Text, CultureInfo.CurrentCulture, DateTimeStyles.None, out var date))
                throw new ArgumentException("Enter a valid expiry date.");
            return DateTime.SpecifyKind(date.Date, DateTimeKind.Utc);
        }

        private async Task<bool> LoadPage(QuerySpec spec, CertificateRow before, int targetPage, bool reset)
        {
            // Cancel the previous query and decide whether its sorted snapshot can be reused.
            using var cursor = BusyCursor.Enter();
            queryCancellation?.Cancel();
            var field = sortField;
            var direction = sortDirection;
            var rows = spec.SameFilter(query) &&
                cachedUnavailableCount == ((store as AllCertificateStore)?.UnavailableCount ?? 0) ? sortedRows : null;
            var cached = rows != null && field == cachedSortField && direction == cachedSortDirection;
            var native = rows == null && field == nameof(CertificateRow.RequestId) &&
                direction == ListSortDirection.Descending;
            using (var request = new CancellationTokenSource())
            {
                // Track the new load and describe whether it will page, search, or sort all matches.
                queryCancellation = request;
                queryLoads++;
                UpdateControls();
                StatusText.Text = !native ? "Sorting all matching CA records…" : spec.UsesClientSearch ?
                    "Searching matching CA records…" : "Loading certificate metadata…";
                SearchHint.Text = spec.UsesClientSearch ?
                    "Searching the full matching view. Exact searches on one field are faster on large CAs." :
                    "Loading results for the current filters…";
                try
                {
                    // Serialize CA reads so a cancelled query releases its resources before the next starts.
                    var watch = Stopwatch.StartNew();
                    var source = store;
                    var token = request.Token;
                    await queryGate.WaitAsync(token);
                    CertificatePage result;
                    try
                    {
                        result = await Task.Run(() =>
                        {
                            // Use native paging or sort the complete matching set before slicing the requested page.
                            if (native) return source.ReadBrowserPage(spec, before, token);
                            if (!cached) rows = CertificateStore.SortRows(rows ??
                                source.ReadRows(spec, null, token, false), field, direction, token);
                            var offset = checked(targetPage * spec.PageSize);
                            var sortedPage = new CertificatePage { HasMore = rows.Length - offset > spec.PageSize };
                            for (var i = offset; i < Math.Min(rows.Length, offset + spec.PageSize); i++)
                                sortedPage.Rows.Add(rows[i]);
                            return sortedPage;
                        }, token);
                    }
                    finally { queryGate.Release(); }

                    // Publish cache metadata only after the completed query survives cancellation.
                    token.ThrowIfCancellationRequested();
                    sortedRows = rows;
                    cachedSortField = field;
                    cachedSortDirection = direction;
                    cachedUnavailableCount = (source as AllCertificateStore)?.UnavailableCount ?? 0;

                    // Update cursor history for a reset, forward step, or revisited page.
                    if (reset)
                    {
                        cursors.Clear();
                        cursors.Add(null);
                    }
                    else if (targetPage >= cursors.Count) cursors.Add(before);
                    else cursors[targetPage] = before;

                    // Replace the visible rows and sort indicators together after the lookup completes.
                    pageIndex = targetPage;
                    page = result;
                    query = spec;
                    filtersDirty = false;
                    Certificates.Items.SortDescriptions.Clear();
                    Certificates.ItemsSource = page.Rows;
                    foreach (var column in Certificates.Columns)
                        column.SortDirection = column.SortMemberPath == field ? direction : (ListSortDirection?)null;

                    // Show the applied view, empty state, and scope of the completed search.
                    ViewTitle.Text = spec.Disposition.HasValue ?
                        CertificateRow.State(spec.Disposition.Value) +
                        (spec.Disposition == 20 || spec.Disposition == 21 ? " Certificates" : " Requests") : "All Records";
                    EmptyText.Text = "No records match these filters.";
                    EmptyText.Visibility = page.Rows.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
                    SearchHint.Text = "Search And Sorting Cover All Matching Records · " + source.SearchStatus;
                    SearchHint.ToolTip = SearchHint.Text;

                    // Report lookup duration and whether more matching records remain.
                    Record($"{page.Rows.Count:N0} records loaded in {watch.Elapsed.TotalSeconds:N2}s. " +
                        (rows != null ? $"{rows.Length:N0} matching records sorted." :
                        page.HasMore ? "More records available." : "End of results."));
                    return true;
                }
                catch (OperationCanceledException) { }
                catch (Exception error)
                {
                    // Ignore superseded failures and surface errors from the current query.
                    if (request.IsCancellationRequested) return false;
                    SearchHint.Text = CaAdministration.Error(error);
                    SearchHint.ToolTip = SearchHint.Text;
                    Record(SearchHint.Text);
                }
                finally
                {
                    // Clear only this load state and restore controls after all outstanding loads settle.
                    if (ReferenceEquals(queryCancellation, request)) queryCancellation = null;
                    queryLoads--;
                    UpdateControls();
                }
            }
            return false;
        }

        private async void RefreshClick(object sender, RoutedEventArgs e)
        {
            // Invalidate cached results and rerun the applied filters from the first page.
            filterTimer.Stop();
            if (busy || store == null) return;
            if (!ReferenceEquals(sender, filterTimer)) OidNames.Invalidate();
            sortedRows = null;
            filtersDirty = true;
            queryCancellation?.Cancel();
            UpdateControls();
            try { await LoadPage(ReadQuery(), null, 0, true); }
            catch (ArgumentException error) { SearchHint.Text = error.Message; }
        }

        private void FilterChanged(object sender, RoutedEventArgs e)
        {
            // Reject edits during protected work and restore a view change if navigation is blocked.
            if (!IsLoaded || busy || store == null || restoringView) return;
            if (ReferenceEquals(sender, Views) && !ReturnToBrowser())
            {
                restoringView = true;
                try
                {
                    Views.SelectedItem = ((SelectionChangedEventArgs)e).RemovedItems.Cast<object>().FirstOrDefault();
                }
                finally { restoringView = false; }
                return;
            }
            // Cancel stale lookups before scheduling a fresh query for changed filters.
            sortedRows = null;
            filtersDirty = true;
            queryCancellation?.Cancel();
            filterTimer.Stop();

            // Clear the list immediately when changing certificate or request views.
            if (ReferenceEquals(sender, Views))
            {
                page = null;
                query = null;
                pageIndex = 0;
                cursors.Clear();
                cursors.Add(null);
                Certificates.ItemsSource = null;
                ViewTitle.Text = Convert.ToString(((ListBoxItem)Views.SelectedItem).Content);
                EmptyText.Visibility = Visibility.Collapsed;
            }
            // Debounce the lookup and prevent actions against results from the previous filters.
            filterTimer.Start();
            SearchHint.Text = "Filters changed; updating results…";
            UpdateControls();
        }

        private void ClearClick(object sender, RoutedEventArgs e)
        {
            // Clear search and expiry criteria before refreshing the current view.
            SearchBox.Clear();
            ExpiresFrom.Text = ExpiresBefore.Text = "";
            RefreshClick(sender, e);
        }

        private void ExpiryPresetClick(object sender, RoutedEventArgs e)
        {
            // Translate an expiry preset into UTC bounds on issued certificates.
            if (!IsLoaded || !(ExpiryPresets.SelectedItem is ComboBoxItem item) ||
                !int.TryParse(Convert.ToString(item.Tag), out var days)) return;
            Views.SelectedIndex = 0;
            var today = DateTime.UtcNow.Date;
            ExpiresFrom.Text = days > 0 ? today.ToString("yyyy-MM-dd") : "";
            ExpiresBefore.Text = days >= 0 ? today.AddDays(days).ToString("yyyy-MM-dd") : "";
            ExpiryPresets.SelectedIndex = 0;
            RefreshClick(sender, e);
        }

        private async void NextClick(object sender, RoutedEventArgs e)
        {
            // Advance only from a completed page that has more matching records.
            if (busy || queryLoads > 0 || filtersDirty || page == null || !page.HasMore) return;
            await LoadPage(query, page.Rows.Last(), pageIndex + 1, false);
        }

        private async void PreviousClick(object sender, RoutedEventArgs e)
        {
            // Reuse the previous page cursor only while the current filters are still applied.
            if (busy || queryLoads > 0 || filtersDirty || pageIndex == 0) return;
            await LoadPage(query, cursors[pageIndex - 1], pageIndex - 1, false);
        }

        private async void GridSorting(object sender, DataGridSortingEventArgs e)
        {
            // Replace page-local grid sorting with a query-wide sort from the first page.
            e.Handled = true;
            if (busy || store == null) return;
            filterTimer.Stop();
            queryCancellation?.Cancel();
            sortDirection = sortField == e.Column.SortMemberPath && sortDirection == ListSortDirection.Ascending ?
                ListSortDirection.Descending : ListSortDirection.Ascending;
            sortField = e.Column.SortMemberPath;
            filtersDirty = true;
            UpdateControls();
            try { await LoadPage(ReadQuery(), null, 0, true); }
            catch (ArgumentException error) { SearchHint.Text = error.Message; }
        }

        private void SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (IsLoaded) UpdateControls();
        }

        private void UpdateControls()
        {
            // Gate actions and navigation using connection, query, and selection state.
            var working = busy || queryLoads > 0;
            Certificates.CanUserSortColumns = !busy && store != null;
            ConnectionPanel.IsEnabled = !working && !discovering;
            Views.IsEnabled = FilterPanel.IsEnabled = store != null && !busy;
            ActionsPanel.IsEnabled = !working && !filtersDirty && Certificates.SelectedItems.Count > 0;
            ExportButton.IsEnabled = !working && !filtersDirty && query != null;
            StatisticsButton.IsEnabled = AdministrationButton.IsEnabled = ToolsButton.IsEnabled =
                !working && store != null && !store.IsAllAuthorities;
            AuthorityColumn.Visibility = store?.IsAllAuthorities == true ? Visibility.Visible : Visibility.Collapsed;
            PreviousButton.IsEnabled = !working && !filtersDirty && pageIndex > 0;
            NextButton.IsEnabled = !working && !filtersDirty && page != null && page.HasMore;
            CancelButton.IsEnabled = working || filterTimer.IsEnabled;
            Progress.Visibility = working ? Visibility.Visible : Visibility.Collapsed;

            // Show current paging and selection counts or the pending-load state.
            PageText.Text = page == null ?
                (queryLoads > 0 || filterTimer.IsEnabled ? "Loading Records…" : "No Records Loaded") :
                $"Page {pageIndex + 1:N0} · {page.Rows.Count:N0} records · " +
                (sortedRows == null ? "" : $"{sortedRows.Length:N0} matching · ") +
                $"{Certificates.SelectedItems.Count:N0} selected";

            // Summarize unavailable authorities once query work has settled.
            if (!working)
            {
                var all = store as AllCertificateStore;
                AuthorityNoticeText.Text = all?.UnavailableMessage ?? "";
                AuthorityNoticeText.ToolTip = all?.UnavailableDetails;
                AuthorityNotice.Visibility = AuthorityNoticeText.Text.Length == 0 ?
                    Visibility.Collapsed : Visibility.Visible;
                if (all != null) TargetText.Text = $"All CAs · {all.AuthorityCount:N0} Authorities" +
                    (all.UnavailableCount == 0 ? "" : $" · {all.UnavailableCount:N0} Unavailable");
            }
            UpdateContextMenu();
        }

        private async Task Run(string message, Func<CancellationToken, Task> operation)
        {
            // Serialize cancellable browser operations and pause pending filter refreshes.
            if (busy || queryLoads > 0) return;
            using var cursor = BusyCursor.Enter();
            filterTimer.Stop();
            busy = true;
            using (cancellation = new CancellationTokenSource())
            {
                // Report progress or partial cancellation while the operation owns the browser.
                UpdateControls();
                StatusText.Text = message;
                try { await operation(cancellation.Token); }
                catch (OperationCanceledException)
                {
                    Record("Operation cancelled. Completed CA changes remain applied.");
                }
                catch (Exception error) { ShowError(error); }
                finally
                {
                    // Restore browser interaction after the guarded operation finishes.
                    busy = false;
                    cancellation = null;
                    UpdateControls();
                }
            }
        }

        private void CancelClick(object sender, RoutedEventArgs e)
        {
            // Cancel delayed searches and active operations without implying rollback of completed changes.
            filterTimer.Stop();
            queryCancellation?.Cancel();
            cancellation?.Cancel();
            SearchHint.Text = "Search cancelled. Refresh or change the filters to continue.";
            StatusText.Text = "Cancelling after the current CA call returns…";
            CancelButton.IsEnabled = false;
        }

        private void Record(string message)
        {
            StatusText.Text = message.Replace("\r", "").Split('\n')[0];
        }

        private void ShowError(Exception error)
        {
            // Normalize an operation failure for the main status line.
            var message = CaAdministration.Error(error);
            Record(message);
        }

        private void BuildContextMenu()
        {
            // Group selected-certificate details, export, validation, and native viewer actions.
            var menu = Dialogs.RowMenu(Certificates);
            Dialogs.MenuItem(menu, "_Open Details", Glyphs.Document, "Open",
                () => OpenClick(this, new RoutedEventArgs()), "Enter");
            Dialogs.MenuItem(menu, "_Export Certificate…", Glyphs.Save, "Export",
                async () => await SelectedCertificate(false));
            Dialogs.MenuItem(menu, "Certificate / CRL Chec_k", Glyphs.Check, "Validate",
                async () => await SelectedCertificate(true));
            Dialogs.MenuItem(menu, "Open In _Windows Certificate Viewer", Glyphs.Certificate, "Windows",
                async () => await SelectedCertificate(false, true));

            // Provide copy commands for request identities and certificate serial numbers.
            menu.Items.Add(new Separator());
            Dialogs.MenuItem(menu, "_Copy Request IDs", Glyphs.Copy, "Copy IDs", () => Dialogs.CopyText(
                string.Join(Environment.NewLine, Certificates.SelectedItems.Cast<CertificateRow>()
                    .Select(row => row.RequestId.ToString()))));
            Dialogs.MenuItem(menu, "Copy _Serial Numbers", Glyphs.Copy, "Copy serials", () => Dialogs.CopyText(
                string.Join(Environment.NewLine, Certificates.SelectedItems.Cast<CertificateRow>()
                    .Select(row => row.SerialNumber))));

            // Expose request disposition and attribute changes from the row menu.
            menu.Items.Add(new Separator());
            foreach (var action in new[]
            {
                new[] { "_Issue / Resubmit", "Issue", Glyphs.Check },
                new[] { "_Deny Request", "Deny", Glyphs.Cancel },
                new[] { "_Revoke Certificate…", "Revoke", Glyphs.Block },
                new[] { "Release Certificate _Hold", "Release hold", Glyphs.Refresh },
                new[] { "Set Request _Attributes…", "Set attributes", Glyphs.Edit }
            })
                Dialogs.MenuItem(menu, action[0], action[2], action[1],
                    () => ActionClick(new MenuItem { Tag = action[1] }, new RoutedEventArgs()));

            // Separate database deletion from selection and refresh commands.
            menu.Items.Add(new Separator());
            Dialogs.MenuItem(menu, "Delete From Data_base…", Glyphs.Delete, "Delete",
                () => ActionClick(new MenuItem { Tag = "Delete" }, new RoutedEventArgs()), "Delete");
            menu.Items.Add(new Separator());
            Dialogs.MenuItem(menu, "Select This _Page", Glyphs.SelectAll,
                "Select page", Certificates.SelectAll, "Ctrl+A");
            Dialogs.MenuItem(menu, "Re_fresh", Glyphs.Refresh, "Refresh",
                () => RefreshClick(this, new RoutedEventArgs()), "F5");
            menu.Opened += (sender, e) => UpdateContextMenu();
        }

        private void UpdateContextMenu()
        {
            // Apply the same readiness rules to row menus and More Actions.
            var selected = Certificates.SelectedItems.Cast<CertificateRow>().ToArray();
            var ready = !busy && queryLoads == 0 && !filtersDirty && store != null && workspace.Count == 0;
            var any = ready && selected.Length > 0;
            var view = Convert.ToString((Views.SelectedItem as ListBoxItem)?.Tag);
            foreach (var item in Certificates.ContextMenu.Items.OfType<MenuItem>().Cast<FrameworkElement>()
                .Concat(MoreActions.Items.OfType<ComboBoxItem>()))
            {
                // Enable each action only when every selected record supports it.
                switch ((string)item.Tag)
                {
                    case "Open": item.IsEnabled = any && selected.Length == 1; break;
                    case "Windows":
                    case "Export":
                    case "Validate":
                        item.IsEnabled = any && selected.Length == 1 && selected[0].NotAfter.HasValue; break;
                    case "Copy IDs": item.IsEnabled = any; break;
                    case "Copy serials":
                        item.IsEnabled = any && selected.All(row => !string.IsNullOrEmpty(row.SerialNumber)); break;
                    case "Issue":
                        item.IsEnabled = any && selected.All(row => row.Disposition == 9 || row.Disposition == 31); break;
                    case "Deny":
                    case "Set attributes": item.IsEnabled = any && selected.All(row => row.Disposition == 9); break;
                    case "Extension":
                        item.IsEnabled = any && selected.Length == 1 && selected[0].Disposition == 9; break;
                    case "Archived key":
                        item.IsEnabled = any && selected.Length == 1 && selected[0].Disposition == 20; break;
                    case "Revoke": item.IsEnabled = any && selected.All(row => row.Disposition == 20); break;
                    case "Release hold":
                        item.IsEnabled = any && selected.All(row => row.Disposition == 21 && row.RevocationReason == 6);
                        break;
                    case "Delete": item.IsEnabled = any; break;
                    case "Select page": item.IsEnabled = ready && Certificates.Items.Count > 0; break;
                    case "Refresh":
                        item.IsEnabled = !busy && queryLoads == 0 && store != null && workspace.Count == 0; break;
                }
            }
            // Determine which operations can apply to the selected certificate or request view.
            bool Applicable(FrameworkElement item)
            {
                if (view.Length == 0) return true;
                switch ((string)item.Tag)
                {
                    case "Windows":
                    case "Export":
                    case "Validate":
                    case "Copy serials": return view == "20" || view == "21";
                    case "Issue": return view == "9" || view == "31";
                    case "Deny":
                    case "Set attributes":
                    case "Extension": return view == "9";
                    case "Archived key":
                    case "Revoke": return view == "20";
                    case "Release hold": return view == "21";
                    default: return true;
                }
            }
            // Hide irrelevant actions in both menus and remove empty context-menu separators.
            Dialogs.FilterMenu(Certificates.ContextMenu, Applicable);
            foreach (var item in MoreActions.Items.OfType<ComboBoxItem>())
            {
                var visible = Applicable(item);
                item.Visibility = visible ? Visibility.Visible : Visibility.Collapsed;
                if (!visible) item.IsEnabled = false;
            }
        }

        private async Task SelectedCertificate(bool validate, bool windows = false)
        {
            // Require one current row before retrieving its certificate from the owning CA.
            if (busy || queryLoads > 0 || filtersDirty || store == null ||
                Certificates.SelectedItems.Count != 1 || !(Certificates.SelectedItem is CertificateRow row)) return;
            await Run("Loading certificate…", async token =>
            {
                // Load complete certificate data before opening validation, viewing, or export.
                var source = store.ForRow(row);
                var detail = await Task.Run(() => source.ReadDetails(row.RequestId, token), token);
                token.ThrowIfCancellationRequested();
                if (detail.Certificate == null) throw new InvalidOperationException("This request has no certificate.");
                if (windows) Dialogs.WindowsCertificate(this, detail.Certificate);
                else if (validate)
                    new ValidationWindow(detail.Certificate, "Request " + row.RequestId + " — " + source.Configuration,
                        detail.Oids) { Owner = this }.Show();
                else await Dialogs.ExportCertificate(this, detail.Certificate, row.RequestId + ".cer");
            });
        }

        private async void ActionClick(object sender, RoutedEventArgs e)
        {
            // Capture the selected records and requested action before collecting operation options.
            if (busy || queryLoads > 0 || filtersDirty || store == null) return;
            var selected = Certificates.SelectedItems.Cast<CertificateRow>().ToArray();
            if (selected.Length == 0) return;
            var source = store;
            var action = Convert.ToString(((FrameworkElement)sender).Tag);
            var reason = 0;
            DateTime? effective = null;
            var attributes = "";
            try
            {
                // Collect revocation reason and effective time only for a revocation action.
                if (action == "Revoke")
                {
                    var revoke = new RevokeDialog { Owner = this };
                    if (await revoke.ShowAsync() != true) return;
                    reason = revoke.Reason;
                    effective = revoke.Effective;
                }
                // Collect replacement attributes only for pending-request attribute updates.
                if (action == "Set attributes")
                {
                    attributes = await Dialogs.Prompt(this, "Request attributes",
                        "One Name:Value pair per line. These values update the selected pending requests.", "", true);
                    if (attributes == null) return;
                }
                // Describe the requested change, including database deletion consequences.
                var detail = action == "Delete" ?
                    "Permanently delete only the selected CA database records, including their attributes, " +
                    "extensions and any archived private keys. This does not revoke certificates or remove " +
                    "copies from Windows certificate stores. Deleting revoked records can remove their entries " +
                    "from future CRLs.\r\n\r\nSelected: " + string.Join(", ", selected.GroupBy(row => row.Status)
                        .Select(group => group.Count() + " " + group.Key)) :
                    action == "Revoke" ? $"Reason: {reason}. Effective: {effective?.ToString("u") ?? "immediately"}." :
                    action == "Set attributes" ? attributes : "";

                // Group confirmation targets by CA so duplicate request IDs remain unambiguous.
                var title = action == "Delete" ? "Delete From Database" : action;
                var targets = string.Join("\r\n\r\n", selected.GroupBy(source.ForRow).Select(group =>
                    "CA: " + group.Key.Configuration + $"\r\n{group.Count():N0} selected record(s)\r\nRequest IDs: " +
                    string.Join(", ", group.Take(20).Select(row => row.RequestId)) +
                    (group.Count() > 20 ? ", …" : "")));
                if (!await Dialogs.Confirm(this, "Confirm " + title,
                    $"{title}: {selected.Length:N0} selected record(s)\r\n\r\n" +
                    targets + "\r\n\r\n" + detail)) return;

                // Apply the confirmed changes with selection-wide progress and an operation report.
                await Run(action + "…", async token =>
                {
                    var progress = new Progress<int>(count =>
                        StatusText.Text = $"{action}: {count:N0}/{selected.Length:N0}");
                    var report = await Task.Run(() => source.Apply(selected,
                        action, reason, effective, attributes, token,
                        count => ((IProgress<int>)progress).Report(count)));
                    Record(report);
                    Dialogs.Report(this, "Operation results", report);
                });

                // Refresh the original connection after changes and discard its stale sorted snapshot.
                if (ReferenceEquals(store, source))
                {
                    sortedRows = null;
                    filtersDirty = true;
                    await LoadPage(query, null, 0, true);
                }
            }
            catch (Exception error) { ShowError(error); }
        }

        private async void OpenClick(object sender, RoutedEventArgs e)
        {
            // Load the selected request details through its originating CA connection.
            if (busy || queryLoads > 0 || filtersDirty || !(Certificates.SelectedItem is CertificateRow row)) return;
            await Run("Loading request details…", async token =>
            {
                var source = store.ForRow(row);
                var detail = await Task.Run(() => source.ReadDetails(row.RequestId, token), token);
                token.ThrowIfCancellationRequested();
                new DetailsWindow(row.RequestId, detail) { Owner = this }.Show();
                Record("Loaded details for request " + row.RequestId + " on " + source.Configuration + ".");
            });
        }

        private void GridDoubleClick(object sender, MouseButtonEventArgs e)
        {
            // Open request details only when the double-click lands on a data row.
            if (ItemsControl.ContainerFromElement(Certificates, e.OriginalSource as DependencyObject) is DataGridRow)
                OpenClick(sender, e);
        }

        private async void ExtensionClick(object sender, RoutedEventArgs e)
        {
            // Ignore extension actions while results are stale or another operation is active.
            if (busy || queryLoads > 0 || filtersDirty || store == null ||
                !(Certificates.SelectedItem is CertificateRow row)) return;
            try
            {
                // Require one pending request and collect its replacement extension data.
                if (Certificates.SelectedItems.Count != 1 || row.Disposition != 9)
                    throw new InvalidOperationException("Select one pending request.");
                var configuration = store.ForRow(row).Configuration;
                var form = new FormDialog("Set certificate extension", new[]
                {
                    "Extension OID", "Flags (0 = normal, 1 = critical, 2 = disabled, 3 = both)", "DER value (base64)"
                }, new[] { "", "0", "" }) { Owner = this };
                if (await form.ShowAsync() != true) return;

                // Validate the extension identifier, flags, and binary encoding before confirmation.
                var oid = form.Values[0].Trim();
                if (!System.Text.RegularExpressions.Regex.IsMatch(oid, @"^[0-2](\.\d+)+$"))
                    throw new ArgumentException("Enter a numeric extension OID.");
                var flags = int.Parse(form.Values[1]);
                if (flags < 0 || flags > 3) throw new ArgumentException("Flags must be between 0 and 3.");
                var bytes = Convert.FromBase64String(form.Values[2]);

                // Confirm the exact request extension change and apply it in the background.
                if (!await Dialogs.Confirm(this, "Set extension " + oid, configuration, new[] { row.RequestId },
                    "Flags: " + flags + "\r\nDER (base64): " + form.Values[2])) return;
                await Run("Setting extension…", async token =>
                {
                    await Task.Run(() => CaAdministration.SetExtension(
                        configuration, row.RequestId, oid, flags, bytes));
                    Record("Extension updated for request " + row.RequestId + ".");
                });
            }
            catch (Exception error) { ShowError(error); }
        }

        private async void ArchivedKeyClick(object sender, RoutedEventArgs e)
        {
            // Resolve the selected request CA and choose a recovery-blob output file.
            if (busy || queryLoads > 0 || filtersDirty || store == null ||
                !(Certificates.SelectedItem is CertificateRow row)) return;
            var configuration = store.ForRow(row).Configuration;
            var save = new FilePicker(true) { FileName = row.RequestId + "-archived-key.p7b", Filter = "Recovery Blob|*.p7b" };
            if (await save.ShowAsync() != true) return;
            await Run("Retrieving encrypted archived key…", async token =>
            {
                // Retrieve the encrypted archived key without attempting to decrypt it.
                await Task.Run(() =>
                {
                    var encoded = CaAdministration.Use(configuration,
                        admin => admin.GetArchivedKey(configuration, row.RequestId, 1));
                    File.WriteAllBytes(save.FileName, Convert.FromBase64String(encoded));
                });
                Record("Saved the encrypted recovery blob. " +
                    "A key recovery agent is required to recover the private key.");
            });
        }

        private async void ExportClick(object sender, RoutedEventArgs e)
        {
            // Choose an output file before exporting the entire applied query.
            if (busy || queryLoads > 0 || filtersDirty || query == null) return;
            var save = new FilePicker(true) { FileName = "certificates.csv", Filter = "CSV|*.csv" };
            if (await save.ShowAsync() != true) return;
            await Run("Exporting all records matching the applied query…", async token =>
            {
                // Stream all matching records to CSV while reporting export progress.
                var progress = new Progress<long>(count => StatusText.Text = $"Exported {count:N0} records…");
                var count = await Task.Run(() => store.Export(query, save.FileName, token,
                    value => ((IProgress<long>)progress).Report(value)), token);
                Record($"Exported {count:N0} records to {save.FileName}.");
            });
        }

        private void AdministrationClick(object sender, RoutedEventArgs e)
        {
            // Open administration only for an idle single-CA connection.
            if (busy || queryLoads > 0 || store == null || store.IsAllAuthorities) return;
            Navigate(new AdministrationWindow(store.Configuration, Record, store.LoadedOids));
        }

        private void ToolsClick(object sender, RoutedEventArgs e)
        {
            // Open maintenance tools only for an idle single-CA connection.
            if (busy || queryLoads > 0 || store == null || store.IsAllAuthorities) return;
            Navigate(new ToolWindow(store.Configuration, Record));
        }

        private void ValidationClick(object sender, RoutedEventArgs e) =>
            Navigate(new ValidationWindow(names: store?.LoadedOids));

        private void CertificateToolsClick(object sender, RoutedEventArgs e) =>
            Navigate(new CertificateToolsWindow(store?.IsAllAuthorities == true ? "" : store?.Configuration ?? "",
                Record, store?.LoadedOids));

        private void OidManagerClick(object sender, RoutedEventArgs e) => Navigate(new OidManagerPage(Record));

        private void PublishedClick(object sender, RoutedEventArgs e) => Navigate(new PublishedPage(Record));

        private void StatisticsClick(object sender, RoutedEventArgs e)
        {
            // Open statistics only for an idle single-CA connection.
            if (busy || queryLoads > 0 || store == null || store.IsAllAuthorities) return;
            Navigate(new StatisticsPage(store));
        }

        private void ThemeClick(object sender, RoutedEventArgs e)
        {
            // Toggle the theme and report any failure to persist the preference.
            try { App.ApplyTheme(!App.IsDark); }
            catch (Exception error) { Record("Theme changed; preference could not be saved: " + error.Message); }
        }

        private void WindowKeyDown(object sender, KeyEventArgs e)
        {
            // Give workspace pages priority over browser keyboard shortcuts.
            if (workspace.Count > 0)
            {
                if (e.Key == Key.Escape) { workspace.Last().Close(); e.Handled = true; }
                return;
            }
            // Route search, refresh, and selected-row shortcuts to browser actions.
            if (e.Key == Key.F5) { RefreshClick(sender, e); e.Handled = true; }
            if (e.Key == Key.Enter && SearchBox.IsKeyboardFocusWithin) { RefreshClick(sender, e); e.Handled = true; }
            if (Certificates.IsKeyboardFocusWithin && Keyboard.Modifiers == ModifierKeys.None)
            {
                if (e.Key == Key.Enter && Certificates.SelectedItems.Count == 1)
                { OpenClick(sender, e); e.Handled = true; }
                if (e.Key == Key.Delete)
                { ActionClick(new MenuItem { Tag = "Delete" }, e); e.Handled = true; }
            }
            // Use Escape for cancellation and Ctrl+F to focus browser search.
            if (e.Key == Key.Escape && (busy || queryLoads > 0 || filterTimer.IsEnabled))
            {
                CancelClick(sender, e);
                e.Handled = true;
            }
            if (e.Key == Key.F && Keyboard.Modifiers == ModifierKeys.Control) { SearchBox.Focus(); e.Handled = true; }
        }

        private void WindowClosing(object sender, CancelEventArgs e)
        {
            // Defer window closure until workspace and CA operations can stop safely.
            filterTimer.Stop();
            if (workspace.Any(page => !page.CanClose())) { e.Cancel = true; return; }
            if (!busy && queryLoads == 0) return;
            queryCancellation?.Cancel();
            cancellation?.Cancel();
            e.Cancel = true;
            StatusText.Text = "Waiting for the current operation to stop. Close the window again when it finishes.";
        }

        internal void Notify(string text) => Record(text);

        internal void ShowPage(WorkspacePage page)
        {
            // Push a new workspace page only once and reveal it above the browser.
            if (workspace.Contains(page)) return;
            workspace.Add(page);
            UpdateWorkspace();
        }

        internal void ClosePage(WorkspacePage page, bool? result)
        {
            // Complete only the top workspace page when navigating back.
            if (workspace.LastOrDefault() != page) return;
            workspace.RemoveAt(workspace.Count - 1);
            UpdateWorkspace();
            page.Complete(result);
        }

        private void UpdateWorkspace()
        {
            // Switch the main content and header between the browser and the top workspace page.
            var page = workspace.LastOrDefault();
            BrowserPanel.Visibility = page == null ? Visibility.Visible : Visibility.Collapsed;
            WorkspaceHeader.Visibility = WorkspaceContent.Visibility =
                page == null ? Visibility.Collapsed : Visibility.Visible;
            WorkspaceContent.Content = page;
            WorkspaceTitle.Text = page?.Title ?? "";
        }

        private bool ReturnToBrowser()
        {
            // Close the workspace stack only after every page permits navigation.
            if (workspace.Any(page => !page.CanClose())) return false;
            var previous = workspace.ToArray();
            workspace.Clear();
            UpdateWorkspace();
            foreach (var page in previous) page.Complete(null);
            return true;
        }

        private void Navigate(WorkspacePage page)
        {
            // Return to the browser before opening a new top-level tool page.
            if (busy || !ReturnToBrowser()) return;
            ShowPage(page);
        }

        private void BackClick(object sender, RoutedEventArgs e) => workspace.LastOrDefault()?.Close();

        private void MoreActionClick(object sender, SelectionChangedEventArgs e)
        {
            // Reset the action selector and dispatch only visible, enabled choices.
            if (!IsLoaded || !(MoreActions.SelectedItem is ComboBoxItem item)) return;
            var action = Convert.ToString(item.Tag);
            if (string.IsNullOrEmpty(action)) return;
            var enabled = item.IsEnabled && item.Visibility == Visibility.Visible;
            MoreActions.SelectedIndex = 0;
            if (!enabled) return;
            if (action == "Extension") ExtensionClick(sender, e);
            else if (action == "Archived key") ArchivedKeyClick(sender, e);
            else ActionClick(new Button { Tag = action }, e);
        }

        private async void DiscoverClick(object sender, RoutedEventArgs e) => await DiscoverAuthorities();

        private void UpdateAuthorities(IEnumerable<string> discovered)
        {
            // Merge discovered CA names while preserving the currently typed connection target.
            var current = ConfigurationBox.Text;
            configurations = CaDirectory.Configurations(discovered.Concat(configurations));
            ConfigurationBox.ItemsSource = new[] { CaDirectory.AllAuthorities }.Concat(configurations).ToArray();
            ConfigurationBox.Text = current;
        }

        private async Task DiscoverAuthorities()
        {
            // Prevent overlapping discovery and show busy feedback while reading the forest.
            if (discovering) return;
            using var cursor = BusyCursor.Enter();
            discovering = true;
            DiscoverButton.IsEnabled = false;
            UpdateControls();
            try
            {
                // Merge directory discovery results into the CA selector.
                var authorities = await Task.Run(() => CaDirectory.Discover());
                UpdateAuthorities(authorities);
            }
            catch (Exception error) { Record("CA discovery: " + CaAdministration.Error(error)); }
            finally { discovering = false; DiscoverButton.IsEnabled = true; UpdateControls(); }
        }
    }
}
