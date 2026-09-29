using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using System.Windows.Media;

namespace Certitude
{
    public partial class MainWindow
    {
        private BrowserWorkspace savedWorkspace = new BrowserWorkspace();
        private bool workspaceWritable = true;
        private bool autoAuthorityColumn = true;
        private int? expiryDays;
        private List<BrowserColumn> defaultColumns;

        private void InitializeWorkspace()
        {
            // Preserve the initial column defaults and leave unreadable settings untouched.
            defaultColumns = CaptureColumns();
            try { savedWorkspace = BrowserWorkspace.Load(BrowserWorkspace.DefaultPath); }
            catch (Exception error)
            {
                workspaceWritable = false;
                WorkspaceWarning("Workspace settings could not be loaded; the original file will not be changed. " +
                    CaAdministration.Error(error));
            }
            // Restore saved controls before falling back to automatic local-CA selection.
            configurations = savedWorkspace.Authorities.ToArray();
            RestoreViewControls(savedWorkspace.Current);
            if (ConfigurationBox.Text.Length == 0)
            {
                try { ConfigurationBox.Text = CertificateStore.LocalConfiguration(); }
                catch (Exception error) { Record(CaAdministration.Error(error)); }
            }
            ReloadSavedViews();
        }

        private void WorkspaceWarning(string message)
        {
            // Keep persistence failures visible independently of transient operation messages.
            WorkspaceNotice.Text = message;
            WorkspaceNotice.Visibility = string.IsNullOrEmpty(message) ? Visibility.Collapsed : Visibility.Visible;
        }

        private List<BrowserColumn> CaptureColumns() => Certificates.Columns.Select(column => new BrowserColumn
        {
            Key = column.SortMemberPath, Order = column.DisplayIndex,
            Width = Math.Max(24, Math.Min(4000, column.Width.IsAbsolute ? column.Width.Value : column.ActualWidth)),
            Visible = column.Visibility == Visibility.Visible
        }).ToList();

        private void RestoreColumns(IEnumerable<BrowserColumn> columns)
        {
            // Match columns by stable field identity and retain defaults for omitted entries.
            var layout = columns.ToDictionary(column => column.Key, StringComparer.Ordinal);
            foreach (var column in Certificates.Columns)
            {
                var value = layout.TryGetValue(column.SortMemberPath, out var saved) ? saved :
                    defaultColumns.Single(item => item.Key == column.SortMemberPath);
                column.Width = new DataGridLength(value.Width);
                column.Visibility = value.Visible ? Visibility.Visible : Visibility.Collapsed;
            }
            // Apply the complete display order after restoring sizes and visibility.
            var ordered = Certificates.Columns.OrderBy(column => layout.TryGetValue(column.SortMemberPath, out var value) ?
                value.Order : defaultColumns.Single(item => item.Key == column.SortMemberPath).Order).ToArray();
            for (var index = 0; index < ordered.Length; index++) ordered[index].DisplayIndex = index;
        }

        private BrowserView CaptureView() => new BrowserView
        {
            Configuration = store?.Configuration ?? savedWorkspace.Current.Configuration,
            Filter = ReadQuery(), ExpiryDays = expiryDays, SortField = sortField, SortDirection = sortDirection,
            AutoAuthorityColumn = autoAuthorityColumn, Columns = CaptureColumns()
        };

        private bool PersistWorkspace()
        {
            // Retain the last successful query when the current controls contain unapplied edits.
            if (!workspaceWritable) return false;
            try
            {
                if (query != null && !filtersDirty) savedWorkspace.Current = CaptureView();
                else
                {
                    savedWorkspace.Current.Columns = CaptureColumns();
                    savedWorkspace.Current.AutoAuthorityColumn = autoAuthorityColumn;
                }
                savedWorkspace.Authorities = CaDirectory.Configurations(configurations).ToList();
                savedWorkspace.Save(BrowserWorkspace.DefaultPath);
                WorkspaceWarning("");
                return true;
            }
            catch (Exception error)
            {
                WorkspaceWarning("Workspace settings could not be saved: " + CaAdministration.Error(error));
                return false;
            }
        }

        private void UpdateRelativeExpiry()
        {
            // Advance rolling UTC boundaries without scheduling recursive filter refreshes.
            if (!expiryDays.HasValue) return;
            var previous = restoringView;
            restoringView = true;
            try
            {
                var today = DateTime.UtcNow.Date;
                ExpiresFrom.Text = expiryDays > 0 ? today.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) : "";
                ExpiresBefore.Text = today.AddDays(expiryDays.Value).ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
            }
            finally { restoringView = previous; }
        }

        private void RestoreViewControls(BrowserView view)
        {
            // Validate once and suppress live filtering while replacing the browser controls.
            view.Validate(false);
            var filter = view.Query(DateTime.UtcNow);
            restoringView = true;
            try
            {
                filterTimer.Stop();
                ConfigurationBox.Text = view.Configuration;
                // Restore the category, search and date controls using their persisted identities.
                Views.SelectedItem = Views.Items.Cast<ListBoxItem>().Single(item =>
                    Convert.ToString(item.Tag) == Convert.ToString(filter.Disposition, CultureInfo.InvariantCulture));
                SearchField.SelectedItem = SearchField.Items.Cast<ComboBoxItem>().Single(item =>
                    Convert.ToString(item.Tag) == filter.Field);
                SearchBox.Text = filter.Value;
                MatchMode.SelectedIndex = (int)filter.Match;
                ExpiresFrom.Text = filter.ExpiresFrom?.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) ?? "";
                ExpiresBefore.Text = filter.ExpiresBefore?.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) ?? "";
                PageSize.SelectedItem = PageSize.Items.Cast<ComboBoxItem>().Single(item =>
                    Convert.ToString(item.Content) == filter.PageSize.ToString(CultureInfo.InvariantCulture));
                // Restore the rolling preset separately from the dates calculated for this session.
                expiryDays = view.ExpiryDays;
                ExpiryPresets.SelectedIndex = 0;
                if (expiryDays.HasValue)
                    ExpiryPresets.SelectedItem = ExpiryPresets.Items.Cast<ComboBoxItem>().Single(item =>
                        Convert.ToString(item.Tag) == expiryDays.Value.ToString(CultureInfo.InvariantCulture));
                // Restore query-wide sorting and column layout before any CA lookup starts.
                sortField = view.SortField;
                sortDirection = view.SortDirection;
                autoAuthorityColumn = view.AutoAuthorityColumn;
                RestoreColumns(view.Columns);
                if (autoAuthorityColumn) AuthorityColumn.Visibility = view.Configuration == CaDirectory.AllAuthorities ?
                    Visibility.Visible : Visibility.Collapsed;
                foreach (var column in Certificates.Columns)
                    column.SortDirection = column.SortMemberPath == sortField ? sortDirection :
                        (System.ComponentModel.ListSortDirection?)null;
                ViewTitle.Text = Convert.ToString(((ListBoxItem)Views.SelectedItem).Content);
            }
            finally { restoringView = false; }
        }

        private void ReloadSavedViews(string selectedName = null)
        {
            // Keep the selected saved view while rebuilding its ordered list and pinned shortcuts.
            selectedName ??= (SavedViewsBox.SelectedItem as BrowserView)?.Name;
            var views = savedWorkspace.Views.OrderBy(view => view.Name, StringComparer.OrdinalIgnoreCase).ToArray();
            SavedViewsBox.ItemsSource = views;
            SavedViewsBox.SelectedItem = views.FirstOrDefault(view => view.Name == selectedName);
            PinnedViewsPanel.Children.Clear();
            foreach (var view in views.Where(view => view.Pinned))
            {
                var button = new Button
                {
                    Content = view.Name.Replace("_", "__"),
                    HorizontalContentAlignment = HorizontalAlignment.Left, Margin = new Thickness(0, 0, 0, 4),
                    ToolTip = view.Name + Environment.NewLine + view.Configuration
                };
                System.Windows.Automation.AutomationProperties.SetName(button, view.Name);
                Glyphs.SetIcon(button, Glyphs.List);
                button.Click += async (sender, args) => await OpenSavedView(view);
                // Expose view management directly on each pinned shortcut.
                var menu = new ContextMenu();
                Dialogs.MenuItem(menu, "_Open", Glyphs.Open, "Open", async () => await OpenSavedView(view));
                Dialogs.MenuItem(menu, "_Rename...", Glyphs.Edit, "Rename", async () => await RenameSavedView(view));
                Dialogs.MenuItem(menu, "_Unpin", Glyphs.List, "Unpin", () => ToggleViewPin(view));
                Dialogs.MenuItem(menu, "_Delete...", Glyphs.Delete, "Delete", async () => await DeleteSavedView(view));
                button.ContextMenu = menu;
                PinnedViewsPanel.Children.Add(button);
            }
            PinnedViewsLabel.Visibility = PinnedViewsPanel.Children.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
            UpdateSavedViewControls();
        }

        private void UpdateSavedViewControls()
        {
            // Prevent view changes while a CA query or protected operation owns the browser.
            var ready = !busy && queryLoads == 0 && !discovering;
            OpenViewButton.IsEnabled = ready && SavedViewsBox.SelectedItem != null;
            SaveViewButton.IsEnabled = ready && workspaceWritable && query != null && !filtersDirty;
            SavedViewsBox.IsEnabled = ManageViewsButton.IsEnabled = ready;
            PinnedViewsPanel.IsEnabled = ready;
        }

        private void SavedViewSelected(object sender, SelectionChangedEventArgs e)
        {
            if (IsLoaded) UpdateSavedViewControls();
        }

        private async void OpenViewClick(object sender, RoutedEventArgs e)
        {
            if (SavedViewsBox.SelectedItem is BrowserView view) await OpenSavedView(view);
        }

        private async Task OpenSavedView(BrowserView view)
        {
            // Respect workspace navigation guards before switching the target and applied filters.
            if (busy || queryLoads > 0 || discovering || !ReturnToBrowser()) return;
            try
            {
                RestoreViewControls(view);
                SavedViewsBox.SelectedItem = view;
                await Connect();
            }
            catch (Exception error) { ShowError(error); }
        }

        private async void SaveViewClick(object sender, RoutedEventArgs e)
        {
            // Capture the applied view before asking for a name or confirmation to replace it.
            if (!workspaceWritable || busy || queryLoads > 0 || filtersDirty || query == null) return;
            try
            {
                var view = CaptureView();
                var name = await Dialogs.Prompt(this, "Save View", "View Name", (SavedViewsBox.SelectedItem as BrowserView)?.Name ?? "");
                if (name == null) return;
                // Enforce case-insensitive names and preserve the pin state when replacing a view.
                view.Name = name;
                view.Validate(true);
                var existing = savedWorkspace.Views.FirstOrDefault(value =>
                    value.Name.Equals(view.Name, StringComparison.OrdinalIgnoreCase));
                if (existing != null && !await Dialogs.Confirm(this, "Replace Saved View", "Replace '" + existing.Name +
                    "' with the current CA, filters, sorting and column layout?")) return;
                view.Pinned = existing?.Pinned ?? true;
                savedWorkspace.PutView(view, existing != null);
                ReloadSavedViews(view.Name);
                if (PersistWorkspace()) Record("Saved view: " + view.Name);
            }
            catch (Exception error) { ShowError(error); }
        }

        private async Task RenameSavedView(BrowserView view)
        {
            // Validate the proposed name without altering the existing view on cancellation or error.
            if (!workspaceWritable || !savedWorkspace.Views.Contains(view)) return;
            try
            {
                var name = await Dialogs.Prompt(this, "Rename Saved View", "View Name", view.Name);
                if (name == null || !savedWorkspace.Views.Contains(view)) return;
                var renamed = view.Copy();
                renamed.Name = name;
                renamed.Validate(true);
                if (savedWorkspace.Views.Any(value => value != view &&
                    value.Name.Equals(renamed.Name, StringComparison.OrdinalIgnoreCase)))
                    throw new ArgumentException("A view with that name already exists.");
                view.Name = renamed.Name;
                ReloadSavedViews(view.Name);
                PersistWorkspace();
            }
            catch (Exception error) { ShowError(error); }
        }

        private void ToggleViewPin(BrowserView view)
        {
            // Keep pinned shortcuts and the persisted view list in sync.
            if (!workspaceWritable || !savedWorkspace.Views.Contains(view)) return;
            view.Pinned = !view.Pinned;
            ReloadSavedViews(view.Name);
            PersistWorkspace();
        }

        private async Task DeleteSavedView(BrowserView view)
        {
            // Remove only the named view after confirmation; CA data remains unchanged.
            if (!workspaceWritable || !savedWorkspace.Views.Contains(view)) return;
            if (!await Dialogs.Confirm(this, "Delete Saved View", "Delete '" + view.Name +
                "'? Certificates and certificate authorities are not changed.")) return;
            savedWorkspace.Views.Remove(view);
            ReloadSavedViews();
            PersistWorkspace();
        }

        private void ManageViewsClick(object sender, RoutedEventArgs e)
        {
            // Host saved-view and connection management in the existing inline workspace.
            if (busy || queryLoads > 0 || discovering || !ReturnToBrowser()) return;
            var manager = new WorkspacePage { Title = "Saved Views And Connections" };
            var tabs = new TabControl();
            var viewsPanel = new DockPanel { Margin = new Thickness(8) };
            var actions = new WrapPanel();
            DockPanel.SetDock(actions, Dock.Bottom);
            viewsPanel.Children.Add(actions);
            // List saved view identities and pin state without making the grid itself editable.
            var grid = new DataGrid { SelectionMode = DataGridSelectionMode.Single };
            grid.Columns.Add(new DataGridTextColumn { Header = "View", Binding = new Binding("Name"),
                Width = new DataGridLength(1, DataGridLengthUnitType.Star) });
            grid.Columns.Add(new DataGridCheckBoxColumn { Header = "Pinned", Binding = new Binding("Pinned"), Width = 64 });
            grid.Columns.Add(new DataGridTextColumn { Header = "Certificate Authority", Binding = new Binding("Configuration"),
                Width = new DataGridLength(1, DataGridLengthUnitType.Star) });
            void Reload() => grid.ItemsSource = savedWorkspace.Views.OrderBy(view => view.Name,
                StringComparer.OrdinalIgnoreCase).ToArray();
            // Rebuild the manager inventory after each accepted view change.
            Dialogs.Button(actions, "_Open", async () =>
            {
                if (grid.SelectedItem is BrowserView view) await OpenSavedView(view);
            });
            var rename = Dialogs.Button(actions, "_Rename...", async () =>
            {
                if (grid.SelectedItem is BrowserView view) { await RenameSavedView(view); Reload(); }
            });
            var pin = Dialogs.Button(actions, "_Pin / Unpin", () =>
            {
                if (grid.SelectedItem is BrowserView view) { ToggleViewPin(view); Reload(); }
            });
            var delete = Dialogs.Button(actions, "_Delete...", async () =>
            {
                if (grid.SelectedItem is BrowserView view) { await DeleteSavedView(view); Reload(); }
            });
            rename.IsEnabled = pin.IsEnabled = delete.IsEnabled = workspaceWritable;
            Reload();
            viewsPanel.Children.Add(grid);
            tabs.Items.Add(new TabItem { Header = "Saved Views", Content = viewsPanel });
            // Forgetting a remembered connection does not change the active connection or saved views.
            var connectionsPanel = new DockPanel { Margin = new Thickness(8) };
            var connectionActions = new WrapPanel();
            DockPanel.SetDock(connectionActions, Dock.Bottom);
            connectionsPanel.Children.Add(connectionActions);
            var connections = new ListBox { ItemsSource = configurations.ToArray() };
            var forget = Dialogs.Button(connectionActions, "_Forget Connection", async () =>
            {
                if (connections.SelectedItem is not string configuration || !workspaceWritable) return;
                if (!await Dialogs.Confirm(this, "Forget Connection", configuration +
                    "\r\n\r\nRemove this remembered connection? Directory discovery may find it again. " +
                    "Saved views and the current connection are unchanged.")) return;
                configurations = configurations.Where(value => value != configuration).ToArray();
                UpdateAuthorities(Array.Empty<string>());
                connections.ItemsSource = configurations.ToArray();
                PersistWorkspace();
            });
            forget.IsEnabled = workspaceWritable;
            connectionsPanel.Children.Add(connections);
            tabs.Items.Add(new TabItem { Header = "Connections", Content = connectionsPanel });
            manager.Content = tabs;
            Navigate(manager);
        }

        private static bool IsColumnHeader(DependencyObject source)
        {
            // Distinguish header descendants from row clicks without disturbing bulk selection.
            while (source != null)
            {
                if (source is DataGridColumnHeader) return true;
                source = source is Visual ? VisualTreeHelper.GetParent(source) : LogicalTreeHelper.GetParent(source);
            }
            return false;
        }

        private void InitializeColumnMenu()
        {
            // Give headers their own column menu while retaining the row-action context menu.
            var menu = new ContextMenu();
            menu.Opened += (sender, args) => FillColumnMenu(menu.Items);
            var style = new Style(typeof(DataGridColumnHeader), (Style)FindResource(typeof(DataGridColumnHeader)));
            style.Setters.Add(new Setter(ContextMenuProperty, menu));
            Certificates.ColumnHeaderStyle = style;
            // Persist user-driven layout changes but ignore programmatic restoration events.
            Certificates.ColumnReordered += (sender, args) =>
            {
                if (!restoringView) PersistWorkspace();
            };
            Certificates.AddHandler(Thumb.DragCompletedEvent, new DragCompletedEventHandler((sender, args) =>
            {
                if (!restoringView && IsColumnHeader(args.OriginalSource as DependencyObject)) PersistWorkspace();
            }), true);
        }

        private void SetColumnVisibility(string key, bool visible)
        {
            // Keep at least one column visible and retain an explicit authority-column preference.
            var column = Certificates.Columns.Single(value => value.SortMemberPath == key);
            if (!visible && column.Visibility == Visibility.Visible &&
                Certificates.Columns.Count(value => value.Visibility == Visibility.Visible) == 1) return;
            column.Visibility = visible ? Visibility.Visible : Visibility.Collapsed;
            if (key == nameof(CertificateRow.Configuration)) autoAuthorityColumn = false;
            PersistWorkspace();
        }

        private void FillColumnMenu(ItemCollection items)
        {
            // Rebuild checked state when opening either the header menu or row submenu.
            items.Clear();
            void UpdateChecks()
            {
                var visible = Certificates.Columns.Count(column => column.Visibility == Visibility.Visible);
                foreach (var item in items.OfType<MenuItem>().Where(item => item.Tag is DataGridColumn))
                {
                    var column = (DataGridColumn)item.Tag;
                    item.IsChecked = column.Visibility == Visibility.Visible;
                    item.IsEnabled = !busy && workspace.Count == 0 && (!item.IsChecked || visible > 1);
                }
            }
            foreach (var column in Certificates.Columns.OrderBy(value => value.DisplayIndex))
            {
                // Keep toggles open and immediately reflect the last-visible-column guard.
                var item = new MenuItem
                {
                    Header = column.Header, Tag = column, IsCheckable = true, StaysOpenOnClick = true,
                    IsChecked = column.Visibility == Visibility.Visible
                };
                item.Click += (sender, args) =>
                {
                    if (!busy && workspace.Count == 0) SetColumnVisibility(column.SortMemberPath, item.IsChecked);
                    UpdateChecks();
                };
                items.Add(item);
            }
            items.Add(new Separator());
            // Reset visibility, widths and order together, including automatic CA-column behavior.
            var reset = new MenuItem { Header = "_Reset Column Layout", IsEnabled = !busy && workspace.Count == 0 };
            Glyphs.SetIcon(reset, Glyphs.Refresh);
            reset.Click += (sender, args) =>
            {
                autoAuthorityColumn = true;
                RestoreColumns(defaultColumns);
                UpdateControls();
                PersistWorkspace();
            };
            items.Add(reset);
            UpdateChecks();
        }

        private static ProcessStartInfo NativeConsoleStartInfo(bool templates)
        {
            // Use fixed Windows paths and console names, with no user-controlled command arguments.
            var system = Environment.SystemDirectory;
            return new ProcessStartInfo
            {
                FileName = Path.Combine(system, "mmc.exe"),
                Arguments = "\"" + Path.Combine(system, templates ? "certtmpl.msc" : "certsrv.msc") + "\"",
                WorkingDirectory = system, UseShellExecute = true
            };
        }

        private void LaunchNativeConsole(bool templates)
        {
            // Report missing management tools without attempting installation or forced elevation.
            try
            {
                var start = NativeConsoleStartInfo(templates);
                var console = Path.Combine(Environment.SystemDirectory, templates ? "certtmpl.msc" : "certsrv.msc");
                if (!File.Exists(start.FileName) || !File.Exists(console))
                    throw new FileNotFoundException("The native " + (templates ? "Certificate Templates" :
                        "Certification Authority") + " console is not installed. Enable the Windows AD CS management tools.");
                using var process = Process.Start(start);
                Record("Opened native " + (templates ? "Certificate Templates" : "Certification Authority") +
                    " MMC. Its target is managed independently of Certitude.");
            }
            catch (Exception error) { ShowError(error); }
        }

        private void NativeCaClick(object sender, RoutedEventArgs e) => LaunchNativeConsole(false);

        private void NativeTemplatesClick(object sender, RoutedEventArgs e) => LaunchNativeConsole(true);
    }
}