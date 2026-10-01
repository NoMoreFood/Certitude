//
// Copyright (c) Bryan Berns.
// Licensed under GPLv3. See LICENSE.md.
//

using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;

namespace Certitude
{
    internal sealed class PublishedPage : WorkspacePage
    {
        private readonly DockPanel layout = new DockPanel { Margin = new Thickness(8) };
        private readonly TextBox server = new TextBox { Width = 360, Margin = new Thickness(0, 0, 8, 4) };
        private readonly ComboBox stores = new ComboBox { Width = 240, DisplayMemberPath = "Name" };
        private readonly TextBox search = new TextBox { Width = 340, Margin = new Thickness(0, 0, 0, 4) };
        private readonly TextBlock target = new TextBlock { TextWrapping = TextWrapping.Wrap };
        private readonly TextBlock status = new TextBlock { TextWrapping = TextWrapping.Wrap };
        private readonly TextBox details = new TextBox { IsReadOnly = true, AcceptsReturn = true, Height = 100,
            TextWrapping = TextWrapping.Wrap, VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            VerticalContentAlignment = VerticalAlignment.Top, Margin = new Thickness(0, 5, 0, 5) };
        private readonly DataGrid grid = new DataGrid { SelectionMode = DataGridSelectionMode.Single };
        private readonly Button add, remove, view, inspect, export;
        private readonly Action<string> record;
        private PublishedDirectory directory;
        private PublishedStore loadedStore;
        private PublishedSnapshot snapshot = new PublishedSnapshot();
        private bool initialized;
        internal bool IsBusy
        {
            get;
            // Keep publication controls disabled while directory reads or writes are in progress.
            private set { field = value; layout.IsEnabled = !value; }
        }

        public PublishedPage(Action<string> log = null)
        {
            // Create the forest publication page and explain the scope of directory changes.
            record = log ?? (text => { });
            Title = "Forest Published";
            var header = new StackPanel();
            DockPanel.SetDock(header, Dock.Top);
            layout.Children.Add(header);
            Dialogs.Note(header, "Review and manage certificates and revocation lists published in the forest " +
                "using your Windows identity. Changes require directory permissions " +
                "and replicate through Active Directory.");

            // Keep directory discovery beside its input and make the forest-wide result scope explicit.
            header.Children.Add(Glyphs.Label("Domain / Domain Controller (Blank = Automatic)"));
            var connection = new WrapPanel();
            connection.Children.Add(server);
            Dialogs.Button(connection, "_Load Directory", async () => await Refresh(true));
            header.Children.Add(connection);
            var scope = new TextBlock { Text = "Forest-Wide Results", FontSize = 10,
                Margin = new Thickness(0, 0, 0, 4) };
            scope.SetResourceReference(TextBlock.ForegroundProperty, "Muted");
            header.Children.Add(scope);
            header.Children.Add(target);

            // Expose refresh and publication management actions above the result table.
            var actions = new WrapPanel { Margin = new Thickness(0, 6, 0, 0) };
            header.Children.Add(actions);
            Dialogs.Button(actions, "_Refresh", async () => await Refresh());
            add = Dialogs.Button(actions, "_Add Certificate", async () => await Add());
            remove = Dialogs.Button(actions, "Remo_ve", async () => await Remove());
            view = Dialogs.Button(actions, "View _Certificate", View);
            inspect = Dialogs.Button(actions, "_Details", Inspect);
            export = Dialogs.Button(actions, "_Export", async () => await Export());

            // Combine store selection with text filtering of the loaded publication snapshot.
            var filters = new WrapPanel { Margin = new Thickness(0, 6, 0, 11) };
            stores.Margin = new Thickness(0, 0, 8, 4);
            stores.ItemsSource = PublishedDirectory.Stores;
            stores.SelectedIndex = 0;
            filters.Children.Add(stores);
            var label = Glyphs.Label("Search", true);
            label.Target = search;
            label.Margin = new Thickness(0, 0, 6, 4);
            filters.Children.Add(label);
            filters.Children.Add(search);
            header.Children.Add(filters);
            search.ToolTip = "Filter by subject, issuer, thumbprint / SHA-256, " +
                "CRL number, status or publication object.";

            // Keep selected artifact details and operation status visible below the grid.
            var footer = new StackPanel();
            DockPanel.SetDock(footer, Dock.Bottom);
            layout.Children.Add(footer);
            footer.Children.Add(details);
            footer.Children.Add(status);

            // Display publication identity, expiry, and status in sortable columns.
            Columns((PublishedStore)stores.SelectedItem);
            BusyCursor.OnSorting(grid);
            layout.Children.Add(grid);
            Content = layout;

            // Provide type-appropriate viewing, export, and removal actions on selected rows.
            var menu = Dialogs.RowMenu(grid);
            var native = Dialogs.MenuItem(menu,
                "Open In _Windows Certificate Viewer", Glyphs.Certificate, "View", View);
            var detail = Dialogs.MenuItem(menu, "_Details", Glyphs.Document, "Details", Inspect);
            var save = Dialogs.MenuItem(menu, "_Export Certificate", Glyphs.Save, "Export", async () => await Export());
            var copy = Dialogs.MenuItem(menu, "_Copy Thumbprint", Glyphs.Copy, "Copy",
                () => Dialogs.CopyText((grid.SelectedItem as PublishedArtifact)?.Thumbprint));
            var delete = Dialogs.MenuItem(menu, "Remo_ve From AD", Glyphs.Delete, "Remove",
                async () => await Remove(), "Delete");
            bool UpdateMenu()
            {
                // Hide the native certificate viewer for CRLs and retain raw export for unreadable artifacts.
                var row = grid.SelectedItem as PublishedArtifact;
                native.IsEnabled = !IsBusy && row?.Certificate != null;
                save.IsEnabled = detail.IsEnabled = delete.IsEnabled = copy.IsEnabled = !IsBusy && row != null;
                save.Header = row?.Readable == true ? "_Export " + row.Store.ItemName : "_Export Raw Value";
                copy.Header = row?.Certificate != null ? "_Copy Thumbprint" : "_Copy SHA-256";
                return Dialogs.FilterMenu(menu, item => row != null && (item != native || row.Certificate != null));
            }
            grid.ContextMenuOpening += (sender, e) => { if (!UpdateMenu()) e.Handled = true; };
            menu.Opened += (sender, e) => { if (!UpdateMenu()) menu.IsOpen = false; };

            // Open certificates in Windows and show CRL details inline on row double-click.
            grid.SelectionChanged += (sender, e) => SelectionChanged();
            grid.MouseDoubleClick += (sender, e) =>
            {
                if (ItemsControl.ContainerFromElement(grid, e.OriginalSource as DependencyObject) is DataGridRow)
                    View();
            };

            // React to search and store changes without reusing a different target snapshot.
            search.TextChanged += (sender, e) => Filter();
            stores.SelectionChanged += async (sender, e) => { if (initialized) await Refresh(); };
            server.TextChanged += (sender, e) =>
            {
                // Clear directory results immediately when the connection target changes.
                directory = null;
                snapshot = new PublishedSnapshot();
                target.Text = "";
                Filter();
                status.Text = "Load The Directory To Review Its Published Artifacts.";
            };
            server.KeyDown += async (sender, e) =>
            {
                // Load the edited directory target when Enter is pressed.
                if (e.Key != Key.Enter) return;
                e.Handled = true;
                await Refresh(true);
            };
            PreviewKeyDown += async (sender, e) =>
            {
                // Handle refresh, remove, and view shortcuts in the relevant control context.
                if (e.Key == Key.F5) { e.Handled = true; await Refresh(); }
                if (!grid.IsKeyboardFocusWithin) return;
                if (e.Key == Key.Delete) { e.Handled = true; await Remove(); }
                if (e.Key == Key.Enter) { e.Handled = true; View(); }
            };

            // Load the first snapshot once and prevent navigation during directory work.
            Closing += (sender, e) => e.Cancel = IsBusy;
            Loaded += async (sender, e) =>
            {
                if (initialized) return;
                initialized = true;
                await Refresh(true);
            };
            SelectionChanged();
        }

        private void Column(string header, string path, double width, string format = null, double minimum = 60)
        {
            // Preserve readable column widths and reveal long identifiers without changing the active theme.
            var cell = new Style(typeof(DataGridCell), (Style)FindResource(typeof(DataGridCell)));
            var date = path is nameof(PublishedArtifact.Updated) or nameof(PublishedArtifact.Expires);
            cell.Setters.Add(new Setter(ToolTipProperty, date ? TimeDisplay.Binding(path, format) :
                new Binding(path) { StringFormat = format }));
            var column = new DataGridTextColumn
            {
                Header = header, SortMemberPath = path, Binding = date ? TimeDisplay.Binding(path, format) :
                    new Binding(path) { StringFormat = format }, CellStyle = cell,
                Width = new DataGridLength(width, DataGridLengthUnitType.Star), MinWidth = minimum
            };
            if (date) TimeDisplay.Label(column, DataGridColumn.HeaderProperty, header);
            grid.Columns.Add(column);
        }

        private void Columns(PublishedStore store)
        {
            // Show CRL freshness and size without repeating the issuer as a certificate subject.
            grid.Columns.Clear();
            if (store.IsCrl)
            {
                Column("Issuer", nameof(PublishedArtifact.Issuer), 2.1, minimum: 165);
                Column("Status", nameof(PublishedArtifact.Status), 1.3, minimum: 135);
                Column("This Update (UTC)", nameof(PublishedArtifact.Updated), 1.3, "yyyy-MM-dd HH:mm", 132);
                Column("Next Update (UTC)", nameof(PublishedArtifact.Expires), 1.3, "yyyy-MM-dd HH:mm", 132);
                Column("CRL Number", nameof(PublishedArtifact.Number), 0.8, minimum: 92);
                Column("Entries", nameof(PublishedArtifact.Entries), 0.7, "N0", 62);
                Column("AD Object", "Object.DistinguishedName", 2, minimum: 220);
            }
            else
            {
                Column("Subject", nameof(PublishedArtifact.Subject), 2.2);
                Column("Issuer", nameof(PublishedArtifact.Issuer), 1.8);
                Column("Expires (UTC)", nameof(PublishedArtifact.Expires), 1.1, "yyyy-MM-dd");
                Column("AD Object", "Object.Name", 2);
                Column("Status", nameof(PublishedArtifact.Status), 1.3);
            }
        }

        private void Filter(string selected = null)
        {
            // Filter cached artifacts while retaining a stable selected publication key.
            selected ??= (grid.SelectedItem as PublishedArtifact)?.Key;
            var text = search.Text.Trim();
            var rows = snapshot.Artifacts.Where(row => new[] { row.Subject, row.Issuer, row.Thumbprint,
                row.Status, row.Object.Name, row.Object.DistinguishedName, row.PairSide, row.Number }.Any(value =>
                    value.IndexOf(text, StringComparison.OrdinalIgnoreCase) >= 0)).ToArray();

            // Publish filtered rows with object counts and OID resolution status.
            grid.ItemsSource = rows;
            grid.SelectedItem = rows.FirstOrDefault(row => row.Key == selected);
            var kind = ((PublishedStore)stores.SelectedItem).IsCrl ? "CRLs" : "Certificates";
            status.Text = $"{rows.Length:N0} Of {snapshot.Artifacts.Count:N0} {kind} · " +
                $"{snapshot.Objects.Count:N0} Publication Objects" +
                (rows.Any(row => !row.Readable) ? " · Select Unreadable Values To Review Their Errors" : "") +
                (snapshot.OidStatus.Length == 0 ? "" : " · " + snapshot.OidStatus);
            SelectionChanged();
        }

        private static string Describe(PublishedArtifact row) => "Store: " + row.Store.Name +
            "\r\nDirectory Object: " + row.Object.DistinguishedName + "\r\nAttribute: " + row.Store.Attribute +
            "\r\nSize: " + CaServerStatistics.Size(row.Value.Length) +
            (row.PairSide.Length == 0 ? "" : "\r\nPair Direction: " + row.PairSide) + "\r\n\r\n" + row.Details;

        private void SelectionChanged()
        {
            // Enable and label actions according to the selected store and artifact type.
            var row = grid.SelectedItem as PublishedArtifact;
            var store = (PublishedStore)stores.SelectedItem;
            add.Content = "_Add " + store.ItemName;
            view.Content = "View _" + store.ItemName;
            search.IsEnabled = directory != null && !IsBusy;
            add.IsEnabled = directory != null && !IsBusy &&
                (!loadedStore.ExistingOnly || snapshot.Objects.Count > 0);
            remove.IsEnabled = inspect.IsEnabled = directory != null && !IsBusy && row != null;
            view.IsEnabled = !IsBusy && row?.Readable == true;
            export.IsEnabled = !IsBusy && row != null;
            TimeDisplay.Text(details, () => row == null ?
                "Select A Published Artifact To Review Its Identity And AD Location." : Describe(row));
        }

        private async Task Run(string message, Func<Task> action)
        {
            // Serialize page operations and show progress with a busy cursor.
            if (IsBusy) return;
            using var cursor = BusyCursor.Enter();
            IsBusy = true;
            status.Text = message;
            try { await action(); }
            catch (Exception error) { status.Text = CaAdministration.Error(error); }
            finally
            {
                // Restore the page and selected-row actions after each directory operation.
                IsBusy = false;
                SelectionChanged();
                record(status.Text);
            }
        }

        private Task Refresh(bool reconnect = false) => Run("Reading Published Artifacts…", async () =>
        {
            // Capture the requested store and clear stale results before reading the directory.
            OidNames.Invalidate();
            var connection = reconnect ? null : directory;
            var selected = (grid.SelectedItem as PublishedArtifact)?.Key;
            var requested = server.Text.Trim();
            var store = (PublishedStore)stores.SelectedItem;
            directory = null;
            snapshot = new PublishedSnapshot();
            grid.ItemsSource = null;
            Columns(store);
            details.Clear();
            target.Text = "";

            // Publish a complete snapshot after the directory lookup finishes.
            connection ??= await Task.Run(() => PublishedDirectory.Connect(requested));
            snapshot = await Task.Run(() => connection.Read(store));
            directory = connection;
            loadedStore = store;
            target.Text = "Domain Controller: " + directory.Server + "\r\nForest: " + directory.ConfigurationName;
            Filter(selected);
        });

        private async Task Add()
        {
            // Open the publication form and refresh results after a successful addition.
            if (!add.IsEnabled) return;
            var row = grid.SelectedItem as PublishedArtifact;
            var page = new PublishArtifactPage(directory, loadedStore, snapshot.Objects.ToArray(),
                loadedStore.IsCrl ? row?.Object.DistinguishedName : row?.Object.Name) { Owner = this };
            if (await page.ShowAsync() != true) return;
            await Refresh();
            status.Text = loadedStore.ItemName + " Published To Active Directory. " + status.Text;
            record(status.Text);
        }

        private async Task Remove()
        {
            // Confirm removal using the exact publication location and its forest-wide effect.
            if (!remove.IsEnabled || grid.SelectedItem is not PublishedArtifact row) return;
            var connection = directory;
            if (!await Dialogs.Confirm(this, "Remove Published " + row.Store.ItemName,
                "Domain Controller: " + connection.Server + "\r\n\r\n" + row.Store.Effect +
                "\r\n\r\nRemove this value from this AD publication? " +
                "Other values, directory objects and their settings are preserved. " +
                (row.Store.IsCrl ? "Clients using this location may no longer find current revocation information." :
                    "Removing a publication does not revoke the certificate.") +
                " Cached copies on clients are not immediately removed." +
                (row.Store.Id == "CrossCA" && row.Direction >= 0 ?
                    " The other side of a cross-certificate pair, if present, is preserved." : "") +
                (!row.Readable ? " This unreadable value's original directory bytes will be removed." : "") +
                "\r\n\r\n" + Describe(row))) return;

            // Remove the selected publication in the background and refresh only on success.
            var removed = false;
            await Run("Removing Published " + row.Store.ItemName + "…", async () =>
            {
                await Task.Run(() => connection.Remove(row));
                removed = true;
            });
            if (!removed) return;
            await Refresh();
            status.Text = row.Store.ItemName + " Removed From AD Publication. " + status.Text;
            record(status.Text);
        }

        private void View()
        {
            // Keep Windows certificate viewing and inline CRL inspection appropriate to the selected artifact.
            if (IsBusy || grid.SelectedItem is not PublishedArtifact row) return;
            if (row.Certificate != null) Dialogs.WindowsCertificate(this, row.Certificate.Encoded);
            else Inspect();
        }

        private void Inspect()
        {
            // Show publication details even when the stored artifact is unreadable.
            if (!IsBusy && grid.SelectedItem is PublishedArtifact row)
                Dialogs.Report(this, "Published " + row.Store.ItemName + " Details", () => Describe(row));
        }

        private async Task Export()
        {
            // Preserve certificate export formats and save CRLs or unreadable values without altering their bytes.
            if (IsBusy || grid.SelectedItem is not PublishedArtifact row) return;
            if (row.Certificate != null)
            {
                await Dialogs.ExportCertificate(this, row.Certificate.Encoded, row.Certificate.Thumbprint + ".cer");
                return;
            }
            var save = new FilePicker(true) { Owner = this,
                FileName = row.Fingerprint + (row.Crl != null ? ".crl" : ".bin"),
                Filter = row.Crl != null ? "CRL|*.crl" : "Raw Value|*.bin" };
            if (await save.ShowAsync() != true) return;
            await Run("Exporting Published Value…", async () =>
            {
                await Task.Run(() => File.WriteAllBytes(save.FileName, row.Encoded));
                status.Text = "Exported To " + save.FileName;
            });
        }
    }

    internal sealed class PublishArtifactPage : WorkspacePage
    {
        private readonly DockPanel layout = new DockPanel { Margin = new Thickness(8) };
        private readonly TextBox file;
        private readonly ComboBox objectName;
        private readonly TextBox preview = new TextBox { IsReadOnly = true, AcceptsReturn = true,
            TextWrapping = TextWrapping.Wrap, VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            VerticalContentAlignment = VerticalAlignment.Top, Margin = new Thickness(0, 8, 0, 0) };
        private readonly TextBlock status = new TextBlock { TextWrapping = TextWrapping.Wrap };
        private readonly PublishedDirectory directory;
        private readonly PublishedStore store;
        private byte[] encoded;
        internal bool IsBusy
        {
            get;
            // Keep preview and publication controls disabled through review and directory writes.
            private set { field = value; layout.IsEnabled = !value; }
        }

        public PublishArtifactPage(PublishedDirectory directory, PublishedStore store,
            PublishedObject[] objects, string selected)
        {
            // Create a publication form bound to the selected directory and store.
            this.directory = directory;
            this.store = store;
            Title = "Add Published " + store.ItemName;
            var header = new StackPanel();
            DockPanel.SetDock(header, Dock.Top);
            layout.Children.Add(header);
            Dialogs.Note(header, "Store: " + store.Name + "\r\nDomain Controller: " + directory.Server);

            // Provide file browsing and explicit loading before publication review.
            file = Dialogs.Field(header, store.ItemName + " File (DER / PEM)", width: 640);
            var browse = new WrapPanel { Margin = new Thickness(0, 5, 0, 0) };
            header.Children.Add(browse);
            Dialogs.Button(browse, "_Browse…", async () =>
            {
                // Load the chosen file into the publication preview.
                var picker = new FilePicker { Owner = this, Filter = store.IsCrl ?
                    "CRLs|*.crl;*.pem|All Files|*.*" : "Certificates|*.cer;*.crt;*.pem|All Files|*.*" };
                if (await picker.ShowAsync() != true) return;
                file.Text = picker.FileName;
                await LoadArtifact();
            });
            Dialogs.Button(browse, "_Load " + store.ItemName, async () => await LoadArtifact());

            // Restrict object selection according to whether the store allows new objects.
            header.Children.Add(Glyphs.Label(store.IsCrl ? "Existing CRL Publication Object" : store.ExistingOnly ?
                "Existing Enrollment Service" : "Publication Object Name"));
            objectName = new ComboBox { IsEditable = !store.FixedObject && !store.ExistingOnly,
                Width = store.IsCrl ? 650 : 360, HorizontalAlignment = HorizontalAlignment.Left,
                ItemsSource = store.FixedObject ? new[] { "NTAuthCertificates" } :
                    objects.Select(item => store.IsCrl ? item.DistinguishedName : item.Name).ToArray() };
            if (store.FixedObject || (store.ExistingOnly && !store.IsCrl)) objectName.SelectedIndex = 0;
            else objectName.Text = selected ?? "";
            if (store.ExistingOnly && selected != null) objectName.SelectedItem = selected;
            objectName.IsEnabled = !store.FixedObject;
            header.Children.Add(objectName);

            // Place review and cancellation controls beside inline publication status.
            var footer = new StackPanel { Margin = new Thickness(0, 7, 0, 0) };
            DockPanel.SetDock(footer, Dock.Bottom);
            layout.Children.Add(footer);
            footer.Children.Add(status);
            var actions = new WrapPanel { Margin = new Thickness(0, 6, 0, 0) };
            footer.Children.Add(actions);
            Dialogs.Button(actions, "_Review Publication", async () => await Publish());
            Dialogs.Button(actions, "_Cancel", Close);
            layout.Children.Add(preview);
            Content = layout;

            // Invalidate the preview when the file changes and block navigation during work.
            file.TextChanged += (sender, e) => { encoded = null; preview.Clear(); };
            Closing += (sender, e) => e.Cancel = IsBusy;
        }

        private async Task LoadArtifact()
        {
            // Clear prior artifact data while a replacement file is being loaded.
            if (IsBusy) return;
            using var cursor = BusyCursor.Enter();
            IsBusy = true;
            encoded = null;
            preview.Clear();
            try
            {
                // Read a bounded public artifact file away from the UI thread.
                var path = file.Text.Trim();
                var bytes = await Task.Run(() =>
                {
                    var info = new FileInfo(path);
                    if (!info.Exists || info.Length == 0 || info.Length > 32 * 1024 * 1024)
                        throw new ArgumentException("Select a " + store.ItemName + " file no larger than 32 MB.");
                    var data = File.ReadAllBytes(path);
                    if (!store.IsCrl) return CertificateUtilities.DecodePublicPem(data);

                    // Accept exactly one armored CRL or an unmodified DER payload.
                    var text = Encoding.ASCII.GetString(data).Trim();
                    if (!text.StartsWith("-----BEGIN", StringComparison.Ordinal)) return data;
                    var match = Regex.Match(text,
                        @"\A-----BEGIN (X509 CRL|CRL)-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END \1-----\z");
                    if (!match.Success) throw new ArgumentException("Select a single CRL in DER or PEM format.");
                    return Convert.FromBase64String(match.Groups[2].Value);
                });

                // Validate the artifact for its destination and populate the preview.
                var value = await Task.Run(() => PublishedDirectory.ValidateArtifact(store, bytes, directory.Names));
                encoded = value.Encoded;
                TimeDisplay.Text(preview, () => value.Details);

                // Suggest an object name when the destination permits a new publication.
                if (!store.FixedObject && !store.ExistingOnly && string.IsNullOrWhiteSpace(objectName.Text))
                {
                    using var decoded = new X509Certificate2(bytes);
                    objectName.Text = decoded.GetNameInfo(X509NameType.SimpleName, store.Id == "KRA");
                }
                status.Text = store.ItemName + " Loaded. Review The Publication Target Before Adding It To AD.";
            }
            catch (Exception error) { status.Text = CaAdministration.Error(error); }
            finally { IsBusy = false; }
        }

        private async Task Publish()
        {
            // Prevent concurrent publication attempts while review and writing are in progress.
            if (IsBusy) return;
            using var cursor = BusyCursor.Enter();
            IsBusy = true;
            var published = false;
            try
            {
                // Prepare and confirm the exact directory change before applying it.
                if (encoded == null) throw new ArgumentException("Load a " + store.ItemName + " first.");
                var name = objectName.Text;
                status.Text = "Preparing Publication…";
                var plan = await Task.Run(() => directory.Prepare(store, name, encoded));
                if (!await Dialogs.Confirm(this, "Publish " + store.ItemName + " To Active Directory", plan.Review))
                { status.Text = "Publication Cancelled. No Changes Made."; return; }

                // Publish the reviewed artifact and close the form only after success.
                status.Text = "Publishing " + store.ItemName + "…";
                await Task.Run(() => directory.Publish(plan));
                published = true;
            }
            catch (Exception error) { status.Text = CaAdministration.Error(error); }
            finally { IsBusy = false; }
            if (published) DialogResult = true;
        }
    }
}
