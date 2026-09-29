//
// Copyright (c) Bryan Berns.
// Licensed under GPLv3. See LICENSE.md.
//

using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
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
        private readonly TextBox server = new TextBox();
        private readonly ComboBox stores = new ComboBox { Width = 215, DisplayMemberPath = "Name" };
        private readonly TextBox search = new TextBox();
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
            Dialogs.Note(header, "Review and manage certificates published in the forest's AD stores using your " +
                "Windows identity. Changes require directory permissions and replicate through Active Directory.");

            // Place the domain input beside its directory load action.
            header.Children.Add(Glyphs.Label("Domain / Domain Controller (Blank = Current Domain)"));
            var connection = new DockPanel { Margin = new Thickness(0, 0, 0, 6) };
            var loadButtons = Dialogs.RightActions(connection);
            Dialogs.Button(loadButtons, "_Load Directory", async () => await Refresh(true));
            connection.Children.Add(server);
            header.Children.Add(connection);
            header.Children.Add(target);

            // Expose refresh and certificate management actions above the result table.
            var actions = new WrapPanel { Margin = new Thickness(0, 6, 0, 0) };
            header.Children.Add(actions);
            Dialogs.Button(actions, "_Refresh", async () => await Refresh());
            add = Dialogs.Button(actions, "_Add Certificate", async () => await Add());
            remove = Dialogs.Button(actions, "Remo_ve", async () => await Remove());
            view = Dialogs.Button(actions, "View _Certificate", View);
            inspect = Dialogs.Button(actions, "_Details", Inspect);
            export = Dialogs.Button(actions, "_Export", async () => await Export());

            // Combine store selection with text filtering of the loaded publication snapshot.
            var filters = new DockPanel { Margin = new Thickness(0, 6, 0, 15) };
            DockPanel.SetDock(stores, Dock.Left);
            stores.Margin = new Thickness(0, 0, 8, 0);
            stores.ItemsSource = PublishedDirectory.Stores;
            stores.SelectedIndex = 0;
            filters.Children.Add(stores);
            var label = Glyphs.Label("Search", true);
            label.Target = search;
            DockPanel.SetDock(label, Dock.Left);
            filters.Children.Add(label);
            filters.Children.Add(search);
            header.Children.Add(filters);
            search.ToolTip = "Filter by subject, issuer, thumbprint, status or publication object.";

            // Keep selected certificate details and operation status visible below the grid.
            var footer = new StackPanel();
            DockPanel.SetDock(footer, Dock.Bottom);
            layout.Children.Add(footer);
            footer.Children.Add(details);
            footer.Children.Add(status);

            // Display publication identity, expiry, and status in sortable columns.
            Column("Subject", nameof(PublishedCertificate.Subject), 2.2);
            Column("Issuer", nameof(PublishedCertificate.Issuer), 1.8);
            Column("Expires (UTC)", nameof(PublishedCertificate.Expires), 1.1, "yyyy-MM-dd");
            Column("AD Object", "Object.Name", 1.5);
            Column("Status", nameof(PublishedCertificate.Status), 1.3);
            BusyCursor.OnSorting(grid);
            layout.Children.Add(grid);
            Content = layout;

            // Provide certificate viewing, export, and removal actions on selected rows.
            var menu = Dialogs.RowMenu(grid);
            var native = Dialogs.MenuItem(menu,
                "Open In _Windows Certificate Viewer", Glyphs.Certificate, "View", View);
            var detail = Dialogs.MenuItem(menu, "_Details", Glyphs.Document, "Details", Inspect);
            var save = Dialogs.MenuItem(menu, "_Export Certificate", Glyphs.Save, "Export", async () => await Export());
            Dialogs.MenuItem(menu, "_Copy Thumbprint", Glyphs.Copy, "Copy",
                () => Dialogs.CopyText((grid.SelectedItem as PublishedCertificate)?.Thumbprint));
            var delete = Dialogs.MenuItem(menu, "Remo_ve From AD", Glyphs.Delete, "Remove",
                async () => await Remove(), "Delete");
            menu.Opened += (sender, e) =>
            {
                // Require decoded certificates for viewer and export actions.
                var row = grid.SelectedItem as PublishedCertificate;
                native.IsEnabled = save.IsEnabled = !IsBusy && row?.Certificate != null;
                detail.IsEnabled = delete.IsEnabled = !IsBusy && row != null;
            };

            // Refresh details on selection and open certificates on row double-click.
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
                status.Text = "Load The Directory To Review Its Published Certificates.";
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

        private void Column(string header, string path, double width, string format = null) => grid.Columns.Add(
            new DataGridTextColumn { Header = header, Binding = new Binding(path) { StringFormat = format },
                Width = new DataGridLength(width, DataGridLengthUnitType.Star) });

        private void Filter(string selected = null)
        {
            // Filter cached certificates while retaining a stable selected publication key.
            selected ??= (grid.SelectedItem as PublishedCertificate)?.Key;
            var text = search.Text.Trim();
            var rows = snapshot.Certificates.Where(row => new[] { row.Subject, row.Issuer, row.Thumbprint,
                row.Status, row.Object.Name, row.Object.DistinguishedName, row.PairSide }.Any(value =>
                    value.IndexOf(text, StringComparison.OrdinalIgnoreCase) >= 0)).ToArray();

            // Publish filtered rows with object counts and OID resolution status.
            grid.ItemsSource = rows;
            grid.SelectedItem = rows.FirstOrDefault(row => row.Key == selected);
            status.Text = $"{rows.Length:N0} Of {snapshot.Certificates.Count:N0} Certificates · " +
                $"{snapshot.Objects.Count:N0} Publication Objects" +
                (rows.Any(row => row.Certificate == null) ? " · Select Unreadable Values To Review Their Errors" : "") +
                (snapshot.OidStatus.Length == 0 ? "" : " · " + snapshot.OidStatus);
            SelectionChanged();
        }

        private static string Describe(PublishedCertificate row) => "Store: " + row.Store.Name +
            "\r\nDirectory Object: " + row.Object.DistinguishedName + "\r\nAttribute: " + row.Store.Attribute +
            (row.PairSide.Length == 0 ? "" : "\r\nPair Direction: " + row.PairSide) + "\r\n\r\n" +
            (row.Certificate == null ? row.Error + "\r\nValue SHA-256: " + row.Fingerprint :
                CertificateUtilities.Details(row.Certificate));

        private void SelectionChanged()
        {
            // Enable actions according to connection state and the selected certificate data.
            var row = grid.SelectedItem as PublishedCertificate;
            search.IsEnabled = directory != null && !IsBusy;
            add.IsEnabled = directory != null && !IsBusy &&
                (!loadedStore.ExistingOnly || snapshot.Objects.Count > 0);
            remove.IsEnabled = inspect.IsEnabled = directory != null && !IsBusy && row != null;
            view.IsEnabled = export.IsEnabled = !IsBusy && row?.Certificate != null;
            details.Text = row == null ? "Select A Published Certificate To Review Its Identity And AD Location." :
                Describe(row);
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

        private Task Refresh(bool reconnect = false) => Run("Reading Published Certificates…", async () =>
        {
            // Capture the requested store and clear stale results before reading the directory.
            OidNames.Invalidate();
            var connection = reconnect ? null : directory;
            var selected = (grid.SelectedItem as PublishedCertificate)?.Key;
            var requested = server.Text.Trim();
            var store = (PublishedStore)stores.SelectedItem;
            directory = null;
            snapshot = new PublishedSnapshot();
            grid.ItemsSource = null;
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
            var page = new PublishCertificatePage(directory, loadedStore, snapshot.Objects.ToArray(),
                (grid.SelectedItem as PublishedCertificate)?.Object.Name) { Owner = this };
            if (await page.ShowAsync() != true) return;
            await Refresh();
            status.Text = "Certificate Published To Active Directory. " + status.Text;
            record(status.Text);
        }

        private async Task Remove()
        {
            // Confirm removal using the exact publication location and its forest-wide effect.
            if (!remove.IsEnabled || grid.SelectedItem is not PublishedCertificate row) return;
            var connection = directory;
            if (!await Dialogs.Confirm(this, "Remove Published Certificate", "Domain Controller: " + connection.Server +
                "\r\n\r\n" + row.Store.Effect + "\r\n\r\nRemove this certificate from this AD publication? " +
                "Other certificates, directory objects and their settings are preserved. Removing a publication " +
                "does not revoke the certificate or immediately remove cached copies from clients." +
                (row.Store.Id == "CrossCA" && row.Direction >= 0 ?
                    " The other side of a cross-certificate pair, if present, is preserved." : "") +
                (row.Certificate == null ? " This unreadable value's original directory bytes will be removed." : "") +
                "\r\n\r\n" + Describe(row))) return;

            // Remove the selected publication in the background and refresh only on success.
            var removed = false;
            await Run("Removing Published Certificate…", async () =>
            {
                await Task.Run(() => connection.Remove(row));
                removed = true;
            });
            if (!removed) return;
            await Refresh();
            status.Text = "Certificate Removed From AD Publication. " + status.Text;
            record(status.Text);
        }

        private void View()
        {
            // Open the decoded selected certificate in the native Windows viewer.
            if (!IsBusy && grid.SelectedItem is PublishedCertificate row && row.Certificate != null)
                Dialogs.WindowsCertificate(this, row.Certificate.Encoded);
        }

        private void Inspect()
        {
            // Show publication details even when the stored certificate is unreadable.
            if (!IsBusy && grid.SelectedItem is PublishedCertificate row)
                Dialogs.Report(this, "Published Certificate Details", Describe(row));
        }

        private async Task Export()
        {
            // Export only a decoded public certificate from the current selection.
            if (!IsBusy && grid.SelectedItem is PublishedCertificate row && row.Certificate != null)
                await Dialogs.ExportCertificate(this, row.Certificate.Encoded, row.Certificate.Thumbprint + ".cer");
        }
    }

    internal sealed class PublishCertificatePage : WorkspacePage
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
        private byte[] certificate;
        internal bool IsBusy
        {
            get;
            // Keep preview and publication controls disabled through review and directory writes.
            private set { field = value; layout.IsEnabled = !value; }
        }

        public PublishCertificatePage(PublishedDirectory directory, PublishedStore store,
            PublishedObject[] objects, string selected)
        {
            // Create a publication form bound to the selected directory and store.
            this.directory = directory;
            this.store = store;
            Title = "Add Published Certificate";
            var header = new StackPanel();
            DockPanel.SetDock(header, Dock.Top);
            layout.Children.Add(header);
            Dialogs.Note(header, "Store: " + store.Name + "\r\nDomain Controller: " + directory.Server);

            // Provide file browsing and explicit loading before publication review.
            file = Dialogs.Field(header, "Certificate File (DER / PEM)");
            var browse = new WrapPanel { Margin = new Thickness(0, 5, 0, 0) };
            header.Children.Add(browse);
            Dialogs.Button(browse, "_Browse…", async () =>
            {
                // Load the chosen file into the publication preview.
                var picker = new FilePicker { Owner = this, Filter = "Certificates|*.cer;*.crt;*.pem|All Files|*.*" };
                if (await picker.ShowAsync() != true) return;
                file.Text = picker.FileName;
                await LoadCertificate();
            });
            Dialogs.Button(browse, "_Load Certificate", async () => await LoadCertificate());

            // Restrict object selection according to whether the store allows new objects.
            header.Children.Add(Glyphs.Label(store.ExistingOnly ?
                "Existing Enrollment Service" : "Publication Object Name"));
            objectName = new ComboBox { IsEditable = !store.FixedObject && !store.ExistingOnly,
                ItemsSource = store.FixedObject ? new[] { "NTAuthCertificates" } : objects.Select(item => item.Name).ToArray() };
            if (store.FixedObject || store.ExistingOnly) objectName.SelectedIndex = 0;
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
            file.TextChanged += (sender, e) => { certificate = null; preview.Clear(); };
            Closing += (sender, e) => e.Cancel = IsBusy;
        }

        private async Task LoadCertificate()
        {
            // Clear prior certificate data while a replacement file is being loaded.
            if (IsBusy) return;
            using var cursor = BusyCursor.Enter();
            IsBusy = true;
            certificate = null;
            preview.Clear();
            try
            {
                // Read a bounded public certificate file away from the UI thread.
                var path = file.Text.Trim();
                var bytes = await Task.Run(() =>
                {
                    var info = new FileInfo(path);
                    if (!info.Exists || info.Length == 0 || info.Length > 32 * 1024 * 1024)
                        throw new ArgumentException("Select a public certificate file no larger than 32 MB.");
                    return CertificateUtilities.DecodePublicPem(File.ReadAllBytes(path));
                });

                // Validate the certificate for its destination and populate the preview.
                var value = await Task.Run(() => PublishedDirectory.ValidateCertificate(store, bytes, directory.Names));
                certificate = value.Encoded;
                preview.Text = CertificateUtilities.Details(value);

                // Suggest an object name when the destination permits a new publication.
                if (!store.FixedObject && !store.ExistingOnly && string.IsNullOrWhiteSpace(objectName.Text))
                {
                    using var decoded = new X509Certificate2(bytes);
                    objectName.Text = decoded.GetNameInfo(X509NameType.SimpleName, store.Id == "KRA");
                }
                status.Text = "Certificate Loaded. Review The Publication Target Before Adding It To AD.";
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
                if (certificate == null) throw new ArgumentException("Load a public certificate first.");
                var name = objectName.Text;
                status.Text = "Preparing Publication…";
                var plan = await Task.Run(() => directory.Prepare(store, name, certificate));
                if (!await Dialogs.Confirm(this, "Publish Certificate To Active Directory", plan.Review))
                { status.Text = "Publication Cancelled. No Changes Made."; return; }

                // Publish the reviewed certificate and close the form only after success.
                status.Text = "Publishing Certificate…";
                await Task.Run(() => directory.Publish(plan));
                published = true;
            }
            catch (Exception error) { status.Text = CaAdministration.Error(error); }
            finally { IsBusy = false; }
            if (published) DialogResult = true;
        }
    }
}
