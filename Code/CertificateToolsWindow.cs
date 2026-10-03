//
// Copyright (c) Bryan Berns.
// Licensed under GPLv3. See LICENSE.md.
//

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Threading;

namespace Certitude
{
    internal sealed class CertificateToolsWindow : WorkspacePage
    {
        private readonly Action<string> record;
        private readonly Lazy<OidNames> oidNames;
        private OidNames oids = OidNames.Windows;
        private readonly TabControl tabs = new TabControl();
        private readonly TextBlock status = new TextBlock { TextWrapping = TextWrapping.Wrap };
        private readonly Button cancel;
        private readonly ComboBox location = new ComboBox
            { ItemsSource = new[] { "Local Machine", "Current User" }, SelectedIndex = 0, Width = 125 };
        private readonly ComboBox storeName = new ComboBox
            { ItemsSource = CertificateUtilities.StoreNames, SelectedIndex = 0, Width = 125 };
        private readonly TextBox search = new TextBox { Width = 235 };
        private readonly ComboBox validity = new ComboBox { Width = 145, SelectedIndex = 0,
            ItemsSource = new[] { "All Dates", "Expired", "Expires In 30 Days", "Expires In 90 Days", "Not Yet Valid" } };
        private readonly ComboBox keys = new ComboBox { Width = 135, SelectedIndex = 0,
            ItemsSource = new[] { "Any Key Status", "Has Private Key", "No Private Key" } };
        private readonly DataGrid inventory = new DataGrid { SelectionMode = DataGridSelectionMode.Extended };
        private readonly WrapPanel inventoryActions = new WrapPanel();
        private readonly TextBox details = Output();
        private readonly TextBlock source = new TextBlock { TextWrapping = TextWrapping.Wrap };
        private readonly TextBlock counts = new TextBlock
            { TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 4, 0, 4) };
        private readonly DispatcherTimer searchTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(250) };
        private List<InventoryCertificate> rows = new List<InventoryCertificate>();
        private StoreLocation loadedLocation;
        private string loadedStore;
        private CancellationTokenSource cancellation;
        private TlsProbeResult tlsResult;
        private TextBox tlsOutput;
        private TextBox endpoint;
        private TextBox port;
        private TextBox serverName;
        private TextBox expected;
        private TextBox timeout;
        private CheckBox checkRevocation;
        private TextBox subject;
        private TextBox dns;
        private TextBox ips;
        private TextBox template;
        private TextBox configuration;
        private TextBox requestPath;
        private TextBox requestId;
        private TextBox enrollmentOutput;
        private ComboBox algorithm;
        private CheckBox machine;
        private CheckBox exportable;
        private CheckBox serverAuth;
        private CheckBox clientAuth;
        private EnrollmentResult enrollmentResult;

        public CertificateToolsWindow(string config = "", Action<string> log = null, OidNames names = null)
        {
            // Create the local certificate workspace with OID names from the selected CA or forest.
            oidNames = new Lazy<OidNames>(() => names ?? (config.Length == 0 ? OidNames.Local : OidNames.Load(config)));
            record = log ?? (text => { });
            Title = "Certificate Manager — " + Environment.MachineName;
            var layout = new DockPanel { Margin = new Thickness(8) };
            var footer = new DockPanel { Margin = new Thickness(0, 6, 0, 0) };
            DockPanel.SetDock(footer, Dock.Bottom);
            layout.Children.Add(footer);

            // Keep operation status and cancellation accessible beneath all tool tabs.
            cancel = new Button { Content = "_Cancel Operation", IsEnabled = false, Margin = new Thickness(12, 0, 0, 0) };
            Glyphs.SetIcon(cancel, Glyphs.Cancel);
            cancel.Click += (sender, e) => cancellation?.Cancel();
            DockPanel.SetDock(cancel, Dock.Right);
            footer.Children.Add(cancel);
            footer.Children.Add(status);
            layout.Children.Add(tabs);
            Content = layout;

            // Build the tools and connect debounced inventory filtering to source changes.
            BuildInventory();
            BuildTls();
            BuildEnrollment(config);
            searchTimer.Tick += (sender, e) => { searchTimer.Stop(); ApplyFilters(); };
            search.TextChanged += (sender, e) => { searchTimer.Stop(); searchTimer.Start(); };
            validity.SelectionChanged += (sender, e) => ApplyFilters();
            keys.SelectionChanged += (sender, e) => ApplyFilters();
            location.SelectionChanged += (sender, e) => SourceChanged();
            storeName.SelectionChanged += (sender, e) => SourceChanged();
            Closing += (sender, e) =>
            {
                // Cancel active work before allowing the certificate workspace to close.
                searchTimer.Stop();
                if (cancellation == null) return;
                cancellation.Cancel();
                e.Cancel = true;
                status.Text = "Waiting for the current Windows call to return. Close again when it finishes.";
            };

            // Explain the available tools and load the initial Windows store once.
            status.Text = "Load a Windows store, open a certificate file, check a TLS endpoint, or create a request.";
            var firstLoad = true;
            Loaded += async (sender, e) =>
            {
                if (!firstLoad) return;
                firstLoad = false;
                await Reload();
            };
        }

        private DockPanel Page(string title, out StackPanel header)
        {
            // Create a tool tab with a consistent header area and glyph.
            var page = new DockPanel { Margin = new Thickness(6) };
            header = new StackPanel();
            DockPanel.SetDock(header, Dock.Top);
            page.Children.Add(header);
            var tab = new TabItem { Header = Dialogs.Caption(title), Content = page };
            Glyphs.SetIcon(tab, Glyphs.ForCaption(title));
            tabs.Items.Add(tab);
            return page;
        }

        private static TextBox Output() => new TextBox
        {
            IsReadOnly = true, AcceptsReturn = true, VerticalContentAlignment = VerticalAlignment.Top,
            FontFamily = new System.Windows.Media.FontFamily("Consolas"),
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto, HorizontalScrollBarVisibility = ScrollBarVisibility.Auto
        };

        private static void Label(Panel panel, string label, FrameworkElement control)
        {
            // Align labeled controls along the bottom of a wrapping form row.
            var field = new StackPanel { Width = control.Width, Margin = new Thickness(0, 0, 8, 4),
                VerticalAlignment = VerticalAlignment.Bottom };
            var caption = Glyphs.Label(label);
            caption.Target = control;
            AutomationProperties.SetLabeledBy(control, caption);
            caption.Margin = new Thickness(0, 0, 0, 3);
            field.Children.Add(caption);
            field.Children.Add(control);
            panel.Children.Add(field);
        }

        private static CheckBox Check(Panel panel, string caption, bool value = false)
        {
            // Add a consistently spaced, title-cased option to the form.
            var check = new CheckBox { Content = Dialogs.Caption(caption), IsChecked = value, Margin = new Thickness(0, 0, 12, 6) };
            panel.Children.Add(check);
            return check;
        }

        private async Task Run(string message, Func<CancellationToken, Task> operation)
        {
            // Serialize tool operations and expose a shared cancellation control.
            if (cancellation != null) return;
            using var cursor = BusyCursor.Enter();
            using (var request = new CancellationTokenSource())
            {
                cancellation = request;
                tabs.IsEnabled = false;
                cancel.IsEnabled = true;
                status.Text = message;
                UpdateContextMenu();
                try
                {
                    // Refresh OID names before running the operation and append resolution status.
                    oids = await Task.Run(() => oidNames.Value.Refresh(), request.Token);
                    request.Token.ThrowIfCancellationRequested();
                    await operation(request.Token);
                    status.Text += " · " + oids.Status;
                }
                catch (OperationCanceledException)
                {
                    status.Text = "Cancelled. Completed key/store/CA changes remain applied; review before retrying.";
                }
                catch (Exception error)
                {
                    // Display the complete failure in the active tool and a concise status message.
                    var messageText = CaAdministration.Error(error);
                    status.Text = messageText.Replace("\r", "").Split('\n')[0];
                    var output = tabs.SelectedIndex switch { 0 => details, 1 => tlsOutput, _ => enrollmentOutput };
                    output?.Text = "Operation failed\r\n\r\n" + messageText;
                }
                finally
                {
                    // Restore tool interaction and report completion after the operation settles.
                    record(status.Text);
                    cancellation = null;
                    tabs.IsEnabled = true;
                    cancel.IsEnabled = false;
                    UpdateContextMenu();
                }
            }
        }

        private Task<bool> Confirm(string title, string text) => Dialogs.Confirm(this, title, text);

        private void BuildInventory()
        {
            // Provide Windows store selection alongside file inspection and import actions.
            var page = Page("_Windows stores / files", out var header);
            var choose = new WrapPanel();
            header.Children.Add(choose);
            Label(choose, "Store location", location);
            Label(choose, "Store (My = Personal)", storeName);
            Dialogs.Button(choose, "_Load store", async () => await Reload())
                .VerticalAlignment = VerticalAlignment.Bottom;
            Dialogs.Button(choose, "_Open file…", async () => await OpenFile())
                .VerticalAlignment = VerticalAlignment.Bottom;
            var import = Dialogs.Button(choose, "_Import file…", async () => await ImportFile());
            import.VerticalAlignment = VerticalAlignment.Bottom;
            header.Children.Add(source);

            // Place text, expiry, and private-key filters above the inventory actions.
            var filters = new WrapPanel { Margin = new Thickness(0, 6, 0, 9) };
            header.Children.Add(filters);
            Label(filters, "Search subject, SAN, issuer, EKU or thumbprint", search);
            Label(filters, "Expiry", validity);
            Label(filters, "Private key association", keys);

            // Expose certificate details, native viewing, validation, and export actions.
            var actions = inventoryActions;
            header.Children.Add(actions);
            Dialogs.Button(actions, "_View Details", ViewCertificate).Tag = "View";
            Dialogs.Button(actions, "_Windows Certificate Viewer", ViewInWindows).Tag = "Windows";
            Dialogs.Button(actions, "CRL / chain chec_k…", ValidateSelected).Tag = "Validate";
            Dialogs.Button(actions, "_Export…", async () => await Export()).Tag = "Export";
            Dialogs.Button(actions, "Export _CSV…", async () => await Run("Exporting inventory…", async token =>
            {
                // Export only the currently filtered inventory rows to CSV.
                var save = new FilePicker(true) { Filter = "CSV|*.csv", FileName = "certificate-inventory.csv" };
                if (await save.ShowAsync() == true)
                {
                    CertificateUtilities.ExportInventory(inventory.Items.Cast<InventoryCertificate>(), save.FileName);
                    status.Text = "Exported the filtered inventory.";
                }
            })).Tag = "CSV";

            // Add private-key and store-editing actions to the inventory toolbar.
            Dialogs.Button(actions, "Test private _key", async () => await PrivateKeyTest()).Tag = "Key";
            Dialogs.Button(actions, "Friendly _Name…", async () => await EditName()).Tag = "Name";
            Dialogs.Button(actions, "_Copy / Move…", async () => await Transfer()).Tag = "Transfer";
            Dialogs.Button(actions, "_Remove…", async () => await Remove()).Tag = "Remove";
            header.Children.Add(counts);

            // Split the inventory table from its resizable details preview.
            var body = new Grid();
            body.RowDefinitions.Add(new RowDefinition { Height = new GridLength(3, GridUnitType.Star) });
            body.RowDefinitions.Add(new RowDefinition { Height = new GridLength(6) });
            body.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            var splitter = new GridSplitter { Height = 6, HorizontalAlignment = HorizontalAlignment.Stretch };
            Grid.SetRow(splitter, 1);
            Grid.SetRow(details, 2);
            body.Children.Add(inventory);
            body.Children.Add(splitter);
            body.Children.Add(details);
            page.Children.Add(body);

            // Keep inventory rows and details accessible when a narrow view or larger text expands the controls.
            Dialogs.ScrollHeader(page, header, 150);

            // Define certificate metadata columns with appropriate widths and date formatting.
            foreach (var column in new[] { new[] { "Subject", "Subject", "235" }, new[] { "Friendly Name", "FriendlyName", "160" },
                new[] { "Expiry (UTC)", "NotAfter", "145" },
                new[] { "Days left", "DaysLeft", "80" }, new[] { "Private key", "HasPrivateKey", "85" },
                new[] { "Issuer", "Issuer", "250" }, new[] { "SAN", "AlternativeNames", "260" },
                new[] { "EKU", "Purposes", "230" }, new[] { "Algorithm", "Algorithm", "100" },
                new[] { "Key bits", "KeyBits", "80" }, new[] { "Findings", "Findings", "220" },
                new[] { "Thumbprint", "Thumbprint", "330" } })
            {
                var field = new DataGridTextColumn { Header = Dialogs.Caption(column[0]), Width = int.Parse(column[2]),
                    SortMemberPath = column[1], Binding = column[1] == "NotAfter" ?
                        TimeDisplay.Binding(column[1], "yyyy-MM-dd HH:mm") : new Binding(column[1]) };
                if (column[1] == "NotAfter") TimeDisplay.Label(field, DataGridColumn.HeaderProperty, "Expiry (UTC)");
                inventory.Columns.Add(field);
            }

            // Keep the details preview synchronized with the current inventory selection.
            inventory.SelectionChanged += (sender, e) =>
            {
                TimeDisplay.Text(details, () => inventory.SelectedItem is
                    InventoryCertificate item ? CertificateUtilities.Details(item).ToString() : "");
                UpdateContextMenu();
            };
            inventory.MouseDoubleClick += (sender, e) =>
            {
                // Open the native viewer only for a double-click on one selected certificate row.
                if (cancellation != null || inventory.SelectedItems.Count != 1 ||
                    ItemsControl.ContainerFromElement(inventory, e.OriginalSource as DependencyObject) is not DataGridRow) return;
                e.Handled = true;
                ViewInWindows();
            };

            // Attach sorting feedback and certificate actions to the inventory and details preview.
            BusyCursor.OnSorting(inventory);
            Dialogs.CertificateMenu(details, () => (inventory.SelectedItem as InventoryCertificate)?.Encoded,
                ViewInWindows, () => cancellation == null && inventory.SelectedItems.Count == 1);
            BuildContextMenu();
            UpdateContextMenu();
        }

        private void BuildContextMenu()
        {
            // Group certificate inspection and export actions in the row menu.
            var menu = Dialogs.RowMenu(inventory);
            Dialogs.MenuItem(menu, "_View Details", Glyphs.Document, "View", ViewCertificate);
            Dialogs.MenuItem(menu, "Open In _Windows Certificate Viewer", Glyphs.Certificate, "Windows", ViewInWindows);
            Dialogs.MenuItem(menu, "Certificate / CRL Chec_k", Glyphs.Check, "Validate", ValidateSelected);
            Dialogs.MenuItem(menu, "_Export…", Glyphs.Save, "Export", async () => await Export());

            // Expose copy commands for the selected certificate identities.
            menu.Items.Add(new Separator());
            Dialogs.MenuItem(menu, "Copy _Thumbprints", Glyphs.Copy, "Copy thumbprints", () => Dialogs.CopyText(
                string.Join(Environment.NewLine, inventory.SelectedItems.Cast<InventoryCertificate>()
                    .Select(row => row.Thumbprint))));
            Dialogs.MenuItem(menu, "Copy _Subjects", Glyphs.Copy, "Copy subjects", () => Dialogs.CopyText(
                string.Join(Environment.NewLine, inventory.SelectedItems.Cast<InventoryCertificate>()
                    .Select(row => row.Subject))));

            // Group store mutations and private-key checks separately from general actions.
            menu.Items.Add(new Separator());
            Dialogs.MenuItem(menu, "Test Private Ke_y", Glyphs.Key, "Key", async () => await PrivateKeyTest());
            Dialogs.MenuItem(menu, "Friendly _Name…", Glyphs.Edit, "Name", async () => await EditName());
            Dialogs.MenuItem(menu, "_Copy / Move…", Glyphs.Copy, "Transfer", async () => await Transfer());
            Dialogs.MenuItem(menu, "_Remove From Store…", Glyphs.Delete, "Remove", async () => await Remove());
            menu.Items.Add(new Separator());
            Dialogs.MenuItem(menu, "Select _All", Glyphs.SelectAll, "Select all", inventory.SelectAll, "Ctrl+A");
            Dialogs.MenuItem(menu, "Re_load Store", Glyphs.Refresh, "Reload", async () => await Reload());
            menu.Opened += (sender, e) => UpdateContextMenu();
        }

        private void UpdateContextMenu()
        {
            // Keep toolbar and row-menu actions consistent with the current selection and loaded source.
            var selected = inventory.SelectedItems.Cast<InventoryCertificate>().ToArray();
            var ready = cancellation == null && inventory.IsEnabled;
            var any = ready && selected.Length > 0;
            var stored = any && loadedStore != null;
            foreach (var item in inventory.ContextMenu.Items.OfType<MenuItem>().Cast<FrameworkElement>()
                .Concat(inventoryActions.Children.OfType<Button>()))
            {
                // Require an appropriate selection and Windows store for each operation.
                switch ((string)item.Tag)
                {
                    case "View":
                    case "Windows":
                    case "Validate": item.IsEnabled = any && selected.Length == 1; break;
                    case "Export":
                    case "Copy thumbprints":
                    case "Copy subjects": item.IsEnabled = any; break;
                    case "Key": item.IsEnabled = stored && selected.Length == 1 && selected[0].HasPrivateKey; break;
                    case "Name": item.IsEnabled = stored && selected.Length == 1; break;
                    case "Transfer":
                    case "Remove": item.IsEnabled = stored; break;
                    case "Select all": item.IsEnabled = ready && inventory.Items.Count > 0; break;
                    case "Reload": item.IsEnabled = ready && loadedStore != null; break;
                    case "CSV": item.IsEnabled = ready && inventory.Items.Count > 0; break;
                }
            }
            // Hide store-only actions when browsing a file or filtering out private keys.
            bool Applicable(FrameworkElement item) => (string)item.Tag switch
            {
                "Key" => loadedStore != null && keys.SelectedIndex != 2,
                "Name" or "Transfer" or "Remove" or "Reload" => loadedStore != null,
                _ => true
            };
            foreach (var button in inventoryActions.Children.OfType<Button>())
                button.Visibility = Applicable(button) ? Visibility.Visible : Visibility.Collapsed;
            Dialogs.FilterMenu(inventory.ContextMenu, Applicable);
        }

        private StoreLocation Location =>
            location.SelectedIndex == 0 ? StoreLocation.LocalMachine : StoreLocation.CurrentUser;

        private async void SourceChanged()
        {
            // Clear the inventory immediately when the selected store or location changes.
            rows.Clear();
            loadedStore = null;
            source.Text = "";
            ApplyFilters();

            // Read the selected store automatically once the certificate workspace is visible.
            if (IsLoaded) await Reload();
        }

        private async Task Reload()
        {
            // Capture the requested Windows store and invalidate cached directory names.
            if (cancellation != null) return;
            OidNames.Invalidate();
            var target = Location;
            var name = (string)storeName.SelectedItem;
            await Run("Reading " + target + "\\" + name + "…", async token =>
            {
                // Replace inventory rows only after the complete store lookup finishes.
                rows = await Task.Run(() => CertificateUtilities.ReadStore(target, name, token, oids), token);
                loadedLocation = target;
                loadedStore = name;
                source.Text = Environment.MachineName + " · " + target + "\\" + name;
                ApplyFilters();
                status.Text = $"Loaded {rows.Count:N0} certificates. " +
                    "Private key access and trust have not been tested.";
            });
        }

        private void ApplyFilters()
        {
            // Apply all inventory filters against a common current time and update the counts.
            var now = DateTime.UtcNow;
            var filtered = rows.Where(row => row.Matches(search.Text,
                validity.SelectedIndex, keys.SelectedIndex, now)).ToList();
            inventory.ItemsSource = filtered;
            counts.Text = $"{filtered.Count:N0} shown / {rows.Count:N0} loaded · " +
                $"{rows.Count(row => row.NotAfter <= now):N0} expired · " +
                $"{rows.Count(row => row.NotAfter > now && row.NotAfter <= now.AddDays(30)):N0} expire within 30 days";
            UpdateContextMenu();
        }

        internal static Task<byte[]> ReadInput(string path, CancellationToken token) => Task.Run(() =>
        {
            // Read a bounded snapshot on a worker, checking cancellation between chunks.
            return CertificateUtilities.ReadBytes(path, token: token);
        }, token);

        private async Task OpenFile()
        {
            // Choose a certificate bundle before inspecting it in memory.
            var open = new FilePicker() { Filter = "Certificates / chains / PFX|*.cer;*.crt;*.pem;*.p7b;*.p7c;*.pfx;*.p12|All files|*.*" };
            if (await open.ShowAsync() != true) return;
            await Run("Opening certificate file…", async token =>
            {
                // Request a password only when the selected file contains a PFX.
                var bytes = await ReadInput(open.FileName, token);
                var password = "";
                var pfx = await Task.Run(() => X509Certificate2.GetCertContentType(
                    CertificateUtilities.DecodePublicPem(bytes)) == X509ContentType.Pkcs12, token);
                token.ThrowIfCancellationRequested();
                if (pfx)
                {
                    password = await Password("Open PFX", false);
                    if (password == null) return;
                }
                // Show decoded file contents as a read-only inventory with no store association.
                rows = await Task.Run(() => CertificateUtilities.ReadFile(bytes, password, token, oids), token);
                loadedStore = null;
                source.Text = "File: " + open.FileName + " · read only";
                ApplyFilters();
                status.Text = "File loaded. Private keys were opened in memory; nothing was installed.";
            });
        }

        private async Task ImportFile()
        {
            // Capture the import destination before preparing a review of the selected file.
            var open = new FilePicker() { Filter = "Certificates / chains / PFX|*.cer;*.crt;*.pem;*.p7b;*.p7c;*.pfx;*.p12" };
            if (await open.ShowAsync() != true) return;
            var target = Location;
            var name = (string)storeName.SelectedItem;
            var imported = false;
            await Run("Reading import file…", async token =>
            {
                // Decode the bundle in memory before any certificates or keys are installed.
                var bytes = await ReadInput(open.FileName, token);
                var password = "";
                var pfx = await Task.Run(() => X509Certificate2.GetCertContentType(
                    CertificateUtilities.DecodePublicPem(bytes)) == X509ContentType.Pkcs12, token);
                token.ThrowIfCancellationRequested();
                if (pfx) { password = await Password("Import PFX", false); if (password == null) return; }
                var preview = await Task.Run(() => CertificateUtilities.ReadFile(bytes, password, token, oids), token);

                // Explain the exact destination and trust impact in the import review page.
                var dialog = new WorkspacePage { Owner = this, Title = "Review Certificate Import" };
                var panel = new DockPanel { Margin = new Thickness(8) };
                var top = new StackPanel();
                DockPanel.SetDock(top, Dock.Top);
                panel.Children.Add(top);
                Dialogs.Note(top, $"Import all {preview.Count} certificate(s) into " +
                    $"{Environment.MachineName} · {target}\\{name}. Root/TrustedPeople imports change trust. " +
                    "All certificates in a bundle go into this selected store; " +
                    "the chain is not distributed among stores. Service bindings are unchanged.");

                // Offer private-key exportability only for PFX imports.
                var allowExport = Check(top, "Allow later private-key export (PFX only)");
                allowExport.IsEnabled = pfx;
                var buttons = new WrapPanel { Margin = new Thickness(0, 6, 0, 0) };
                DockPanel.SetDock(buttons, Dock.Bottom);
                panel.Children.Add(buttons);
                Dialogs.Button(buttons, "_Import", () => dialog.DialogResult = true);
                Dialogs.Button(buttons, "_Cancel", () => dialog.DialogResult = false);

                // List every certificate and key association before accepting the import.
                var list = Output();
                list.Text = string.Join("\r\n\r\n", preview.Select(row => row.Subject + "\r\n" + row.Thumbprint +
                    "\r\nPrivate key: " + row.HasPrivateKey + "; CA: " + row.IsCa));
                panel.Children.Add(list);
                dialog.Content = panel;
                if (await dialog.ShowAsync() != true) return;

                // Import the reviewed bundle with the chosen key policy and show per-certificate results.
                var canExport = allowExport.IsChecked == true;
                var report = await Task.Run(() =>
                    CertificateUtilities.Import(bytes, password, target, name, canExport, token));
                imported = true;
                record(report);
                Dialogs.Report(this, "Import results", report);
                status.Text = "Import finished. Review individual results for failures or cancellation.";
            });
            if (imported) await Reload();
        }

        private InventoryCertificate Selected()
        {
            // Require an unambiguous single certificate for inspection actions.
            if (inventory.SelectedItems.Count != 1) throw new ArgumentException("Select one certificate.");
            return (InventoryCertificate)inventory.SelectedItem;
        }

        private async void ViewCertificate()
        {
            // Open decoded details for the selected inventory certificate.
            try
            {
                await Dialogs.Certificate(this, Selected().Encoded, oids);
            }
            catch (Exception error) { status.Text = CaAdministration.Error(error); }
        }

        private void ViewInWindows()
        {
            // Avoid opening the native viewer during another certificate operation.
            if (cancellation != null) return;
            try
            {
                // Use the live store certificate when available so the viewer sees its key association.
                var certificate = Selected();
                if (loadedStore == null) { Dialogs.WindowsCertificate(this, certificate.Encoded); return; }
                CertificateUtilities.WithCertificate(loadedLocation, loadedStore, certificate.Thumbprint, false,
                    (store, value) => { Dialogs.WindowsCertificate(this, value); return true; });
            }
            catch (Exception error) { status.Text = CaAdministration.Error(error); }
        }

        private void ValidateSelected()
        {
            // Open validation with the selected certificate and its source context.
            try { new ValidationWindow(Selected().Encoded, source.Text, oids) { Owner = this }.Show(); }
            catch (Exception error) { status.Text = CaAdministration.Error(error); }
        }

        private async Task PrivateKeyTest() => await Run("Testing private key access…", async token =>
        {
            // Require an installed key and confirm the signing challenge before testing access.
            var selected = Selected();
            if (loadedStore == null)
                throw new ArgumentException("Load a Windows store to test the installed private key.");
            if (!await Confirm("Test private key", "Sign and verify a random challenge using " + selected.Subject +
                "? A hardware key provider may request its PIN.")) return;
            details.Text = await Task.Run(() => CertificateUtilities.WithCertificate(loadedLocation, loadedStore,
                selected.Thumbprint, false, (store, certificate) =>
                    CertificateUtilities.TestPrivateKey(certificate)), token);
            status.Text = details.Text;
        });

        private async Task EditName()
        {
            // Track whether a friendly-name change requires the inventory to reload.
            var changed = false;
            await Run("Editing certificate name…", async token =>
            {
                // Edit the selected store certificate friendly name without changing its signed contents.
                if (loadedStore == null) throw new ArgumentException("Load a Windows store first.");
                var selected = Selected();
                var name = await Dialogs.Prompt(this, "Edit Friendly Name", "Friendly Name", selected.FriendlyName);
                if (name == null) return;
                await Task.Run(() => CertificateUtilities.WithCertificate(loadedLocation, loadedStore,
                    selected.Thumbprint, true, (store, certificate) => { certificate.FriendlyName = name; return true; }), token);
                changed = true;
                status.Text = "Friendly name updated. The signed certificate is unchanged.";
            });
            if (changed) await Reload();
        }

        private async Task Transfer()
        {
            // Track completed transfers so the source inventory can be refreshed.
            var changed = false;
            await Run("Preparing certificate transfer…", async token =>
            {
                // Require selected store certificates and explain the copy or move consequences.
                if (loadedStore == null) throw new ArgumentException("Load a Windows store first.");
                var selected = inventory.SelectedItems.Cast<InventoryCertificate>().ToArray();
                if (selected.Length == 0) throw new ArgumentException("Select certificates to copy or move.");
                var page = new WorkspacePage { Owner = this, Title = "Copy Or Move Certificates" };
                var panel = new StackPanel { Margin = new Thickness(8) };
                Dialogs.Note(panel, $"{selected.Length} certificate(s) from {loadedLocation}\\{loadedStore}. " +
                    "Private key associations stay in the same machine/user context. " +
                    "Moving removes the source copy only after the destination is verified. " +
                    "Root/TrustedPeople imports change trust; service bindings are not updated.");

                // Offer a different destination store and an explicit copy or move mode.
                panel.Children.Add(Glyphs.Label("Destination Store (My = Personal)"));
                var destination = new ComboBox { ItemsSource = CertificateUtilities.StoreNames.Where(name =>
                    !string.Equals(name, loadedStore, StringComparison.OrdinalIgnoreCase)).ToArray(),
                    SelectedIndex = 0, Width = 240, HorizontalAlignment = HorizontalAlignment.Left };
                panel.Children.Add(destination);
                var mode = new ComboBox { ItemsSource = new[] { "Copy", "Move" }, SelectedIndex = 0,
                    Width = 120, HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(0, 6, 0, 6) };
                panel.Children.Add(mode);

                // Review selected certificate identities before starting the transfer.
                Dialogs.Note(panel, string.Join("\r\n", selected.Take(12).Select(row => row.Subject + " · " + row.Thumbprint)));
                var buttons = new WrapPanel();
                panel.Children.Add(buttons);
                Dialogs.Button(buttons, "_Continue", () => page.DialogResult = true);
                Dialogs.Button(buttons, "_Cancel", page.Close);
                page.Content = new ScrollViewer { Content = panel, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
                if (await page.ShowAsync() != true) return;

                // Execute the chosen transfer in the background and report individual outcomes.
                var target = (string)destination.SelectedItem;
                var move = mode.SelectedIndex == 1;
                var report = await Task.Run(() => CertificateUtilities.Transfer(loadedLocation, loadedStore, target,
                    selected.Select(row => row.Thumbprint), move, token));
                changed = true;
                record(report);
                Dialogs.Report(this, "Certificate Transfer Results", report);
                status.Text = "Transfer finished. Review individual results for failures or cancellation.";
            });
            if (changed) await Reload();
        }

        private async Task Remove()
        {
            // Track completed removal work so the displayed store can be reloaded.
            var changed = false;
            await Run("Removing selected certificates…", async token =>
            {
                // Confirm the selected store certificates and the scope of their removal.
                if (loadedStore == null) throw new ArgumentException("Load a Windows store first.");
                var selected = inventory.SelectedItems.Cast<InventoryCertificate>().ToArray();
                if (selected.Length == 0) throw new ArgumentException("Select certificates to remove.");
                if (!await Confirm("Remove certificates", $"Remove {selected.Length} certificate(s) " +
                    $"from {loadedLocation}\\{loadedStore}?\r\n" +
                    string.Join("\r\n", selected.Take(12).Select(row => row.Subject + " · " + row.Thumbprint)) +
                    "\r\nThis may break trust or service bindings. " +
                    "It does not revoke certificates or delete their private keys.")) return;

                // Remove certificates independently while retaining failures and cancellation in the report.
                var report = await Task.Run(() =>
                {
                    var text = new StringBuilder();
                    foreach (var row in selected)
                    {
                        if (token.IsCancellationRequested)
                        { text.AppendLine("Cancelled; remaining certificates were not attempted."); break; }
                        try
                        {
                            CertificateUtilities.WithCertificate(loadedLocation, loadedStore, row.Thumbprint, true,
                                (store, certificate) => { store.Remove(certificate); return true; });
                            text.AppendLine(row.Thumbprint + ": Removed");
                        }
                        catch (Exception error)
                        { text.AppendLine(row.Thumbprint + ": FAILED — " + CaAdministration.Error(error)); }
                    }
                    return text.ToString();
                });

                // Present the completed removal report before refreshing the inventory.
                changed = true;
                record(report);
                Dialogs.Report(this, "Removal results", report);
                status.Text = "Removal finished; see individual results.";
            });
            if (changed) await Reload();
        }

        private async Task Export() => await Run("Exporting certificate…", async token =>
        {
            // Choose an export format for a nonempty certificate selection.
            var selected = inventory.SelectedItems.Cast<InventoryCertificate>().ToArray();
            if (selected.Length == 0) throw new ArgumentException("Select certificates to export.");
            var save = new FilePicker(true) { FileName = "certificate.cer", Filter =
                "DER certificate (one)|*.cer|PEM certificate(s)|*.pem|PKCS #7 certificate(s)|*.p7b|PFX with private key (one)|*.pfx" };
            if (await save.ShowAsync() != true) return;
            byte[] bytes;
            if (save.FilterIndex == 4)
            {
                // Require one installed private key and a confirmed password for PFX export.
                if (loadedStore == null || selected.Length != 1 || !selected[0].HasPrivateKey)
                    throw new ArgumentException("Select one certificate with a private key in a loaded Windows store.");
                var password = await Password("Protect the exported PFX", true);
                if (password == null) return;
                bytes = await Task.Run(() => CertificateUtilities.WithCertificate(loadedLocation, loadedStore,
                    selected[0].Thumbprint, false, (store, certificate) =>
                        certificate.Export(X509ContentType.Pfx, password)), token);
            }
            // Write the export atomically and clear private-key export bytes from memory afterward.
            else bytes = CertificateUtilities.ExportPublic(selected.Select(row => row.Encoded), save.FilterIndex - 1);
            try { CertificateUtilities.WriteAtomic(save.FileName, bytes); }
            finally { if (save.FilterIndex == 4) Array.Clear(bytes, 0, bytes.Length); }
            status.Text = "Exported " + save.FileName +
                (save.FilterIndex == 4 ? " (selected certificate and key; no issuer chain)." : ".");
        });

        private async Task<string> Password(string title, bool confirm)
        {
            // Build an in-workspace password form with optional confirmation.
            var window = new WorkspacePage { Owner = this, Title = Dialogs.Caption(title) };
            var panel = new StackPanel { Margin = new Thickness(8) };
            Dialogs.Note(panel, confirm ? "Enter and confirm a nonempty password." :
                "Enter the file password (may be empty).");
            var password = new PasswordBox { Margin = new Thickness(0, 0, 0, 6) };
            var repeat = new PasswordBox { Margin = new Thickness(0, 0, 0, 6) };

            // Apply current theme colors to the masked password inputs.
            foreach (var box in new[] { password, repeat })
            {
                box.SetResourceReference(BackgroundProperty, "Surface");
                box.SetResourceReference(ForegroundProperty, "Ink");
                box.SetResourceReference(BorderBrushProperty, "Border");
            }
            // Show confirmation only when required and provide inline validation feedback.
            panel.Children.Add(password);
            if (confirm) panel.Children.Add(repeat);
            var hint = new TextBlock { TextWrapping = TextWrapping.Wrap };
            panel.Children.Add(hint);
            var buttons = new WrapPanel { Margin = new Thickness(0, 6, 0, 0) };
            panel.Children.Add(buttons);
            Dialogs.Button(buttons, "_Continue", () =>
            {
                // Require matching nonempty passwords when protecting a new PFX export.
                if (confirm && (password.Password.Length == 0 || password.Password != repeat.Password))
                { hint.Text = "Passwords must match and cannot be empty."; return; }
                window.DialogResult = true;
            }).IsDefault = true;

            // Return only an accepted password and clear both input controls afterward.
            Dialogs.Button(buttons, "_Cancel", () => window.DialogResult = false);
            window.Content = panel;
            window.Loaded += (sender, e) => password.Focus();
            var result = await window.ShowAsync() == true ? password.Password : null;
            password.Clear();
            repeat.Clear();
            return result;
        }

        private void BuildTls()
        {
            // Collect the connection address, TLS server name, and timeout for the endpoint check.
            var page = Page("_TLS endpoint", out var header);
            Dialogs.Note(header, "Check the certificate a service currently presents. " +
                "Use a direct TLS port such as HTTPS 443 or LDAPS 636.");
            var fields = new WrapPanel();
            header.Children.Add(fields);
            endpoint = new TextBox { Width = 235 };
            port = new TextBox { Text = "443", Width = 75 };
            serverName = new TextBox { Width = 235 };
            timeout = new TextBox { Text = "15", Width = 75 };
            Label(fields, "Connect to DNS name / IP", endpoint);
            Label(fields, "Port", port);
            Label(fields, "SNI / expected name (optional)", serverName);
            Label(fields, "Timeout (s)", timeout);

            // Allow expected-certificate comparison and Windows revocation checking.
            expected = Dialogs.Field(header, "Expected SHA-1 or SHA-256 thumbprint (optional; verifies deployment)");
            var options = new WrapPanel { Margin = new Thickness(0, 6, 0, 0) };
            header.Children.Add(options);
            checkRevocation = Check(options, "Check revocation with Windows", true);

            // Expose endpoint validation and deeper certificate revocation diagnostics.
            var actions = new WrapPanel();
            header.Children.Add(actions);
            Dialogs.Button(actions, "_Check endpoint", async () => await CheckEndpoint());
            Dialogs.Button(actions, "CRL / chain _details…", () =>
            {
                // Pass the presented TLS certificate into the certificate validation workspace.
                if (tlsResult?.Certificate == null)
                { status.Text = "Check an endpoint that presents a certificate first."; return; }
                new ValidationWindow(tlsResult.Certificate, "TLS endpoint", oids) { Owner = this }.Show();
            });

            // Provide certificate, chain, and report exports from the last endpoint result.
            Dialogs.Button(actions, "Export _certificate…", async () => await SaveTls(false));
            Dialogs.Button(actions, "Export _chain…", async () => await SaveTls(true));
            Dialogs.Button(actions, "_Save report…", async () => await SaveText(tlsOutput.Text, "tls-report.txt"));
            tlsOutput = Output();
            Dialogs.CertificateMenu(tlsOutput, () => tlsResult?.Certificate);
            page.Children.Add(tlsOutput);
        }

        private async Task CheckEndpoint() => await Run("Connecting and validating TLS…", async token =>
        {
            // Clear the prior endpoint result and capture validated connection settings.
            tlsResult = null;
            tlsOutput.Clear();
            if (!int.TryParse(port.Text, out var targetPort) || !int.TryParse(timeout.Text, out var seconds))
                throw new ArgumentException("Enter a numeric port and timeout.");
            var host = endpoint.Text;
            var name = serverName.Text;
            var hash = expected.Text;
            var revocation = checkRevocation.IsChecked == true;

            // Run the TLS probe asynchronously and summarize validation and fingerprint matching.
            tlsResult = await Task.Run(() => CertificateUtilities.Probe(host, targetPort, name,
                revocation, seconds, hash, token, oids), token);
            var report = tlsResult.Report;
            TimeDisplay.Text(tlsOutput, () => report.ToString());
            status.Text = tlsResult.HandshakeCompleted ?
                (tlsResult.ExpectedCertificateMatches == false ? "TLS passed; expected certificate MISMATCH." :
                    "TLS validation passed." + (revocation ? "" : " Revocation was not checked.")) :
                "TLS validation failed or the endpoint could not be reached. See the report.";
        });

        private async Task SaveTls(bool chain)
        {
            try
            {
                // Require a captured endpoint certificate before choosing its export destination.
                if (tlsResult?.Certificate == null)
                    throw new ArgumentException("No endpoint certificate is available.");
                var save = new FilePicker(true) { FileName = chain ? "tls-chain.p7b" : "tls-certificate.cer",
                    Filter = chain ? "PKCS #7|*.p7b" : "DER certificate|*.cer" };
                if (await save.ShowAsync() != true) return;

                // Export the collected chain or leaf certificate and save it atomically.
                var bytes = chain ? CertificateUtilities.ExportPublic(tlsResult.Chain.Count > 0 ?
                    tlsResult.Chain : new List<byte[]> { tlsResult.Certificate }, 2) : tlsResult.Certificate;
                CertificateUtilities.WriteAtomic(save.FileName, bytes);
                status.Text = "Saved " + save.FileName;
            }
            catch (Exception error) { status.Text = CaAdministration.Error(error); }
        }

        private void BuildEnrollment(string config)
        {
            // Arrange enrollment settings above response actions and diagnostic output.
            var page = Page("_Request / install", out var header);
            page.Children.Remove(header);
            var body = new Grid();
            body.RowDefinitions.Add(new RowDefinition { Height = new GridLength(3, GridUnitType.Star) });
            body.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            body.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star), MinHeight = 110 });
            Grid.SetRow(header, 1);
            body.Children.Add(header);
            page.Children.Add(body);

            // Create a scrolling request form and explain the key context requirements.
            var form = new StackPanel();
            var scroll = new ScrollViewer { Content = form, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
            body.Children.Add(scroll);
            Dialogs.Note(form, "Create a PKCS #10 CSR here, submit it to AD CS, then accept the issued response " +
                "on the same machine and key context. " +
                "Renewing a certificate does not automatically update service bindings.");

            // Collect subject, alternative names, and the requested key algorithm.
            subject = Dialogs.Field(form, "X.500 subject", "CN=server.example.com", width: 640);
            var names = new WrapPanel { Margin = new Thickness(0, 6, 0, 0) };
            form.Children.Add(names);
            dns = new TextBox { Width = 280, Height = 50, AcceptsReturn = true, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
            ips = new TextBox { Width = 180, Height = 50, AcceptsReturn = true, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
            algorithm = new ComboBox { Width = 165, SelectedIndex = 1,
                ItemsSource = new[] { "RSA 2048", "RSA 3072", "RSA 4096", "ECDSA P-256", "ECDSA P-384" } };
            Label(names, "DNS SANs (one per line)", dns);
            Label(names, "IP SANs (one per line)", ips);
            Label(names, "Key", algorithm);

            // Collect key storage, exportability, usage, and template settings.
            var options = new WrapPanel();
            form.Children.Add(options);
            machine = Check(options, "Machine key", true);
            exportable = Check(options, "Allow encrypted key export");
            serverAuth = Check(options, "Server authentication", true);
            clientAuth = Check(options, "Client authentication");
            template = Dialogs.Field(form, "AD CS template internal name or OID (optional)");

            // Provide request-settings preview and CSR creation actions.
            var generate = new WrapPanel { Margin = new Thickness(0, 6, 0, 0) };
            form.Children.Add(generate);
            Dialogs.Button(generate, "_Preview / save settings…", () =>
            {
                // Render validated request options as the INF that will drive certificate enrollment.
                try { Dialogs.Report(this, "Certificate request settings (INF)", Options().CreateInf()); }
                catch (Exception error) { status.Text = CaAdministration.Error(error); }
            });
            Dialogs.Button(generate, "_Create CSR…", async () => await CreateCsr());

            // Collect the target CA and an existing request file for submission.
            configuration = Dialogs.Field(form, "Certificate authority · SERVER\\CA name", config, width: 440);
            requestPath = Dialogs.Field(form, "PKCS #10 request file", width: 640);
            var submit = new WrapPanel { Margin = new Thickness(0, 6, 0, 0) };
            form.Children.Add(submit);
            Dialogs.Button(submit, "_Browse request…", async () =>
            {
                // Populate the request path from the chosen CSR file.
                var open = new FilePicker() { Filter = "Certificate request|*.req;*.csr;*.pem|All files|*.*" };
                if (await open.ShowAsync() == true) requestPath.Text = open.FileName;
            });
            Dialogs.Button(submit, "_Submit request…", async () => await SendRequest(false));

            // Pair a request ID input with retrieval of pending or issued responses.
            var request = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 6, 4) };
            submit.Children.Add(request);
            requestId = new TextBox { Width = 95, ToolTip = "Pending or issued request ID" };
            var requestLabel = Glyphs.Label("Request ID", true);
            requestLabel.Target = requestId;
            request.Children.Add(requestLabel);
            request.Children.Add(requestId);
            Dialogs.Button(submit, "_Retrieve", async () => await SendRequest(true));

            // Place issued-response actions between the request form and enrollment output.
            var actions = new WrapPanel { Margin = new Thickness(0, 10, 0, 0) };
            header.Children.Add(actions);
            Dialogs.Button(actions, "Save issued _certificate…", async () =>
            {
                // Save an issued certificate only when the last enrollment returned one.
                if (enrollmentResult?.Certificate == null) { status.Text = "No issued response is available."; return; }
                var save = new FilePicker(true) { Filter = "DER certificate|*.cer", FileName = "issued.cer" };
                if (await save.ShowAsync() != true) return;
                try { CertificateUtilities.WriteAtomic(save.FileName, enrollmentResult.Certificate); }
                catch (Exception error) { status.Text = CaAdministration.Error(error); }
            });

            // Provide response installation, log export, and certificate viewing from enrollment results.
            Dialogs.Button(actions, "_Accept response file…", async () => await AcceptResponse());
            Dialogs.Button(actions, "Save _log…", async () => await SaveText(enrollmentOutput.Text, "enrollment-log.txt"));
            enrollmentOutput = Output();
            Dialogs.CertificateMenu(enrollmentOutput, () => enrollmentResult?.Certificate);
            Grid.SetRow(enrollmentOutput, 2);
            body.Children.Add(enrollmentOutput);
        }

        private CsrOptions Options() => new CsrOptions
        {
            Subject = subject.Text.Trim(), DnsNames = dns.Text, IpAddresses = ips.Text, Template = template.Text.Trim(),
            Algorithm = (string)algorithm.SelectedItem, Machine = machine.IsChecked == true,
            Exportable = exportable.IsChecked == true, ServerAuthentication = serverAuth.IsChecked == true,
            ClientAuthentication = clientAuth.IsChecked == true
        };

        private async Task CreateCsr() => await Run("Creating certificate request…", async token =>
        {
            // Validate request settings and confirm key creation before generating the CSR.
            var options = Options();
            var inf = options.CreateInf();
            var save = new FilePicker(true) { FileName = "certificate.req", Filter = "Certificate request|*.req;*.csr" };
            if (await save.ShowAsync() != true) return;
            if (!await Confirm("Create private key and CSR", "Create a new " + options.Algorithm + " key in the " +
                (options.Machine ? "LOCAL MACHINE" : "CURRENT USER") + " context on " + Environment.MachineName +
                "?\r\n\r\n" + inf)) return;

            // Keep the generated CSR path ready for submission and show the creation output.
            enrollmentOutput.Text = await Enrollment.CreateRequest(inf, save.FileName, token);
            requestPath.Text = save.FileName;
            status.Text = "CSR created. The private key remains in Windows; submit the request when ready.";
        });

        private async Task SendRequest(bool retrieve) => await Run(
            retrieve ? "Retrieving request…" : "Submitting request…", async token =>
        {
            // Validate the CA target and request ID or file before submitting or retrieving.
            var config = configuration.Text.Trim();
            new CertificateStore(config);
            var id = 0;
            if (retrieve && (!int.TryParse(requestId.Text, out id) || id < 1))
                throw new ArgumentException("Enter a positive request ID.");

            // Confirm new submissions with their selected template before contacting the CA.
            var bytes = retrieve ? null : await ReadInput(requestPath.Text, token);
            var templateName = template.Text.Trim();
            if (!retrieve && !await Confirm("Submit request to AD CS", "CA: " + config + "\r\nRequest: " + requestPath.Text +
                "\r\nTemplate: " + (templateName.Length == 0 ? "From request / CA policy" : templateName))) return;

            // Clear stale enrollment output and publish the complete CA response.
            enrollmentResult = null;
            enrollmentOutput.Clear();
            enrollmentResult = await Task.Run(() => Enrollment.Request(config, bytes, id, templateName), token);
            requestId.Text = enrollmentResult.RequestId.ToString();
            enrollmentOutput.Text = enrollmentResult.Report;
            record(enrollmentResult.Report);
            status.Text = "Request " + enrollmentResult.RequestId + ": " +
                CaAdministration.RequestDisposition(enrollmentResult.Disposition);
        });

        private async Task AcceptResponse()
        {
            // Confirm response installation in the original user or machine key context.
            var open = new FilePicker() { Filter = "Certificate / chain response|*.cer;*.crt;*.p7b;*.p7c;*.pem|All files|*.*" };
            if (await open.ShowAsync() != true) return;
            var context = machine.IsChecked == true ? "-machine" : "-user";
            if (!await Confirm("Accept issued response", "Install " + open.FileName +
                " and associate it with the matching private key in the " +
                (context == "-machine" ? "LOCAL MACHINE" : "CURRENT USER") +
                " context?\r\nRun this on the CSR's original machine. " +
                "Service bindings must be updated separately.")) return;
            await Run("Accepting certificate response…", async token =>
            {
                // Accept the response through certreq and explain where to inspect the installed key pair.
                enrollmentOutput.Text = await Enrollment.RunCertReq("-accept -q " + context + " " +
                    ToolWindow.QuoteArgument(Path.GetFullPath(open.FileName)), token);
                status.Text = "Response accepted. Reload the Personal store to inspect the certificate and key.";
            });
        }

        private async Task SaveText(string text, string filename)
        {
            // Save diagnostic or enrollment text atomically to the selected file.
            var save = new FilePicker(true) { FileName = filename, Filter = "Text / INF|*.txt;*.inf|All files|*.*" };
            if (await save.ShowAsync() != true) return;
            try { CertificateUtilities.WriteAtomic(save.FileName, Encoding.UTF8.GetBytes(text)); }
            catch (Exception error) { status.Text = CaAdministration.Error(error); }
        }
    }
}
