//
// Copyright (c) Bryan Berns.
// Licensed under GPLv3. See LICENSE.md.
//

using System;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;

namespace Certitude
{
    internal sealed class OidManagerPage : WorkspacePage
    {
        private readonly DockPanel layout = new DockPanel { Margin = new Thickness(8) };
        private readonly TextBox server = new TextBox { Width = 360, Margin = new Thickness(0, 0, 8, 4) };
        private readonly TextBox search = new TextBox { Width = 340, Margin = new Thickness(0, 0, 0, 4) };
        private readonly ComboBox kind = new ComboBox { Width = 165 };
        private readonly TextBlock target = new TextBlock { TextWrapping = TextWrapping.Wrap };
        private readonly TextBlock status = new TextBlock { TextWrapping = TextWrapping.Wrap };
        private readonly TextBox details = new TextBox { IsReadOnly = true, AcceptsReturn = true, Height = 116,
            TextWrapping = TextWrapping.Wrap, VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            VerticalContentAlignment = VerticalAlignment.Top, Margin = new Thickness(0, 5, 0, 5) };
        private readonly DataGrid grid = new DataGrid { SelectionMode = DataGridSelectionMode.Single };
        private readonly Button add;
        private readonly Button remove;
        private readonly Action<string> record;
        private OidDirectory directory;
        private DirectoryOid[] rows = Array.Empty<DirectoryOid>();
        private bool initialized;
        internal bool IsBusy
        {
            get;
            // Keep directory controls disabled for the complete lifetime of an operation.
            private set { field = value; layout.IsEnabled = !value; }
        }

        public OidManagerPage(Action<string> log = null)
        {
            // Create the directory management page with its explanation and connection target.
            record = log ?? (text => { });
            Title = "OID Manager";
            var header = new StackPanel();
            DockPanel.SetDock(header, Dock.Top);
            layout.Children.Add(header);
            Dialogs.Note(header, "Review forest OIDs and manage custom application and issuance policies using your " +
                "Windows identity. Directory changes require permission to manage the forest's OIDs.");

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

            // Expose refresh and selected-policy actions above the result filters.
            var actions = new WrapPanel { Margin = new Thickness(0, 6, 0, 0) };
            header.Children.Add(actions);
            Dialogs.Button(actions, "_Refresh", async () => await Refresh());
            add = Dialogs.Button(actions, "_Add OID", async () => await Add());
            remove = Dialogs.Button(actions, "Remo_ve OID", async () => await Remove());
            Dialogs.Button(actions, "_Copy OID", () => Dialogs.CopyText((grid.SelectedItem as DirectoryOid)?.Value));

            // Combine the OID type filter with a text search across policy metadata.
            var filters = new WrapPanel { Margin = new Thickness(0, 6, 0, 11) };
            kind.Margin = new Thickness(0, 0, 8, 4);
            kind.ItemsSource = new[] { "All OIDs", "Application Policy", "Issuance Policy", "Certificate Template",
                "Other / Forest OID" };
            kind.SelectedIndex = 0;
            filters.Children.Add(kind);
            var label = Glyphs.Label("Search", true);
            label.Target = search;
            label.Margin = new Thickness(0, 0, 6, 4);
            filters.Children.Add(label);
            filters.Children.Add(search);
            search.ToolTip = "Filter by display name, numeric OID, type, template or distinguished name.";
            header.Children.Add(filters);

            // Keep selection details and status visible beneath the OID grid.
            var footer = new StackPanel();
            DockPanel.SetDock(footer, Dock.Bottom);
            layout.Children.Add(footer);
            footer.Children.Add(details);
            footer.Children.Add(status);

            // Show the key policy fields in a sortable result table.
            Column("Display Name", nameof(DirectoryOid.Name), 2);
            Column("OID", nameof(DirectoryOid.Value), 3);
            Column("Type", nameof(DirectoryOid.Kind), 1.4);
            Column("Refs", nameof(DirectoryOid.TemplateCount), .7);
            BusyCursor.OnSorting(grid);
            layout.Children.Add(grid);
            Content = layout;

            // Refresh filtering and selection state as the user edits the controls.
            search.TextChanged += (sender, e) => Filter();
            kind.SelectionChanged += (sender, e) => Filter();
            grid.SelectionChanged += (sender, e) => SelectionChanged();
            server.TextChanged += (sender, e) =>
            {
                // Clear stale results immediately when the directory target changes.
                directory = null;
                rows = Array.Empty<DirectoryOid>();
                target.Text = "";
                Filter();
                status.Text = "Load The Directory To Review Its OIDs.";
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
                // Provide keyboard shortcuts for refreshing and removing the selected OID.
                if (e.Key == Key.F5) { e.Handled = true; await Refresh(); }
                if (e.Key == Key.Delete && grid.IsKeyboardFocusWithin)
                { e.Handled = true; await Remove(); }
            };

            // Prevent navigation during writes and load the directory on the first visit.
            Closing += (sender, e) => e.Cancel = IsBusy;
            Loaded += async (sender, e) =>
            {
                if (initialized) return;
                initialized = true;
                await Refresh(true);
            };
            SelectionChanged();
        }

        private void Column(string header, string property, double width) => grid.Columns.Add(
            new DataGridTextColumn { Header = header, Binding = new Binding(property),
                Width = new DataGridLength(width, DataGridLengthUnitType.Star) });

        private void Filter(Guid? select = null)
        {
            // Filter cached rows by type and text while preserving the selected object.
            var selected = select ?? (grid.SelectedItem as DirectoryOid)?.Id;
            var text = search.Text.Trim();
            var items = rows.Where(row => (kind.SelectedIndex <= 0 || row.Kind == (string)kind.SelectedItem) &&
                new[] { row.Name, row.Value, row.Kind, row.DistinguishedName, string.Join(" ", row.Templates) }
                    .Any(value => value.IndexOf(text, StringComparison.OrdinalIgnoreCase) >= 0)).ToArray();

            // Publish filtered results and refresh the visible counts and action state.
            grid.ItemsSource = items;
            grid.SelectedItem = items.FirstOrDefault(row => row.Id == selected);
            status.Text = $"{items.Length:N0} Of {rows.Length:N0} OIDs · {rows.Count(row => row.CanRemove):N0} " +
                "Unreferenced Custom Policies";
            SelectionChanged();
        }

        private void SelectionChanged()
        {
            // Enable actions only for an available directory and a removable selection.
            var selected = grid.SelectedItem as DirectoryOid;
            search.IsEnabled = kind.IsEnabled = directory != null && !IsBusy;
            add.IsEnabled = directory != null && !IsBusy;
            remove.IsEnabled = directory != null && !IsBusy && selected?.CanRemove == true;
            remove.ToolTip = selected?.RemovalBlock;

            // Explain the selected registration and the references that affect removal.
            details.Text = selected == null ? "Select An OID To Review Its Directory Object And Template References." :
                selected.Name + "\r\nOID: " + selected.Value + "\r\nType: " + selected.Kind +
                "\r\nDirectory Object: " + selected.DistinguishedName + "\r\n" +
                (selected.CanRemove ? "No Template References Or AD Group Link Found On This Domain Controller." :
                    selected.RemovalBlock) +
                (selected.Templates.Length == 0 ? "" : "\r\nTemplate References:\r\n" +
                    string.Join("\r\n", selected.Templates)) +
                (string.IsNullOrEmpty(selected.GroupLink) ? "" : "\r\nAD Group: " + selected.GroupLink) +
                (selected.LocalizedNames.Length == 0 ? "" : "\r\nLocalized Names: " +
                    string.Join("; ", selected.LocalizedNames)) +
                (selected.PolicyStatements.Length == 0 ? "" : "\r\nPolicy Statements: " +
                    string.Join("; ", selected.PolicyStatements));
        }

        private async Task Run(string message, Func<Task> action)
        {
            // Serialize directory work and show its progress without blocking the UI thread.
            if (IsBusy) return;
            using var cursor = BusyCursor.Enter();
            IsBusy = true;
            status.Text = message;
            try { await action(); }
            catch (Exception error) { status.Text = CaAdministration.Error(error); }
            finally
            {
                // Restore interaction and selection state after success or failure.
                IsBusy = false;
                SelectionChanged();
                record(status.Text);
            }
        }

        private Task Refresh(bool reconnect = false, Guid? selected = null) => Run("Reading Active Directory OIDs…",
            async () =>
            {
                // Capture the requested target and clear results before the asynchronous lookup.
                var previous = reconnect ? null : directory;
                var requested = server.Text.Trim();
                selected ??= reconnect ? null : (grid.SelectedItem as DirectoryOid)?.Id;
                directory = null;
                rows = Array.Empty<DirectoryOid>();
                grid.ItemsSource = null;
                target.Text = "";

                // Load a complete directory snapshot before restoring results and selection.
                var connection = previous ?? await Task.Run(() => OidDirectory.Connect(requested));
                rows = await Task.Run(connection.Read);
                directory = connection;
                target.Text = "Domain Controller: " + directory.Server + "\r\nForest: " + directory.ConfigurationName;
                Filter(selected);
            });

        private async Task Add()
        {
            // Open the add form and select the newly created registration after refreshing.
            if (IsBusy || directory == null) return;
            var dialog = new AddOidPage(directory) { Owner = this };
            if (await dialog.ShowAsync() != true) return;
            await Refresh(false, dialog.AddedId);
            status.Text = "OID Added To Active Directory. " + status.Text;
            record(status.Text);
        }

        private async Task Remove()
        {
            // Require a removable selection and confirm its directory identity and impact.
            if (IsBusy || directory == null ||
                grid.SelectedItem is not DirectoryOid selected || !selected.CanRemove) return;
            var connection = directory;
            if (!await Dialogs.Confirm(this, "Remove OID From Active Directory",
                "Domain Controller: " + connection.Server + "\r\nForest: " + connection.ConfigurationName +
                "\r\n\r\n" + selected.Name + "\r\nOID: " +
                selected.Value + "\r\nType: " + selected.Kind + "\r\nDirectory Object: " + selected.DistinguishedName +
                "\r\n\r\nPermanently remove this forest OID registration? Template references and AD group links " +
                "will be checked again before removal. Issued certificates are not changed. Other applications " +
                "or certificates may still use this OID; directory checks cannot detect that usage.")) return;

            // Remove the registration in the background and drop it from the cached view.
            var removed = false;
            await Run("Removing OID From Active Directory…", async () =>
            {
                await Task.Run(() => connection.Remove(selected));
                removed = true;
                rows = rows.Where(row => row.Id != selected.Id).ToArray();
                Filter();
            });

            // Reload directory references after a successful removal.
            if (!removed) return;
            await Refresh();
            status.Text = "OID Removed From Active Directory. " + status.Text;
            record(status.Text);
        }
    }

    internal sealed class AddOidPage : WorkspacePage
    {
        private bool saving;
        internal bool IsBusy => saving;
        internal Guid AddedId { get; private set; }

        public AddOidPage(OidDirectory directory)
        {
            // Create a footer for save controls and inline directory errors.
            Title = "Add OID To Active Directory";
            var layout = new DockPanel { Margin = new Thickness(8) };
            var footer = new StackPanel();
            DockPanel.SetDock(footer, Dock.Bottom);
            layout.Children.Add(footer);
            var status = new TextBlock { TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 6, 0, 6) };
            footer.Children.Add(status);
            var buttons = new WrapPanel();
            footer.Children.Add(buttons);

            // Collect the policy name, numeric OID, and registration type.
            var form = new StackPanel();
            Dialogs.Note(form, "Domain Controller: " + directory.Server + "\r\nForest: " + directory.ConfigurationName);
            var name = Dialogs.Field(form, "Display Name", width: 360);
            name.MaxLength = 256;
            var oid = Dialogs.Field(form, "Numeric OID", width: 400);
            var policyLabel = Glyphs.Label("Policy Type");
            policyLabel.Margin = new Thickness(0, 5, 0, 3);
            form.Children.Add(policyLabel);
            var kind = new ComboBox { ItemsSource = new[] { "Application Policy (Enhanced Key Usage)", "Issuance Policy" },
                SelectedIndex = 0, Width = 320, HorizontalAlignment = HorizontalAlignment.Left };
            form.Children.Add(kind);

            // Explain registration scope and place the form in a scrollable workspace.
            Dialogs.Note(form, "Use an OID assigned to your organization. This creates a forest policy registration; " +
                "assign the policy to certificate templates separately. Changes replicate through Active Directory.");
            layout.Children.Add(new ScrollViewer { Content = form, VerticalScrollBarVisibility = ScrollBarVisibility.Auto });
            Dialogs.Button(buttons, "_Add To AD", async () =>
            {
                // Prevent duplicate submissions while the directory write is running.
                if (saving) return;
                using var cursor = BusyCursor.Enter();
                saving = true;
                layout.IsEnabled = false;
                status.Text = "Adding OID To Active Directory…";
                try
                {
                    // Capture form values and create the policy off the UI thread.
                    var displayName = name.Text;
                    var value = oid.Text;
                    var flags = kind.SelectedIndex == 0 ? 3 : 2;
                    AddedId = await Task.Run(() => directory.Add(displayName, value, flags));
                }
                catch (Exception error) { status.Text = CaAdministration.Error(error); }
                finally { saving = false; layout.IsEnabled = true; }
                if (AddedId != Guid.Empty) DialogResult = true;
            });

            // Wire cancellation, initial focus, and navigation protection for the add form.
            Dialogs.Button(buttons, "_Cancel", Close);
            Content = layout;
            Closing += (sender, e) => e.Cancel = saving;
            Loaded += (sender, e) => name.Focus();
        }
    }
}
