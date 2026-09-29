//
// Copyright (c) Bryan Berns.
// Licensed under GPLv3. See LICENSE.md.
//

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;

namespace Certitude
{
    public static class Glyphs
    {
        public const string Document = "\uE8A5", Certificate = "\uE8A6", Search = "\uE721", Filter = "\uE71C",
            Calendar = "\uE787", Check = "\uE73E", Pending = "\uE823", Block = "\uE8F8", Warning = "\uE7BA",
            Cancel = "\uE711", Delete = "\uE74D", Copy = "\uE8C8", Save = "\uE74E", Import = "\uE8B5",
            Open = "\uE8DA", Edit = "\uE70F", Settings = "\uE713", Refresh = "\uE72C", Key = "\uE72E",
            Back = "\uE72B", Forward = "\uE72A", List = "\uE8A9", Connect = "\uE703", Theme = "\uE706",
            SelectAll = "\uE8B3", More = "\uE712", Person = "\uE77B", Statistics = "\uE9D9";
        public static readonly DependencyProperty IconProperty = DependencyProperty.RegisterAttached(
            "Icon", typeof(string), typeof(Glyphs), new PropertyMetadata(""));
        public static string GetIcon(DependencyObject target) => (string)target.GetValue(IconProperty);
        public static void SetIcon(DependencyObject target, string value) => target.SetValue(IconProperty, value);

        public static string ForCaption(string caption)
        {
            // Prefer action-specific glyphs after removing access-key markers from the caption.
            var text = caption.Replace("_", "").ToLowerInvariant();
            if (text.StartsWith("delete") || text.StartsWith("remove")) return Delete;
            if (text.StartsWith("revoke")) return Block;
            if (text.StartsWith("cancel") || text.StartsWith("deny")) return Cancel;
            if (text.StartsWith("back") || text.StartsWith("newer")) return Back;
            if (text.StartsWith("export") || text.StartsWith("save")) return Save;
            if (text.StartsWith("import") || text.StartsWith("accept response")) return Import;
            if (text.StartsWith("copy")) return Copy;
            if (text.StartsWith("open") || text.StartsWith("browse")) return Open;
            if (text.StartsWith("load") || text.StartsWith("retrieve") || text.StartsWith("refresh")) return Refresh;
            if (text.StartsWith("friendly") || text.StartsWith("edit") || text.StartsWith("set ")) return Edit;
            if (text.StartsWith("continue") || text.StartsWith("issue") || text.StartsWith("submit") ||
                text.Contains("check") || text.Contains("validat")) return Check;

            // Use field-related glyphs when no action verb identifies the control.
            if (text.Contains("search") || text.Contains("find")) return Search;
            if (text.Contains("key") || text.Contains("password")) return Key;
            if (text.Contains("expir") || text.Contains("date") || text.Contains("time")) return Calendar;
            if (text.Contains("subject") || text.Contains("requester")) return Person;
            if (text.Contains("store") || text.Contains("file")) return Open;
            if (text.Contains("settings") || text.Contains("configuration")) return Settings;
            if (text.Contains("certificate") || text.Contains("enroll")) return Certificate;
            return Document;
        }

        public static Label Label(string text, bool inline = false)
        {
            // Create a title-cased label with the appropriate inline or stacked spacing.
            var label = new Label { Content = Dialogs.Caption(text) };
            label.SetResourceReference(FrameworkElement.StyleProperty,
                inline ? "InlineFieldLabelStyle" : "FieldLabelStyle");
            SetIcon(label, ForCaption(text));
            return label;
        }
    }

    internal static class Dialogs
    {
        public static string Caption(string text) => Regex.Replace(text, @"[A-Za-z][A-Za-z_']*", match =>
        {
            // Title-case ordinary words while preserving acronyms, date tokens, and mnemonic positions.
            var word = match.Value;
            var plain = word.Replace("_", "");
            if (new[] { "Certitude", "SANs", "CRLs", "CAs", "IDs" }.Contains(plain) || plain.All(char.IsUpper) ||
                new[] { "yyyy-MM-dd", "yyyy", "dd", "mm", "ss" }.Contains(plain)) return word;
            var result = char.ToUpperInvariant(plain[0]) + plain.Substring(1).ToLowerInvariant();
            for (var i = 0; i < word.Length; i++) if (word[i] == '_') result = result.Insert(i, "_");
            return result;
        });

        public static Button Button(Panel panel, string caption, Action click)
        {
            // Create a glyph button whose spacing matches its toolbar placement.
            var button = new Button
            {
                Content = Caption(caption), Margin = DockPanel.GetDock(panel) == Dock.Right ?
                    new Thickness(6, 0, 0, 0) : new Thickness(0, 0, 6, 4)
            };
            Glyphs.SetIcon(button, Glyphs.ForCaption(caption));
            button.Click += (sender, e) => click();
            panel.Children.Add(button);
            return button;
        }

        public static WrapPanel RightActions(DockPanel panel)
        {
            // Dock a consistently aligned action group beside a stretching input field.
            var actions = new WrapPanel { VerticalAlignment = VerticalAlignment.Center };
            DockPanel.SetDock(actions, Dock.Right);
            panel.Children.Add(actions);
            return actions;
        }

        public static TextBox Field(Panel panel, string label, string value = "", bool multiline = false)
        {
            // Pair a glyph label with a single-line or scrolling multiline editor.
            var caption = Glyphs.Label(label);
            caption.Margin = new Thickness(0, 5, 0, 3);
            panel.Children.Add(caption);
            var box = new TextBox
            {
                Text = value, AcceptsReturn = multiline, Height = multiline ? 88 : double.NaN,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                HorizontalScrollBarVisibility = ScrollBarVisibility.Auto
            };
            panel.Children.Add(box);
            return box;
        }

        public static void Note(Panel panel, string text) => panel.Children.Add(new TextBlock
        {
            Text = text, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 5, 0, 6)
        });

        public static Task<bool> Confirm(DependencyObject owner, string action, string config,
            IEnumerable<int> ids, string detail)
        {
            // Summarize selected request IDs and operation scope for confirmation.
            var list = ids.ToArray();
            return Confirm(owner, "Confirm " + action, $"{action}: {list.Length:N0} selected record(s)\r\nCA: {config}\r\n" +
                "Request IDs: " + string.Join(", ", list.Take(20)) + (list.Length > 20 ? ", …" : "") +
                "\r\n\r\n" + detail);
        }

        public static async Task<bool> Confirm(DependencyObject owner, string title, string text)
        {
            // Present confirmation in the main workspace with explicit continue and cancel actions.
            var page = new WorkspacePage { Owner = owner, Title = Caption(title) };
            var layout = new DockPanel { Margin = new Thickness(8) };
            var buttons = new WrapPanel();
            DockPanel.SetDock(buttons, Dock.Bottom);
            layout.Children.Add(buttons);
            Button(buttons, "_Continue", () => page.DialogResult = true);
            Button(buttons, "_Cancel", page.Close);
            layout.Children.Add(new TextBox { Text = text, IsReadOnly = true, AcceptsReturn = true,
                TextWrapping = TextWrapping.Wrap, VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                VerticalContentAlignment = VerticalAlignment.Top, Margin = new Thickness(0, 0, 0, 8) });
            page.Content = layout;
            return await page.ShowAsync() == true;
        }

        public static async Task<string> Prompt(DependencyObject owner, string title, string label,
            string value, bool multiline = false)
        {
            // Return the entered value only when the workspace form is accepted.
            var page = new FormDialog(title, new[] { label }, new[] { value }, multiline) { Owner = owner };
            return await page.ShowAsync() == true ? page.Values[0] : null;
        }

        public static void Report(DependencyObject owner, string title, string text)
        {
            // Create a workspace report with save and back controls.
            var page = new WorkspacePage { Owner = owner, Title = Caption(title) };
            var layout = new DockPanel { Margin = new Thickness(8) };
            var buttons = new WrapPanel();
            DockPanel.SetDock(buttons, Dock.Bottom);
            layout.Children.Add(buttons);
            Button(buttons, "_Save", async () =>
            {
                // Save the report text and surface file errors through the main status area.
                var save = new FilePicker(true) { FileName = "Certitude-log.txt", Filter = "Text|*.txt", Owner = page };
                if (await save.ShowAsync() != true) return;
                try { File.WriteAllText(save.FileName, text); }
                catch (Exception error) { ((MainWindow)Application.Current.MainWindow).Notify(CaAdministration.Error(error)); }
            });

            // Show report text in a scrolling read-only pane.
            Button(buttons, "_Back", page.Close);
            layout.Children.Add(new TextBox
            {
                Text = text, IsReadOnly = true, AcceptsReturn = true, FontFamily = new System.Windows.Media.FontFamily("Consolas"),
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto, HorizontalScrollBarVisibility = ScrollBarVisibility.Auto,
                Margin = new Thickness(0, 0, 0, 6), VerticalContentAlignment = VerticalAlignment.Top
            });
            page.Content = layout;
            page.Show();
        }

        public static async void Certificate(DependencyObject owner, byte[] encoded, OidNames names = null,
            bool refreshNames = true)
        {
            // Decode certificate details in the background before opening their workspace page.
            using var cursor = BusyCursor.Enter();
            try
            {
                var details = await Task.Run(() => DetailsWindow.Describe(encoded,
                    refreshNames ? names?.Refresh() ?? OidNames.Local : names ?? OidNames.Windows));
                new DetailsWindow(0, details) { Owner = owner }.Show();
            }
            catch (Exception error) { ((MainWindow)Application.Current.MainWindow).Notify(CaAdministration.Error(error)); }
        }

        public static void WindowsCertificate(DependencyObject owner, byte[] encoded)
        {
            // Own the decoded certificate only for the lifetime of the native viewer call.
            try
            {
                using (var certificate = new X509Certificate2(encoded)) WindowsCertificate(owner, certificate);
            }
            catch (Exception error) { ((MainWindow)Application.Current.MainWindow).Notify(CaAdministration.Error(error)); }
        }

        public static void WindowsCertificate(DependencyObject owner, X509Certificate2 certificate)
        {
            // Use a normal cursor and the application window as owner of the Windows viewer.
            using (BusyCursor.Suspend())
            {
                var window = Window.GetWindow(owner) ?? Application.Current.MainWindow;
                X509Certificate2UI.DisplayCertificate(certificate, new System.Windows.Interop.WindowInteropHelper(window).Handle);
            }
        }

        public static void CertificateMenu(FrameworkElement target, Func<byte[]> certificate,
            Action view = null, Func<bool> ready = null)
        {
            // Attach native certificate viewing to an existing workspace control.
            var menu = new ContextMenu();
            target.ContextMenu = menu;
            var viewer = MenuItem(menu, "Open In _Windows Certificate Viewer", Glyphs.Certificate, "Windows",
                view ?? (() => WindowsCertificate(target, certificate())));
            bool Update()
            {
                // Hide certificate-only actions when the control has no certificate to display.
                var available = certificate() != null;
                viewer.IsEnabled = available && (ready?.Invoke() ?? true);
                return FilterMenu(menu, item => item != viewer || available);
            }
            // Preserve text copy and selection commands alongside certificate actions.
            if (target is TextBox text)
            {
                menu.Items.Add(new Separator());
                menu.Items.Add(new MenuItem { Header = "_Copy", Command = System.Windows.Input.ApplicationCommands.Copy,
                    CommandTarget = text });
                menu.Items.Add(new MenuItem { Header = "Select _All",
                    Command = System.Windows.Input.ApplicationCommands.SelectAll, CommandTarget = text });
            }
            // Refresh menu applicability and suppress menus with no visible actions.
            target.ContextMenuOpening += (sender, e) => { if (!Update()) e.Handled = true; };
            menu.Opened += (sender, e) => { if (!Update()) menu.IsOpen = false; };
            Update();
        }

        public static async Task ExportCertificate(DependencyObject owner, byte[] encoded, string fileName)
        {
            // Save the certificate in the format chosen by the workspace file picker.
            var save = new FilePicker(true) { FileName = fileName,
                Filter = "DER Certificate|*.cer|PEM Certificate|*.pem", Owner = owner };
            if (await save.ShowAsync() != true) return;
            try { File.WriteAllBytes(save.FileName, CertificateUtilities.ExportPublic(
                new[] { encoded }, save.FilterIndex - 1)); }
            catch (Exception error) { ((MainWindow)Application.Current.MainWindow).Notify(CaAdministration.Error(error)); }
        }

        internal static void SelectContextRow(DataGrid grid, DependencyObject source)
        {
            // Target the right-clicked row while retaining an existing multiselection.
            var row = source == null ? null : ItemsControl.ContainerFromElement(grid, source) as DataGridRow;
            if (row == null) { grid.UnselectAll(); return; }
            if (!row.IsSelected) { grid.UnselectAll(); row.IsSelected = true; }
            row.Focus();
        }

        public static ContextMenu RowMenu(DataGrid grid)
        {
            // Attach a context menu that selects the row under the right-click.
            var menu = new ContextMenu();
            grid.ContextMenu = menu;
            grid.PreviewMouseRightButtonDown += (sender, e) => SelectContextRow(grid, e.OriginalSource as DependencyObject);
            return menu;
        }

        public static bool FilterMenu(ContextMenu menu, Func<MenuItem, bool> applicable)
        {
            // Collapse actions that do not apply to the current view or selection.
            foreach (var item in menu.Items.OfType<MenuItem>())
            {
                var visible = applicable(item);
                item.Visibility = visible ? Visibility.Visible : Visibility.Collapsed;
                if (!visible) item.IsEnabled = false;
            }
            // Show separators only between visible groups of applicable actions.
            Separator pending = null;
            var hasItem = false;
            foreach (var element in menu.Items.OfType<UIElement>())
            {
                if (element is Separator separator)
                {
                    separator.Visibility = Visibility.Collapsed;
                    if (hasItem && pending == null) pending = separator;
                }
                else if (element.Visibility == Visibility.Visible)
                {
                    pending?.Visibility = Visibility.Visible;
                    pending = null;
                    hasItem = true;
                }
            }
            return hasItem;
        }

        public static MenuItem MenuItem(ContextMenu menu, string caption, string icon, string action,
            Action click, string gesture = "")
        {
            // Create a tagged glyph menu item and dispatch it only while enabled.
            var item = new MenuItem { Header = caption, Tag = action, InputGestureText = gesture };
            Glyphs.SetIcon(item, icon);
            item.Click += (sender, e) => { if (item.IsEnabled) click(); };
            menu.Items.Add(item);
            return item;
        }

        public static void CopyText(string text)
        {
            // Copy nonempty text while reporting clipboard failures through the main window.
            if (string.IsNullOrEmpty(text)) return;
            try { Clipboard.SetText(text); }
            catch (Exception error) { ((MainWindow)Application.Current.MainWindow).Notify(CaAdministration.Error(error)); }
        }
    }

    internal sealed class FormDialog : WorkspacePage
    {
        private readonly List<TextBox> fields = new List<TextBox>();
        public string[] Values => fields.Select(input => input.Text).ToArray();

        public FormDialog(string title, string[] labels, string[] values, bool multiline = true)
        {
            // Build a scrollable form with consistent fields and acceptance controls.
            Title = Dialogs.Caption(title);
            var layout = new DockPanel { Margin = new Thickness(8) };
            var buttons = new WrapPanel { Margin = new Thickness(0, 8, 0, 0) };
            DockPanel.SetDock(buttons, Dock.Bottom);
            layout.Children.Add(buttons);
            var panel = new StackPanel();
            for (var i = 0; i < labels.Length; i++)
                fields.Add(Dialogs.Field(panel, labels[i], values[i], multiline && i == labels.Length - 1));
            layout.Children.Add(new ScrollViewer { Content = panel, VerticalScrollBarVisibility = ScrollBarVisibility.Auto });
            Dialogs.Button(buttons, "_Continue", () => DialogResult = true);
            Dialogs.Button(buttons, "_Cancel", Close);
            Content = layout;
            Loaded += (sender, e) => fields[0].Focus();
        }
    }

    internal sealed class RevokeDialog : WorkspacePage
    {
        private readonly ComboBox reason;
        private readonly TextBox effective;
        private static readonly int[] Codes = { 0, 1, 2, 3, 4, 5, 6, 8, 9, 10 };
        public int Reason => Codes[reason.SelectedIndex];
        public DateTime? Effective { get; private set; }

        public RevokeDialog()
        {
            // Collect a supported revocation reason for the selected certificates.
            Title = "Revoke Certificates";
            var panel = new StackPanel { Margin = new Thickness(8) };
            Dialogs.Note(panel, "Choose the revocation reason for the selected certificates.");
            reason = new ComboBox
            {
                ItemsSource = new[]
                {
                    "0 · Unspecified", "1 · Key Compromise", "2 · CA Compromise", "3 · Affiliation Changed",
                    "4 · Superseded", "5 · Cessation Of Operation", "6 · Certificate Hold", "8 · Remove From CRL",
                    "9 · Privilege Withdrawn", "10 · Attribute Authority Compromise"
                },
                SelectedIndex = 0
            };

            // Provide an optional UTC effective time with inline validation feedback.
            panel.Children.Add(reason);
            effective = Dialogs.Field(panel, "Effective Time (UTC)");
            Dialogs.Note(panel, "Use yyyy-MM-dd HH:mm:ss, or leave empty for immediately. " +
                "Only certificate hold can be reversed. Publish a CRL after changing revocation state.");
            var error = new TextBlock { TextWrapping = TextWrapping.Wrap };
            panel.Children.Add(error);
            var buttons = new WrapPanel { Margin = new Thickness(0, 8, 0, 0) };
            panel.Children.Add(buttons);
            Dialogs.Button(buttons, "_Continue", () =>
            {
                // Accept immediate revocation or require an explicitly formatted UTC time.
                if (effective.Text.Trim().Length == 0) { Effective = null; DialogResult = true; return; }
                if (!DateTime.TryParseExact(effective.Text.Trim(), "yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var date))
                {
                    error.Text = "Enter the UTC time as yyyy-MM-dd HH:mm:ss.";
                    return;
                }
                Effective = date;
                DialogResult = true;
            });
            Dialogs.Button(buttons, "_Cancel", Close);
            Content = panel;
        }
    }

    internal sealed class DetailsWindow : WorkspacePage
    {
        public DetailsWindow(byte[] encoded) : this(0, Describe(encoded)) { }

        internal static CertificateDetails Describe(byte[] encoded, OidNames names = null)
        {
            // Describe the certificate identity, keys, validity, and resolved identifiers.
            names ??= OidNames.Windows;
            using (var certificate = new X509Certificate2(encoded))
            {
                var detail = new CertificateDetails { Certificate = encoded, Oids = names };
                var metadata = CertificateUtilities.Describe(certificate, names);
                foreach (var field in new[]
                {
                    new[] { "Subject", metadata.Subject }, new[] { "Issuer", metadata.Issuer },
                    new[] { "Version", certificate.Version.ToString() }, new[] { "Serial Number", metadata.SerialNumber },
                    new[] { "SHA-1 Thumbprint", metadata.Thumbprint }, new[] { "SHA-256", metadata.Sha256 },
                    new[] { "Valid From (UTC)", metadata.NotBefore.ToString("u") },
                    new[] { "Expires (UTC)", metadata.NotAfter.ToString("u") },
                    new[] { "Public Key", metadata.Algorithm + " · " + metadata.KeyBits + " Bits" },
                    new[] { "Public Key (Base64)", Convert.ToBase64String(certificate.GetPublicKey()) },
                    new[] { "Signature Algorithm", names.Describe(certificate.SignatureAlgorithm.Value, 4) },
                    new[] { "Certificate Authority", metadata.IsCa.ToString() },
                    new[] { "Subject Alternative Names", metadata.AlternativeNames },
                    new[] { "Enhanced Key Usages", metadata.Purposes },
                    new[] { "Certificate Template", metadata.Template }, new[] { "OID Resolution", names.Status },
                    new[] { "Certificate Object Identifiers", names.Identifiers(encoded) }
                }) detail.Values.Add(new DetailValue { Name = field[0], Value = field[1] });

                // Keep both readable extension values and their original DER encodings.
                foreach (var extension in certificate.Extensions.Cast<X509Extension>())
                {
                    var name = Dialogs.Caption(names.Name(extension.Oid.Value, 6)) + " · " + extension.Oid.Value;
                    if (extension.Critical) name += " · Critical";
                    detail.Values.Add(new DetailValue { Name = name, Value = names.FormatExtension(extension) });
                    detail.Values.Add(new DetailValue { Name = name + " · DER (Base64)",
                        Value = Convert.ToBase64String(extension.RawData) });
                }
                return detail;
            }
        }

        public DetailsWindow(int requestId, CertificateDetails detail)
        {
            // Identify the request and its CA above certificate-specific actions.
            Title = requestId == 0 ? "Certificate Details" : "Request " + requestId;
            if (!string.IsNullOrEmpty(detail.Configuration)) Title += " — " + detail.Configuration;
            var layout = new DockPanel { Margin = new Thickness(8) };
            var buttons = new WrapPanel();
            DockPanel.SetDock(buttons, Dock.Top);
            layout.Children.Add(buttons);

            // Enable export, revocation checking, and native viewing when certificate data exists.
            Dialogs.Button(buttons, "_Export Certificate", async () => await Dialogs.ExportCertificate(this,
                detail.Certificate, requestId == 0 ? "certificate.cer" : requestId + ".cer"))
                .IsEnabled = detail.Certificate != null;
            Dialogs.Button(buttons, "Certificate / CRL Chec_k", () =>
                new ValidationWindow(detail.Certificate, Title, detail.Oids) { Owner = this }.Show())
                .IsEnabled = detail.Certificate != null;
            Dialogs.Button(buttons, "Open In _Windows Certificate Viewer", () =>
                Dialogs.WindowsCertificate(this, detail.Certificate)).IsEnabled = detail.Certificate != null;

            // Provide a separate wrapping preview for the selected property value.
            var value = new TextBox
            {
                IsReadOnly = true, AcceptsReturn = true, Height = 110, Margin = new Thickness(0, 6, 0, 0),
                TextWrapping = TextWrapping.Wrap, VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
                VerticalContentAlignment = VerticalAlignment.Top
            };
            DockPanel.SetDock(value, Dock.Bottom);
            layout.Children.Add(value);

            // Use wrapping cells and variable row heights to prevent clipped detail values.
            var cells = new Style(typeof(DataGridCell), (Style)Application.Current.FindResource(typeof(DataGridCell)));
            cells.Setters.Add(new Setter(Control.VerticalContentAlignmentProperty, VerticalAlignment.Top));
            cells.Setters.Add(new Setter(Control.PaddingProperty, new Thickness(6, 3, 6, 3)));
            var text = new Style(typeof(TextBlock), DataGridTextColumn.DefaultElementStyle);
            text.Setters.Add(new Setter(TextBlock.TextWrappingProperty, TextWrapping.Wrap));
            var grid = new DataGrid
            {
                ItemsSource = detail.Values, SelectionMode = DataGridSelectionMode.Single,
                RowHeight = double.NaN, MinRowHeight = 24, CellStyle = cells, ColumnHeaderHeight = double.NaN,
                ColumnHeaderStyle = (Style)Application.Current.FindResource("DetailsColumnHeaderStyle")
            };

            // Configure property and value columns with pixel scrolling for expanded rows.
            VirtualizingPanel.SetScrollUnit(grid, ScrollUnit.Pixel);
            grid.Columns.Add(new DataGridTextColumn { Header = "Property / Attribute / Extension",
                Binding = new Binding("Name"), ElementStyle = text, Width = 270 });
            grid.Columns.Add(new DataGridTextColumn { Header = "Value (UTC / Base64)", Binding = new Binding("Value"),
                ElementStyle = text, Width = new DataGridLength(1, DataGridLengthUnitType.Star), MinWidth = 100 });

            // Connect certificate menus, sorting feedback, and selected-value preview updates.
            Dialogs.CertificateMenu(grid, () => detail.Certificate);
            Dialogs.CertificateMenu(value, () => detail.Certificate);
            BusyCursor.OnSorting(grid);
            grid.SelectionChanged += (sender, e) => value.Text = (grid.SelectedItem as DetailValue)?.Value ?? "";
            layout.Children.Add(grid);
            Content = layout;
        }
    }
}
