//
// Copyright (c) Bryan Berns.
// Licensed under GPLv3. See LICENSE.md.
//

using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;

namespace Certitude
{
    internal sealed class AdministrationWindow : WorkspacePage
    {
        private readonly string config;
        private readonly Lazy<OidNames> oidNames;
        private readonly Action<string> record;
        private readonly TabControl tabs = new TabControl();
        private readonly TextBlock status = new TextBlock { Margin = new Thickness(0, 14, 0, 0), TextWrapping = TextWrapping.Wrap };
        private bool busy;

        public AdministrationWindow(string configuration, Action<string> log, OidNames names = null)
        {
            // Bind administration pages and status reporting to the selected CA.
            config = configuration;
            oidNames = new Lazy<OidNames>(() => names ?? OidNames.Load(config));
            record = log;
            Title = "Administration — " + config;
            var layout = new DockPanel { Margin = new Thickness(8) };
            DockPanel.SetDock(status, Dock.Bottom);
            layout.Children.Add(status);
            layout.Children.Add(tabs);
            Content = layout;

            // Build the operation tabs and prevent navigation during an active CA call.
            BuildOperations();
            BuildCrls();
            BuildProperties();
            BuildConfiguration();
            BuildTemplates();
            Closing += (sender, e) =>
            {
                if (!busy) return;
                e.Cancel = true;
                status.Text = "Wait for the current CA operation to complete before closing.";
            };
        }

        private StackPanel Page(string title)
        {
            // Wrap each administration form in a scrollable tab.
            var panel = new StackPanel { Margin = new Thickness(8) };
            tabs.Items.Add(new TabItem
            {
                Header = Dialogs.Caption(title), Content = new ScrollViewer { Content = panel, VerticalScrollBarVisibility = ScrollBarVisibility.Auto }
            });
            return panel;
        }

        private void Action(Panel panel, string caption, Func<Task> operation)
        {
            // Route administration buttons through a common asynchronous operation guard.
            Dialogs.Button(panel, caption, async () =>
            {
                // Prevent overlapping CA changes and show progress while the action runs.
                if (busy) return;
                using var cursor = BusyCursor.Enter();
                busy = true;
                tabs.IsEnabled = false;
                status.Text = caption.Replace("_", "") + "…";
                try { await operation(); }
                catch (Exception error)
                {
                    // Surface operation failures in the page status and activity callback.
                    status.Text = CaAdministration.Error(error);
                    record(status.Text);
                }
                finally { busy = false; tabs.IsEnabled = true; }
            });
        }

        private Task<bool> Confirm(string action, string details) => Dialogs.Confirm(this,
            "Confirm CA Change", action + "\r\nCA: " + config + "\r\n\r\n" + details);

        private void Done(string text)
        {
            // Keep the visible completion message and activity callback consistent.
            status.Text = text;
            record(text);
        }

        private void BuildOperations()
        {
            // Group CA information actions separately from request and service operations.
            var panel = Page("_Operations");
            Dialogs.Note(panel, "Certificate authority: " + config);
            var read = new WrapPanel();
            panel.Children.Add(read);
            Action(read, "CA _information", async () =>
            {
                var text = await Task.Run(() => CaAdministration.Use(config, admin =>
                {
                    // Read supported CA properties independently so unavailable values remain visible.
                    var result = new StringBuilder();
                    foreach (var id in new[] { 6, 22, 10, 1, 2, 5, 9, 11, 23, 24, 25, 29, 30, 31 })
                    {
                        try
                        {
                            var type = admin.GetCAPropertyFlags(config, id) & 255;
                            result.AppendLine(admin.GetCAPropertyDisplayName(config, id) + ": " +
                                CertificateStore.Format(admin.GetCAProperty(config, id, 0, type, 1)));
                        }
                        catch (FileNotFoundException) when (id == 9)
                        {
                            result.AppendLine("Parent CA: Not configured.");
                        }
                        catch (Exception error)
                        {
                            result.AppendLine($"Property {id}: {CaAdministration.Error(error)}");
                        }
                    }
                    // Append the current identity access mask to the CA information report.
                    result.AppendLine($"Your CA role/access mask: 0x{admin.GetMyRoles(config):X}");
                    return result.ToString();
                }));
                Dialogs.Report(this, "CA information", text);
                Done("CA information loaded.");
            });
            Action(read, "View CA _certificate…", async () =>
            {
                // Fetch the CA certificate before opening its decoded details.
                var bytes = await Task.Run(() =>
                {
                    using (var request = ComScope<ICertRequest>.Create("CertificateAuthority.Request"))
                        return Convert.FromBase64String(request.Value.GetCACertificate(0, config, 1));
                });
                Dialogs.Certificate(this, bytes, await Task.Run(() => oidNames.Value.Refresh()));
                Done("CA certificate loaded.");
            });
            Action(read, "Database _schema…", async () =>
            {
                // Read database column types and indexing information on a worker thread.
                var text = await Task.Run(() =>
                {
                    using (var view = ComScope<ICertView>.Create("CertificateAuthority.View"))
                    {
                        view.Value.OpenConnection(config);
                        using (var columns = new ComScope<ICertViewColumn>(view.Value.EnumCertViewColumn(0)))
                        {
                            var result = new StringBuilder("Name\tType\tIndexed\r\n");
                            while (columns.Value.Next() >= 0)
                                result.AppendLine($"{columns.Value.GetName()}\t{columns.Value.GetType()}\t" +
                                    $"{columns.Value.IsIndexed() != 0}");
                            return result.ToString();
                        }
                    }
                });

                // Present the completed schema report in the workspace.
                Dialogs.Report(this, "CA database schema", text);
                Done("Schema loaded.");
            });

            // Provide request submission and issued-certificate import actions.
            Dialogs.Note(panel, "Certificate requests");
            var requests = new WrapPanel();
            panel.Children.Add(requests);
            Action(requests, "_Submit PKCS #10 request…", async () =>
            {
                // Choose a request and confirm its enrollment attributes before submitting it.
                var open = new FilePicker() { Filter = "PKCS #10 request|*.req;*.csr;*.p10;*.pem|All files|*.*" };
                if (await open.ShowAsync() != true) return;
                var attributes = await Dialogs.Prompt(this, "Request attributes",
                    "Optional Name:Value pairs, one per line", "", true);
                if (attributes == null ||
                    !await Confirm("Submit certificate request", open.FileName + "\r\n" + attributes)) return;

                // Submit the request in the background and show the resulting disposition.
                var result = await Task.Run(() => CaAdministration.Submit(config, open.FileName, attributes));
                Done(result);
                Dialogs.Report(this, "Submission result", result);
            });
            Action(requests, "_Import issued certificate…", async () =>
            {
                // Confirm the selected public certificate before importing it into the CA database.
                var open = new FilePicker() { Filter = "Certificate|*.cer;*.crt;*.pem|All files|*.*" };
                if (await open.ShowAsync() != true ||
                    !await Confirm("Import certificate into the CA database", open.FileName)) return;
                var id = await Task.Run(() => CaAdministration.Use(config,
                    admin => admin.ImportCertificate(config, CaAdministration.ReadBase64(open.FileName), 1)));
                Done("Imported certificate as request " + id + ".");
            });

            // Link request administration to the dedicated CRL publication tab.
            Dialogs.Note(panel, "Certificate revocation lists");
            var crls = new WrapPanel();
            panel.Children.Add(crls);
            Action(crls, "Generate / publish / export _CRLs…", () =>
            {
                tabs.SelectedIndex = 1;
                return Task.CompletedTask;
            });

            // Expose Certificate Services status and lifecycle operations.
            Dialogs.Note(panel, "Certificate Services");
            var service = new WrapPanel();
            panel.Children.Add(service);
            foreach (var verb in new[] { "Status", "Start", "Stop", "Restart" })
            {
                Action(service, verb, async () =>
                {
                    // Confirm service changes before executing them on the selected CA host.
                    if (verb != "Status" && !await Confirm(verb + " Certificate Services",
                        "This affects certificate issuance on the selected server.")) return;
                    Done(await Task.Run(() => CaAdministration.Service(config, verb)));
                });
            }
            Dialogs.Note(panel, "Use Advanced Tools for backups, connectivity checks and database maintenance. " +
                "Restore, CA renewal and other certutil/certreq commands run outside Certitude.");
        }

        private void BuildCrls()
        {
            // Collect CRL type, optional next-update time, and republication mode.
            var panel = Page("C_RLs");
            Dialogs.Note(panel, "Generate new CRLs and publish them to this CA's configured locations. " +
                "Delta publication requires delta CRLs to be enabled on the CA.");
            var kind = new ComboBox { ItemsSource = new[] { "Base CRLs", "Delta CRLs", "Base And Delta CRLs" }, SelectedIndex = 0 };
            panel.Children.Add(kind);
            var next = Dialogs.Field(panel, "Next update in UTC (yyyy-MM-dd HH:mm:ss); empty uses CA defaults");
            var republish = new CheckBox
            {
                Content = "Republish Existing CRLs Instead Of Generating New Ones",
                Margin = new Thickness(0, 6, 0, 6)
            };
            panel.Children.Add(republish);

            // Add guarded publication and publication-status actions.
            var controls = new WrapPanel();
            panel.Children.Add(controls);
            Action(controls, "_Publish…", async () =>
            {
                // Translate form settings into publication flags and an optional UTC deadline.
                var flags = kind.SelectedIndex + 1;
                if (republish.IsChecked == true) flags |= 0x10;
                DateTime? date = null;
                if (next.Text.Trim().Length > 0)
                {
                    if (!DateTime.TryParseExact(next.Text.Trim(), "yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture,
                        DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed))
                        throw new ArgumentException("Enter the next-update UTC time as yyyy-MM-dd HH:mm:ss.");
                    date = parsed;
                }
                // Validate and confirm the publication request before making the CA call.
                CaAdministration.ValidateCrlPublication(flags, date);
                var action = (flags & 0x10) != 0 ? "Republish existing " : "Generate and publish new ";
                if (!await Confirm(action + kind.SelectedItem, "Next update: " + (date?.ToString("u") ?? "CA defaults") +
                    "\r\nApplies to the CA's current and unexpired renewed signing certificates.")) return;

                // Show the publication report so per-location failures remain visible.
                var report = await Task.Run(() => CaAdministration.PublishCrls(config, flags, date));
                Done("CRL publication call completed. Review the publication report for errors.");
                record(report);
                Dialogs.Report(this, "CRL publication results", report);
            });
            Action(controls, "Publication _status…", async () =>
            {
                // Read and display the CA-reported CRL publication status.
                var report = await Task.Run(() => CaAdministration.Use(config,
                    admin => CaAdministration.CrlPublicationStatus(config, admin)));
                Done("CRL publication status loaded.");
                record(report);
                Dialogs.Report(this, "CRL publication status", report);
            });

            // Select the signing certificate index and CRL type for inspection or export.
            Dialogs.Note(panel, "Inspect or export a CRL for one CA signing certificate. " +
                "The index selects the signing certificate, including renewed CA certificates.");
            var index = Dialogs.Field(panel, "CA certificate index", "0");
            var exportKind = new ComboBox { ItemsSource = new[] { "Base CRL", "Delta CRL" }, SelectedIndex = 0,
                Margin = new Thickness(0, 6, 0, 0) };
            panel.Children.Add(exportKind);
            var exports = new WrapPanel { Margin = new Thickness(0, 12, 0, 0) };
            panel.Children.Add(exports);
            Action(exports, "_Inspect CRL…", async () =>
            {
                // Read and decode the selected CA CRL with refreshed OID names.
                var number = int.Parse(index.Text, CultureInfo.InvariantCulture);
                var delta = exportKind.SelectedIndex == 1;
                var report = await Task.Run(() => CertificateValidation.InspectCrl(
                    CaAdministration.ReadCrl(config, delta, number), config + " · index " + number, null,
                    new X509Certificate2[0], oidNames.Value.Refresh()).Details);
                Dialogs.Report(this, "CA CRL", report);
                Done("CA CRL metadata loaded.");
            });
            Action(exports, "_Export CRL…", async () =>
            {
                // Choose an output file and save the requested base or delta CRL.
                var number = int.Parse(index.Text, CultureInfo.InvariantCulture);
                var delta = exportKind.SelectedIndex == 1;
                var save = new FilePicker(true) { FileName = delta ? "delta.crl" : "base.crl", Filter = "CRL|*.crl" };
                if (await save.ShowAsync() != true) return;
                await Task.Run(() => File.WriteAllBytes(save.FileName, CaAdministration.ReadCrl(config, delta, number)));
                Done("CRL saved to " + save.FileName);
            });
            Dialogs.Note(panel, "Use Certificate / CRL check to validate a certificate against published or local CRLs. " +
                "A successful publication call alone does not confirm that clients can download every distribution point.");
        }

        private void BuildProperties()
        {
            // Collect the property identity, index, and typed value for direct CA administration.
            var panel = Page("CA _properties");
            Dialogs.Note(panel, "Read any CA API property by ID and index. Binary values use base64. " +
                "Writable properties include role separation (23), KRA usage/count (24/25) and KRA certificates (26).");
            var property = Dialogs.Field(panel, "Property ID", "6");
            var index = Dialogs.Field(panel, "Property index (zero-based)", "0");
            var type = new ComboBox { ItemsSource = new[] { "1 · Integer", "2 · UTC Date", "3 · Binary (Base64)", "4 · String" }, SelectedIndex = 3 };
            Dialogs.Note(panel, "Value Type (Detected When Reading)");
            panel.Children.Add(type);
            var value = Dialogs.Field(panel, "Property value", "", true);

            // Provide guarded read and write actions for the property form.
            var buttons = new WrapPanel { Margin = new Thickness(0, 8, 0, 0) };
            panel.Children.Add(buttons);
            Action(buttons, "_Read property", async () =>
            {
                // Read the property using the type reported by the CA.
                var id = int.Parse(property.Text);
                var number = int.Parse(index.Text);
                var result = await Task.Run(() => CaAdministration.Use(config, admin =>
                {
                    var flags = admin.GetCAPropertyFlags(config, id);
                    return new
                    {
                        Type = flags & 255, Name = admin.GetCAPropertyDisplayName(config, id),
                        Value = CertificateStore.Format(admin.GetCAProperty(config, id, number, flags & 255, 1))
                    };
                }));

                // Reflect the detected type and formatted value in the property editor.
                type.SelectedIndex = result.Type - 1;
                value.Text = result.Value;
                Done(result.Name + " loaded.");
            });
            Action(buttons, "_Set property…", async () =>
            {
                // Parse the new property value and restrict writes to supported writable IDs.
                var id = int.Parse(property.Text);
                var number = int.Parse(index.Text);
                var kind = type.SelectedIndex + 1;
                var data = CaAdministration.ParseValue(value.Text, kind);
                if (!new[] { 23, 24, 25, 26, 29 }.Contains(id))
                    throw new ArgumentException("This CA property is read-only.");

                // Confirm the property change before marshaling its typed value to the CA.
                if (!await Confirm("Set CA property " + id + " at index " + number, value.Text)) return;
                await Task.Run(() => CaAdministration.Use(config, admin =>
                {
                    using (var variant = new VariantValue(data))
                        admin.SetCAProperty(config, id, number, kind, variant.Pointer);
                    return 0;
                }));
                Done("CA property " + id + " updated.");
            });
            Dialogs.Note(panel, "Common IDs: 6 name; 10 type; 11 CA certificate count; 12 certificate; 13 chain; " +
                "17 base CRL; 18 delta CRL; 22 DNS name; 26 KRA certificate; 29 templates; 30/31 CRL publish status; " +
                "41 CDP URLs; 42 AIA URLs; 43 OCSP URLs. Use index to inspect renewed certificates and CRLs.");
        }

        private void BuildConfiguration()
        {
            // Build the editor for typed entries under the CA configuration tree.
            var panel = Page("_Configuration");
            Dialogs.Note(panel, "Read or update CA configuration entries, including validity periods, " +
                "CDP/AIA publication URLs, policy and exit modules, audit filters and CA flags. " +
                "Some changes require a service restart.");
            var node = Dialogs.Field(panel, "Node relative to this CA's configuration (empty for the CA root)");
            var name = Dialogs.Field(panel, "Entry name", "CRLPeriodUnits");
            var type = new ComboBox
            {
                ItemsSource = new[] { "1 · DWORD", "2 · UTC Date", "3 · Binary (Base64)", "4 · String", "5 · Multi-String (One Entry Per Line)" },
                SelectedIndex = 0
            };

            // Attach the value editor and guarded configuration actions.
            Dialogs.Note(panel, "Value type");
            panel.Children.Add(type);
            var value = Dialogs.Field(panel, "Value", "", true);
            var buttons = new WrapPanel { Margin = new Thickness(0, 8, 0, 0) };
            panel.Children.Add(buttons);
            Action(buttons, "_Read entry", async () =>
            {
                // Read a configuration entry and select the editor type from its returned value.
                var path = node.Text.Trim();
                var entry = name.Text.Trim();
                var data = await Task.Run(() => CaAdministration.Use(config,
                    admin => admin.GetConfigEntry(config, path, entry)));
                type.SelectedIndex = data is int ? 0 : data is DateTime ? 1 :
                    data is byte[] ? 2 : data is Array ? 4 : 3;
                value.Text = data is Array array && !(data is byte[]) ?
                    string.Join(Environment.NewLine, array.Cast<object>().Select(CertificateStore.Format)) :
                    CertificateStore.Format(data);
                Done("Configuration entry loaded.");
            });
            Action(buttons, "_Write entry…", async () =>
            {
                // Validate and confirm the target entry before writing its native variant value.
                var path = node.Text.Trim();
                var entry = name.Text.Trim();
                var data = CaAdministration.ParseValue(value.Text, type.SelectedIndex + 1);
                if (entry.Length == 0) throw new ArgumentException("Enter a configuration entry name.");
                if (!await Confirm("Write " + path + "\\" + entry, value.Text)) return;
                await Task.Run(() => CaAdministration.Use(config, admin =>
                {
                    using (var variant = new VariantValue(data, binaryString: false))
                        admin.SetConfigEntry(config, path, entry, variant.Pointer);
                    return 0;
                }));
                Done("Configuration updated. Restart Certificate Services if the setting requires it.");
            });
        }

        private void BuildTemplates()
        {
            // Build the published-template editor and retain the originally loaded list.
            var panel = Page("_Templates");
            Dialogs.Note(panel, "Published template short names, one per line. This changes which templates this " +
                "enterprise CA issues. Edit the template definitions and their permissions in the template console.");
            var names = Dialogs.Field(panel, "Published templates", "", true);
            names.Height = 300;
            var loaded = false;
            string original = null;
            var buttons = new WrapPanel { Margin = new Thickness(0, 8, 0, 0) };
            panel.Children.Add(buttons);
            Action(buttons, "_Load templates", async () =>
            {
                // Decode the CA template list into editable short names.
                original = await Task.Run(() => CaAdministration.Use(config,
                    admin => Convert.ToString(admin.GetCAProperty(config, 29, 0, 4, 1), CultureInfo.InvariantCulture)));
                var entries = original.Replace("\r", "").Split('\n');
                names.Text = string.Join(Environment.NewLine,
                    entries.Where((entry, i) => i % 2 == 0 && entry.Length > 0));
                loaded = true;
                Done("Published templates loaded.");
            });
            Action(buttons, "_Save templates…", async () =>
            {
                // Require a loaded baseline and normalize a nonempty list of template names.
                if (!loaded) throw new InvalidOperationException("Load the current templates before editing.");
                var entries = names.Text.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                    .Select(name => name.Trim()).Where(name => name.Length > 0)
                    .Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
                if (entries.Length == 0)
                    throw new ArgumentException("Enter at least one template. " +
                        "Use the Windows Certification Authority console to remove all templates.");

                // Confirm the complete replacement list before submitting it.
                var data = string.Concat(entries.Select(name => name + "\n\n"));
                if (!await Confirm("Replace this CA's published template list",
                    string.Join(Environment.NewLine, entries))) return;
                await Task.Run(() => CaAdministration.Use(config, admin =>
                {
                    // Reject concurrent template changes before replacing the saved baseline.
                    var current = Convert.ToString(admin.GetCAProperty(config, 29, 0, 4, 1),
                        CultureInfo.InvariantCulture);
                    if (current != original)
                        throw new InvalidOperationException("Templates changed on the CA. Reload before saving.");
                    using (var variant = new VariantValue(data)) admin.SetCAProperty(config, 29, 0, 4, variant.Pointer);
                    return 0;
                }));

                // Require another load before any further template edits can be saved.
                loaded = false;
                Done("Published templates updated. Reload to view the resulting list.");
            });
        }
    }
}
