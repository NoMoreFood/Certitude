//
// Copyright (c) Bryan Berns.
// Licensed under GPLv3. See LICENSE.md.
//

using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;

namespace Certitude
{
    internal sealed class ValidationWindow : WorkspacePage
    {
        private readonly StackPanel editor;
        private readonly TextBlock identity;
        private readonly TextBlock status;
        private readonly TextBox issuerFiles;
        private readonly TextBox crlFiles;
        private readonly TextBox timeout;
        private readonly TextBox output;
        private readonly CheckBox offline;
        private readonly CheckBox retrieve;
        private readonly CheckBox entireChain;
        private readonly ComboBox downloaded;
        private readonly Button cancel;
        private readonly Button saveCrl;
        private byte[] certificate;
        private OidNames oids;
        private CancellationTokenSource cancellation;

        public ValidationWindow(byte[] encoded = null, string source = null, OidNames names = null)
        {
            // Create the validation workspace with an optional preselected certificate.
            oids = names;
            Title = "Certificate And CRL Validation";
            certificate = encoded;
            var layout = new DockPanel { Margin = new Thickness(8) };
            editor = new StackPanel();
            DockPanel.SetDock(editor, Dock.Top);
            layout.Children.Add(editor);

            // Provide certificate loading and viewing actions above the validation inputs.
            var buttons = new WrapPanel();
            editor.Children.Add(buttons);
            Dialogs.Button(buttons, "_Open certificate…", async () =>
            {
                // Load a public certificate and invalidate any previous validation results.
                var open = new FilePicker() { Filter = "Public certificate|*.cer;*.crt;*.pem|All files|*.*" };
                if (await open.ShowAsync() != true) return;
                try
                {
                    using var cursor = BusyCursor.Enter();
                    editor.IsEnabled = false;
                    certificate = await Task.Run(() => CertificateValidation.ReadCertificate(open.FileName));
                    identity.Text = open.FileName;
                    ClearResult();
                }
                catch (Exception error) { status.Text = CaAdministration.Error(error); }
                finally { editor.IsEnabled = true; }
            });
            Dialogs.Button(buttons, "_View certificate…", async () =>
            {
                // Open certificate details using OID resolution allowed by the current network mode.
                if (certificate == null) { status.Text = "Open a certificate first."; return; }
                try
                {
                    await Dialogs.Certificate(this, certificate, oids, offline.IsChecked != true);
                }
                catch (Exception error) { status.Text = CaAdministration.Error(error); }
            });

            // Show the certificate source and expose native viewer access.
            identity = new TextBlock
            {
                Text = source ?? "Open a DER or PEM certificate, or use a CA request's details.",
                TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 5, 0, 0)
            };
            editor.Children.Add(identity);
            Dialogs.CertificateMenu(identity, () => certificate);
            Dialogs.Button(buttons, "_Windows Certificate Viewer", () =>
            {
                // Require a loaded certificate before invoking the Windows viewer.
                if (certificate == null) { status.Text = "Open a certificate first."; return; }
                Dialogs.WindowsCertificate(this, certificate);
            });

            // Collect supporting issuer and CRL files along with network and chain-scope options.
            issuerFiles = FileInput(editor, "Supporting issuer / CRL-signer certificates (optional, one path per line)",
                "_Issuer files…", "Certificates / chains|*.cer;*.crt;*.pem;*.p7b|All files|*.*");
            crlFiles = FileInput(editor, "Local CRL files (optional; supply a base and its delta together)",
                "_CRL files…", "Certificate revocation lists|*.crl;*.pem|All files|*.*");
            var options = new WrapPanel { Margin = new Thickness(0, 6, 0, 6) };
            editor.Children.Add(options);
            offline = new CheckBox { Content = "O_ffline / Cache Only", Margin = new Thickness(0, 0, 18, 0) };
            retrieve = new CheckBox { Content = "Retrieve Distribution-Point CRLs", IsChecked = true, Margin = new Thickness(0, 0, 18, 0) };
            entireChain = new CheckBox { Content = "Check Chain Except Root", IsChecked = true };
            options.Children.Add(offline);
            options.Children.Add(retrieve);
            options.Children.Add(entireChain);

            // Place the retrieval timeout beside the validation action.
            var run = new WrapPanel { Margin = new Thickness(0, 0, 0, 5) };
            editor.Children.Add(run);
            var timing = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 6, 4) };
            run.Children.Add(timing);
            var timeoutLabel = Glyphs.Label("Retrieval Timeout (Seconds)", true);
            timing.Children.Add(timeoutLabel);
            timeout = new TextBox { Text = "15", Width = 55 };
            timeoutLabel.Target = timeout;
            timing.Children.Add(timeout);
            Dialogs.Button(run, "_Validate", async () => await Validate());

            // Explain retrieval scope and create controls for cancellation and result exports.
            Dialogs.Note(editor, "Online retrieval checks each CRL location directly, including delta locations. " +
                "Offline mode uses local files and Windows caches. Supporting certificates are not trusted.");
            var footer = new StackPanel { Margin = new Thickness(0, 6, 0, 0) };
            DockPanel.SetDock(footer, Dock.Bottom);
            layout.Children.Add(footer);
            var controls = new WrapPanel { Margin = new Thickness(0, 0, 0, 1) };
            footer.Children.Add(controls);
            downloaded = new ComboBox { Width = 320, Margin = new Thickness(0, 0, 8, 4) };
            controls.Children.Add(downloaded);
            cancel = Dialogs.Button(controls, "_Cancel", () =>
            {
                // Request cancellation and wait for the current native retrieval to finish.
                cancellation?.Cancel();
                cancel.IsEnabled = false;
                status.Text = "Cancelling after the current Windows retrieval finishes…";
            });
            cancel.IsEnabled = false;
            saveCrl = Dialogs.Button(controls, "_Save CRL…", async () =>
            {
                // Save the selected inspected CRL using its original encoded bytes.
                if (downloaded.SelectedItem is not CrlResult selected) return;
                var save = new FilePicker(true) { FileName = selected.IsDelta ? "delta.crl" : "base.crl", Filter = "CRL|*.crl" };
                if (await save.ShowAsync() != true) return;
                try { File.WriteAllBytes(save.FileName, selected.Encoded); }
                catch (Exception error) { status.Text = CaAdministration.Error(error); }
            });
            saveCrl.IsEnabled = false;
            Dialogs.Button(controls, "Save _report…", async () =>
            {
                // Export the visible validation report as text.
                if (output.Text.Length == 0) return;
                var save = new FilePicker(true) { FileName = "Certificate-validation.txt", Filter = "Text|*.txt" };
                if (await save.ShowAsync() != true) return;
                try { File.WriteAllText(save.FileName, output.Text); }
                catch (Exception error) { status.Text = CaAdministration.Error(error); }
            });

            // Show inspected CRLs and a read-only diagnostic output area.
            status = new TextBlock { Text = "Ready. Validation does not change the CA.", TextWrapping = TextWrapping.Wrap };
            footer.Children.Add(status);
            output = new TextBox
            {
                IsReadOnly = true, AcceptsReturn = true, VerticalContentAlignment = VerticalAlignment.Top,
                FontFamily = new System.Windows.Media.FontFamily("Consolas"),
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto, HorizontalScrollBarVisibility = ScrollBarVisibility.Auto
            };
            Dialogs.CertificateMenu(output, () => certificate, ready: () => cancellation == null);
            layout.Children.Add(output);
            Content = layout;

            // Automatically validate a certificate supplied by another workspace action.
            var validateOnLoad = encoded != null;
            Loaded += async (sender, e) =>
            {
                if (!validateOnLoad) return;
                validateOnLoad = false;
                await Validate();
            };

            // Invalidate results whenever validation inputs or options change.
            issuerFiles.TextChanged += (sender, e) => ClearResult();
            crlFiles.TextChanged += (sender, e) => ClearResult();
            timeout.TextChanged += (sender, e) => ClearResult();
            foreach (var option in new[] { offline, retrieve, entireChain })
            {
                option.Checked += (sender, e) => ClearResult();
                option.Unchecked += (sender, e) => ClearResult();
            }
            // Request cancellation before allowing navigation away from active validation.
            Closing += (sender, e) =>
            {
                if (cancellation == null) return;
                e.Cancel = true;
                cancellation.Cancel();
                status.Text = "Waiting for validation to stop. Close again when it finishes.";
            };
        }

        private TextBox FileInput(Panel panel, string label, string caption, string filter)
        {
            // Pair a multiline path input with a file picker for supporting validation files.
            Dialogs.Note(panel, Dialogs.Caption(label));
            var line = new WrapPanel();
            panel.Children.Add(line);
            var box = new TextBox { AcceptsReturn = true, MinLines = 2, MaxLines = 2, Width = 520,
                Margin = new Thickness(0, 0, 8, 4),
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
            line.Children.Add(box);
            Dialogs.Button(line, caption, async () =>
            {
                // Replace the path list with the selected supporting files.
                var open = new FilePicker() { Filter = filter, Multiselect = true };
                if (await open.ShowAsync() == true) box.Text = string.Join(Environment.NewLine, open.FileNames);
            });
            return box;
        }

        private void ClearResult()
        {
            // Clear results that no longer correspond to the current validation inputs.
            output.Clear();
            downloaded.ItemsSource = null;
            saveCrl.IsEnabled = false;
            status.Text = "Inputs changed. Validate to refresh the report.";
        }

        private async Task Validate()
        {
            // Prevent simultaneous validations and show a busy cursor for the operation.
            if (cancellation != null) return;
            using var cursor = BusyCursor.Enter();
            try
            {
                // Validate the certificate and timeout before capturing the remaining options.
                if (certificate == null) throw new ArgumentException("Open a certificate first.");
                if (!int.TryParse(timeout.Text, out var seconds) || seconds is < 1 or > 120)
                    throw new ArgumentException("Set the retrieval timeout to 1–120 seconds.");
                var issuers = Paths(issuerFiles.Text);
                var crls = Paths(crlFiles.Text);
                var cached = offline.IsChecked == true;
                var fetch = retrieve.IsChecked == true;
                var wholeChain = entireChain.IsChecked == true;

                // Clear stale output and allow cancellation while the editor is locked.
                ClearResult();
                editor.IsEnabled = false;
                cancel.IsEnabled = true;
                status.Text = "Validating…";
                using (cancellation = new CancellationTokenSource())
                {
                    // Resolve permitted OID names and run native validation away from the UI thread.
                    var token = cancellation.Token;
                    var progress = new Progress<string>(message => status.Text = message);
                    var names = cached ? oids ?? OidNames.Windows :
                        await Task.Run(() => oids?.Refresh() ?? OidNames.Local, token);
                    if (!cached) oids = names;
                    var result = await Task.Run(() => CertificateValidation.Validate(certificate, issuers, crls,
                        cached, fetch, wholeChain, seconds, token, progress, names), token);

                    // Publish the completed report and enable export of its inspected CRLs.
                    token.ThrowIfCancellationRequested();
                    TimeDisplay.Text(output, () => result.Report.ToString());
                    downloaded.ItemsSource = result.Crls;
                    downloaded.SelectedIndex = result.Crls.Count > 0 ? 0 : -1;
                    saveCrl.IsEnabled = result.Crls.Count > 0;
                    status.Text = result.Summary;
                }
            }
            catch (OperationCanceledException) { status.Text = "Validation cancelled."; }
            catch (Exception error) { status.Text = CaAdministration.Error(error); }
            finally { cancellation = null; editor.IsEnabled = true; cancel.IsEnabled = false; }
        }

        private static string[] Paths(string text) => text.Split(new[] { '\r', '\n' },
            StringSplitOptions.RemoveEmptyEntries).Select(path => path.Trim().Trim('"'))
            .Where(path => path.Length > 0).ToArray();
    }
}
