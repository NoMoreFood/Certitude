//
// Copyright (c) Bryan Berns.
// Licensed under GPLv3. See LICENSE.md.
//

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;

namespace Certitude
{
    internal static partial class WorkflowChecks
    {
        private static void Reject<T>(Action action, string message) where T : Exception
        {
            try { action(); }
            catch (T) { return; }
            throw new InvalidOperationException(message);
        }

        private static void CheckReleasePaths(string repository)
        {
            var output = Path.Combine(repository, "Build", "Temp", "CrlWorkflowChecks", "files");
            Directory.CreateDirectory(output);

            // Public PEM inspection must consume the whole bundle and never accept a mislabeled key container.
            string Pem(string label, byte[] bytes) => "-----BEGIN " + label + "-----\r\n" +
                Convert.ToBase64String(bytes, Base64FormattingOptions.InsertLineBreaks) +
                "\r\n-----END " + label + "-----\r\n";
            var certificate = Pem("CERTIFICATE", fixtures["ca"]);
            var bundle = Encoding.ASCII.GetBytes(certificate + Pem("CERTIFICATE", fixtures["sample"]));
            Assert(CertificateUtilities.ReadFile(bundle, null, CancellationToken.None, OidNames.Windows).Count == 2,
                "A public PEM bundle must retain both certificates.");
            var chain = Encoding.ASCII.GetBytes(Pem("PKCS7", CertificateUtilities.DecodePublicPem(bundle)));
            Assert(CertificateUtilities.ReadFile(chain, null, CancellationToken.None, OidNames.Windows).Count == 2,
                "A PKCS #7 PEM chain must retain both certificates.");
            foreach (var encoding in new[] { new UTF8Encoding(true), Encoding.Unicode, Encoding.BigEndianUnicode })
            {
                var encoded = encoding.GetPreamble().Concat(encoding.GetBytes(Encoding.ASCII.GetString(bundle))).ToArray();
                Assert(CertificateUtilities.ReadFile(encoded, null, CancellationToken.None, OidNames.Windows).Count == 2,
                    "A byte-order mark must not bypass complete PEM bundle inspection.");
            }
            foreach (var malformed in new[] { certificate + "-----BEGIN CERTIFICATE-----\r\nAA==",
                certificate + "trailing garbage", certificate + Pem("PRIVATE KEY", new byte[] { 1, 2, 3 }),
                Pem("PKCS7", fixtures["ca"]) })
                Reject<ArgumentException>(() => CertificateUtilities.DecodePublicPem(
                    Encoding.ASCII.GetBytes(malformed)),
                    "A malformed or mislabeled public PEM bundle was silently accepted.");
            using (var publicCertificate = new X509Certificate2(fixtures["ca"]))
            {
                var pfx = publicCertificate.Export(X509ContentType.Pkcs12, "");
                Reject<ArgumentException>(() => CertificateUtilities.DecodePublicPem(
                    Encoding.ASCII.GetBytes(certificate + Pem("CERTIFICATE", pfx))),
                    "A PFX concealed inside public certificate armor must be rejected before import.");
            }

            // File validation and comparison must read identical artifacts across supported text encodings.
            var artifactPath = Path.Combine(output, "artifact.pem");
            using (var rsa = RSA.Create())
            {
                rsa.KeySize = 2048;
                var request = new CertificateRequest("CN=encoding.example.com", rsa,
                    HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).CreateSigningRequest();
                foreach (var artifact in new[] { (Label: "CERTIFICATE", Bytes: fixtures["ca"]),
                    (Label: "X509 CRL", Bytes: fixtures["base"]), (Label: "CERTIFICATE REQUEST", Bytes: request),
                    (Label: "NEW CERTIFICATE REQUEST", Bytes: request) })
                {
                    var pem = Pem(artifact.Label, artifact.Bytes);
                    var encodings = new List<byte[]> { artifact.Bytes,
                        Encoding.ASCII.GetBytes(Convert.ToBase64String(artifact.Bytes)), Encoding.ASCII.GetBytes(pem) };
                    foreach (var encoding in new[] { new UTF8Encoding(true), Encoding.Unicode, Encoding.BigEndianUnicode })
                        encodings.Add(encoding.GetPreamble().Concat(encoding.GetBytes(pem)).ToArray());
                    var expected = ComparisonData.Read(artifact.Bytes, artifactPath, CancellationToken.None);
                    foreach (var bytes in encodings)
                    {
                        File.WriteAllBytes(artifactPath, bytes);
                        Assert(CertificateUtilities.ReadEncoded(artifactPath).SequenceEqual(artifact.Bytes),
                            "Reading an encoded artifact changed its payload.");
                        var actual = ComparisonSource.File(artifactPath).Read(CancellationToken.None);
                        Assert(actual.Kind == expected.Kind &&
                            !ComparisonDocument.Compare(expected, actual).Any(row => row.Different),
                            "Text encoding changed the artifact's comparison properties.");
                        if (artifact.Label == "CERTIFICATE")
                            Assert(CertificateValidation.ReadCertificate(artifactPath).SequenceEqual(fixtures["ca"]),
                                "Certificate validation rejected a supported file encoding.");
                        else if (artifact.Label == "X509 CRL")
                            PublishedDirectory.ValidateArtifact(PublishedDirectory.Stores.Single(store =>
                                store.Id == "BaseCRL"), CertificateUtilities.DecodeObject(bytes, "X509 CRL", "CRL"),
                                OidNames.Windows);
                        else
                            Assert(CertificateUtilities.DecodeObject(bytes, "CERTIFICATE REQUEST",
                                "NEW CERTIFICATE REQUEST").SequenceEqual(request), "Request decoding changed the CSR.");
                    }
                }
            }
            foreach (var malformed in new[] { certificate + certificate, certificate + "trailing data",
                certificate.Replace("END CERTIFICATE", "END X509 CRL"), "-----BEGIN CERTIFICATE-----\r\nAA==" })
            {
                File.WriteAllText(artifactPath, malformed, Encoding.Unicode);
                Reject<ArgumentException>(() => CertificateValidation.ReadCertificate(artifactPath),
                    "Single-certificate validation accepted incomplete or multiple PEM objects.");
                Reject<ArgumentException>(() => ComparisonSource.File(artifactPath).Read(CancellationToken.None),
                    "Comparison silently ignored malformed PEM contents.");
            }
            Reject<ArgumentException>(() => CertificateUtilities.DecodeObject(Encoding.ASCII.GetBytes(certificate),
                "CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST"), "Request submission accepted certificate armor.");
            Reject<ArgumentException>(() => CertificateUtilities.DecodeObject(bundle, "X509 CRL", "CRL"),
                "CRL publication accepted a certificate bundle.");
            Reject<InvalidDataException>(() => ComparisonData.Read(fixtures["ca"].Concat(new byte[] { 0 }).ToArray(),
                artifactPath, CancellationToken.None), "Comparison silently ignored trailing DER data.");

            // Single-certificate validation must not silently inspect only the first object in a DER file.
            foreach (var suffix in new[] { new byte[] { 0 }, fixtures["sample"] })
            {
                File.WriteAllBytes(artifactPath, fixtures["ca"].Concat(suffix).ToArray());
                Reject<ArgumentException>(() => CertificateValidation.ReadCertificate(artifactPath),
                    "Certificate validation silently ignored trailing DER data or another certificate.");
            }

            // A sharing violation during publication must preserve the destination and remove temporary output.
            var path = Path.Combine(output, "export.csv");
            var original = Encoding.UTF8.GetBytes("Existing export");
            File.WriteAllBytes(path, original);
            using (File.Open(path, FileMode.Open, FileAccess.Read, FileShare.Read))
                Reject<IOException>(() => CertificateUtilities.WriteAtomic(path, fixtures["ca"]),
                    "Replacement of a locked destination unexpectedly succeeded.");
            Assert(File.ReadAllBytes(path).SequenceEqual(original) && Directory.GetFiles(output, "*.tmp").Length == 0,
                "A failed atomic write damaged the destination or left temporary files.");

            // Failed and cancelled streaming exports must not publish partial rows.
            var rows = Enumerable.Range(1, 1500).Select(id => new CertificateRow
            {
                Configuration = targets[0], RequestId = id, Disposition = 20,
                CommonName = id == 1 ? "=SUM(1,2)" : "service\"" + id + ",example", Requester = "test"
            }).ToArray();
            var source = new FixtureStore(targets[0], rows) { FailAfter = 500 };
            var query = new QuerySpec { PageSize = 17 };
            var columns = new[] { "RequestID", "CommonName" };
            Reject<IOException>(() => source.Export(query, path, CancellationToken.None, null, columns),
                "A failed CA scan was published as a successful export.");
            Assert(File.ReadAllBytes(path).SequenceEqual(original), "A failed export replaced the destination.");
            source.FailAfter = -1;
            using (var cancellation = new CancellationTokenSource())
            {
                source.AfterRow = count => { if (count == 600) cancellation.Cancel(); };
                Reject<OperationCanceledException>(() => source.Export(query, path, cancellation.Token, null, columns),
                    "A cancelled export was published.");
                Assert(File.ReadAllBytes(path).SequenceEqual(original), "Cancellation replaced the previous export.");
            }
            source.AfterRow = null;
            Assert(source.Export(query, path, CancellationToken.None, null, columns) == rows.Length,
                "Export incorrectly stopped at the browser page size.");
            var csv = File.ReadAllText(path);
            Assert(csv.Contains("\"'=SUM(1,2)\"") && csv.Contains("\"service\"\"2,example\""),
                "CSV export did not escape formulas, quotes and commas.");
            var completed = File.ReadAllBytes(path);
            Reject<IOException>(() => source.Export(query, path, CancellationToken.None, null, columns,
                overwrite: false), "An export overwrote a file without overwrite permission.");
            Assert(File.ReadAllBytes(path).SequenceEqual(completed) && Directory.GetFiles(output, "*.tmp").Length == 0,
                "Export cleanup or overwrite protection failed.");

            // A producer that fails after emitting rows must abort the merged result and unblock its peers.
            source.FailAfter = 500;
            var merged = new AllCertificateStore(new[] { source, new FixtureStore(targets[1], rows) });
            Reject<InvalidOperationException>(() => merged.Export(query, path, CancellationToken.None, null, columns),
                "A partial multi-CA export was accepted as complete.");
            Assert(File.ReadAllBytes(path).SequenceEqual(completed),
                "A partial multi-CA export replaced the destination.");
            foreach (var ordered in new[] { false, true })
            {
                merged = new AllCertificateStore(new[] { source, new FixtureStore(targets[1], rows) });
                Reject<InvalidOperationException>(() => merged.ReadRows(query, null, CancellationToken.None, ordered)
                    .ToArray(), "A failed producer was not surfaced by the merged query.");
                source.FailAfter = -1;
                merged = new AllCertificateStore(new[] { source, new FixtureStore(targets[1], rows) });
                Assert(merged.ReadRows(query, null, CancellationToken.None, ordered).Take(1).Count() == 1,
                    "Ending a merged query early did not release its producers.");
                source.FailAfter = 500;
            }

            // Paging across equal IDs on different authorities must visit every record exactly once in both orders.
            foreach (var direction in new[] { ListSortDirection.Ascending, ListSortDirection.Descending })
            {
                var authorities = targets.Select(target => new FixtureStore(target,
                    new[] { 1, 2, 3, int.MaxValue }.Select(id => Row(target, id, "ok")).ToArray())).ToArray();
                var all = new AllCertificateStore(authorities);
                var seen = new List<CertificateRow>();
                CertificateRow cursor = null;
                for (var pageNumber = 0; ; pageNumber++)
                {
                    Assert(pageNumber < 20, "Multi-CA paging failed to advance.");
                    var page = all.ReadBrowserPage(new QuerySpec { PageSize = 2 }, cursor,
                        CancellationToken.None, direction);
                    seen.AddRange(page.Rows);
                    if (!page.HasMore) break;
                    cursor = page.Rows.Last();
                }
                var expected = CertificateStore.SortRows(authorities.SelectMany(authority => authority.Rows),
                    nameof(CertificateRow.RequestId), direction, CancellationToken.None);
                Assert(seen.Select(row => row.Configuration + ":" + row.RequestId).SequenceEqual(
                    expected.Select(row => row.Configuration + ":" + row.RequestId)),
                    "Equal-ID multi-CA pagination skipped, repeated or reordered records.");
            }

            // Competing workspace instances must reject stale saves and preserve the current valid settings.
            path = Path.Combine(output, "workspace.xml");
            File.Delete(path);
            var first = BrowserWorkspace.Load(path);
            first.Save(path);
            var stale = BrowserWorkspace.Load(path);
            first.UseUtc = true;
            first.Save(path);
            Reject<IOException>(() => stale.Save(path), "A stale workspace overwrote newer settings.");
            completed = File.ReadAllBytes(path);
            first.Current.Columns.Add(new BrowserColumn { Key = "CommonName", Width = double.NaN });
            Reject<InvalidDataException>(() => first.Save(path), "An invalid layout was saved.");
            Assert(File.ReadAllBytes(path).SequenceEqual(completed) && BrowserWorkspace.Load(path).UseUtc,
                "Workspace validation damaged the saved settings.");

            // Measure the real streaming writer on a large synthetic inventory without a native CA dependency.
            source = new FixtureStore(targets[0], Enumerable.Range(1, 100000)
                .Select(id => new CertificateRow { RequestId = id, Disposition = 20, CommonName = "server-" + id })
                .ToArray());
            var watch = Stopwatch.StartNew();
            Assert(source.Export(query, Path.Combine(output, "large.csv"), CancellationToken.None, null, columns) ==
                100000, "The large export lost rows.");
            Console.WriteLine($"100,000-row CSV export: {watch.Elapsed.TotalMilliseconds:N0} ms.");
            Console.WriteLine("Encoded artifacts, PEM bundles, atomic output, CSV, cancellation, " +
                "multi-CA paging and workspace checks passed.");
        }

        private static void CheckReleaseViews(MainWindow window, string output)
        {
            // Render all locally constructible workspaces without showing a window or contacting external services.
            var manager = new CertificateToolsWindow(names: OidNames.Windows);

            // Opening a bundle stays read-only; importing the same file must stop at the review page.
            var bundlePath = Path.Combine(output, "manager.p7b");
            var bundle = new X509Certificate2Collection();
            using (var first = new X509Certificate2(fixtures["ca"]))
            using (var second = new X509Certificate2(fixtures["sample"]))
            {
                bundle.Add(first);
                bundle.Add(second);
                File.WriteAllBytes(bundlePath, bundle.Export(X509ContentType.Pkcs7));
            }
            window.ShowPage(manager);
            foreach (var import in new[] { false, true })
            {
                var previous = Field(manager, "rows");
                var operation = (Task)typeof(CertificateToolsWindow).GetMethod("OpenFile", Private)
                    .Invoke(manager, new object[] { import });
                var selected = (FilePicker)window.ActivePage;
                selected.FileName = bundlePath;
                selected.DialogResult = true;
                if (import) Complete(CancelImport());
                Complete(operation);
                Assert(Field(manager, "loadedStore") == null &&
                    ((List<InventoryCertificate>)Field(manager, "rows")).Count == 2,
                    "Opening a bundle did not produce a read-only inventory of both certificates.");
                if (import) Assert(ReferenceEquals(previous, Field(manager, "rows")),
                    "Cancelling import changed the displayed inventory.");

                async Task CancelImport()
                {
                    while (window.ActivePage.Title != "Review Certificate Import")
                    {
                        Assert(!operation.IsCompleted, "Import bypassed its review page.");
                        await Task.Delay(10);
                    }
                    var review = window.ActivePage;
                    Assert(Children(review).OfType<TextBlock>().Any(text =>
                        text.Text.Contains("Import all 2 certificate(s)")), "Import review omitted bundle members.");
                    Assert(Children(review).OfType<CheckBox>().All(box => !box.IsEnabled),
                        "A public certificate bundle incorrectly offered private-key exportability.");
                    review.DialogResult = false;
                }
            }
            window.ClosePage(manager, null);
            ((TabControl)Field(manager, "tabs")).SelectedIndex = 2;
            typeof(CertificateToolsWindow).GetField("enrollmentResult", Private).SetValue(manager,
                new EnrollmentResult { Certificate = fixtures["ca"] });
            ((TextBox)Field(manager, "subject")).Clear();
            Complete((System.Threading.Tasks.Task)typeof(CertificateToolsWindow).GetMethod("CreateCsr", Private)
                .Invoke(manager, null));
            Assert(Field(manager, "enrollmentResult") == null &&
                ((TextBox)Field(manager, "enrollmentOutput")).Text.Contains("Operation failed"),
                "A failed new enrollment must not leave the previous issued certificate available for export.");
            ((TextBox)Field(manager, "subject")).Text = "CN=server.example.com";
            ((TextBox)Field(manager, "enrollmentOutput")).Clear();
            ((TextBlock)Field(manager, "status")).Text = "Ready.";
            ((TabControl)Field(manager, "tabs")).SelectedIndex = 0;
            var picker = new FilePicker(true) { FileName = "certificate.cer" };
            typeof(FilePicker).GetField("patterns", Private).SetValue(picker, new[] { "*.cer" });
            var formats = (ComboBox)Field(picker, "formats");
            formats.ItemsSource = new[] { "Certificate" };
            formats.SelectedIndex = 0;
            typeof(FilePicker).GetField("initialized", Private).SetValue(picker, true);
            ((TextBox)Field(picker, "folder")).Text = output;

            // File checks must lock the selection and restore interaction after either acceptance or failure.
            var disabled = false;
            picker.IsEnabledChanged += (sender, args) => { if (!(bool)args.NewValue) disabled = true; };
            var selectedName = "selection-" + Guid.NewGuid().ToString("N") + ".cer";
            ((TextBox)Field(picker, "names")).Text = selectedName;
            window.ShowPage(picker);
            Complete((Task)typeof(FilePicker).GetMethod("Accept", Private).Invoke(picker, null));
            Assert(disabled && picker.IsEnabled && picker.FileName == Path.Combine(output, selectedName) &&
                window.ActivePage != picker,
                "File selection remained editable during acceptance or failed to complete.");
            window.ShowPage(picker);
            ((TextBox)Field(picker, "names")).Text = Path.Combine(selectedName, "missing.cer");
            Complete((Task)typeof(FilePicker).GetMethod("Accept", Private).Invoke(picker, null));
            Assert(picker.IsEnabled && window.ActivePage == picker && picker.FileNames.Length == 1 &&
                picker.FileName == Path.Combine(output, selectedName) &&
                ((TextBlock)Field(picker, "status")).Text.Contains("destination folder does not exist"),
                "A failed file check changed the accepted selection or left the picker disabled.");
            window.ClosePage(picker, null);
            ((TextBlock)Field(picker, "status")).Text = "";
            ((TextBox)Field(picker, "names")).Text = "certificate.cer";
            var published = new PublishedPage();
            typeof(PublishedPage).GetField("initialized", Private).SetValue(published, true);
            var policies = new OidManagerPage();
            typeof(OidManagerPage).GetField("initialized", Private).SetValue(policies, true);
            var pages = new (string Name, WorkspacePage Page)[]
            {
                ("file-picker", picker), ("manager", manager), ("validation", new ValidationWindow()),
                ("details", new DetailsWindow(fixtures["ca"])), ("oid-manager", policies),
                ("published", published), ("comparison", new ComparisonPage())
            };
            foreach (var dark in new[] { false, true })
            {
                App.ApplyTheme(dark, false);
                var theme = dark ? "dark" : "light";
                foreach (var entry in pages)
                {
                    window.ShowPage(entry.Page);
                    Render(window, Path.Combine(output, entry.Name + "-" + theme + ".png"), 1);
                    Assert(!entry.Page.IsLoaded, "Preview rendering must not trigger live initialization.");
                    if (entry.Page == manager)
                    {
                        var tabs = (TabControl)Field(manager, "tabs");
                        for (var index = 1; index < tabs.Items.Count; index++)
                        {
                            tabs.SelectedIndex = index;
                            Render(window, Path.Combine(output, "manager-" + index + "-" + theme + ".png"), 1);
                        }
                        tabs.SelectedIndex = 0;
                    }
                    if (!dark)
                    {
                        window.FontSize = 18;
                        Render(window, Path.Combine(output, entry.Name + "-text-150.png"), 1);
                        if (entry.Page == manager)
                        {
                            var location = (ComboBox)Field(manager, "location");
                            var label = new TextBlock { Text = (string)location.SelectedItem,
                                FontFamily = location.FontFamily, FontSize = location.FontSize };
                            label.Measure(new Size(double.PositiveInfinity, double.PositiveInfinity));
                            Assert(location.ActualWidth + 1 >= label.DesiredSize.Width + 30,
                                "The selected store location is clipped with enlarged text.");
                        }
                        window.FontSize = 12;
                    }
                    window.ClosePage(entry.Page, null);
                }
            }
            Console.WriteLine("Workspace previews rendered in both themes at minimum window dimensions.");

            // Enlarged text must fit the shared table rows without losing glyphs above or below the baseline.
            var table = new DataGrid { FontSize = 24, ItemsSource = new[] { new { Value = "Signing Key" } } };
            var column = new DataGridTextColumn
                { Header = "Certificate", Binding = new System.Windows.Data.Binding("Value") };
            table.Columns.Add(column);
            var tablePage = new WorkspacePage { Title = "Table Scaling", Content = table };
            window.ShowPage(tablePage);
            Render(window, Path.Combine(output, "table-text-200.png"), 1);
            var row = (DataGridRow)table.ItemContainerGenerator.ContainerFromIndex(0);
            var cell = column.GetCellContent(row);
            cell.Measure(new Size(double.PositiveInfinity, double.PositiveInfinity));
            Assert(row.ActualHeight >= cell.DesiredSize.Height, "Enlarged table text is vertically clipped.");
            window.ClosePage(tablePage, null);

            // Exercise the browser's real loading path with local fixtures and render a documentation preview.
            typeof(MainWindow).GetMethod("ReturnToBrowser", Private).Invoke(window, null);
            var configuration = @"pki01.example.com\Example Issuing CA";
            var hosts = new[] { "portal", "vpn", "api", "mail", "files", "dc01" };
            var browserRows = Enumerable.Range(1, 18).Select(id => new CertificateRow
            {
                Configuration = configuration, RequestId = 50000 + id, Disposition = 20,
                CommonName = hosts[(id - 1) % hosts.Length] + (id > 6 ? "-" + ((id - 1) / 6 + 1) : "") + ".example.com",
                Requester = @"EXAMPLE\" + (id % 6 == 0 ? "DC01$" : "svc-enrollment"),
                Template = id % 6 == 0 ? "Domain Controller" : "Web Server",
                NotBefore = DateTime.UtcNow.Date.AddDays(-id), NotAfter = DateTime.UtcNow.Date.AddDays(365 - id),
                SerialNumber = "120000" + id.ToString("X4")
            }).ToArray();
            typeof(MainWindow).GetField("store", Private).SetValue(window, new FixtureStore(configuration, browserRows));
            window.ConfigurationBox.Text = window.TargetText.Text = configuration;
            Complete((Task)typeof(MainWindow).GetMethod("LoadPage", Private).Invoke(window,
                new object[] { new QuerySpec { Match = SearchMatch.Contains }, null, 0, true }));
            Assert(window.Certificates.Items.Count == browserRows.Length && window.ExportButton.IsEnabled &&
                window.ResultsLoading.Visibility == Visibility.Collapsed,
                "The browser did not publish its completed page or clear loading state.");
            window.StatusText.Text = "Sample Data · 18 Issued Certificates · No Live CA Connection";
            window.SearchHint.Text = "Search And Sorting Cover All Matching Records";
            Render(window, Path.Combine(output, "browser-dark.png"), 1, 1280, 800);
        }
    }

    internal sealed class FixtureStore(string configuration, CertificateRow[] rows) : CertificateStore(configuration)
    {
        internal CertificateRow[] Rows => rows;
        internal int FailAfter = -1;
        internal Action<int> AfterRow;

        public override IEnumerable<CertificateRow> ReadRows(QuerySpec query, int? before,
            CancellationToken token, bool ordered = true, string[] fields = null, bool ascending = false)
        {
            var count = 0;
            var selected = rows.Where(row => !before.HasValue || (ascending ?
                row.RequestId > before : row.RequestId < before)).Where(query.Matches);
            if (ordered) selected = ascending ? selected.OrderBy(row => row.RequestId) :
                selected.OrderByDescending(row => row.RequestId);
            foreach (var row in selected)
            {
                token.ThrowIfCancellationRequested();
                if (count == FailAfter) throw new IOException("Simulated CA connection loss");
                yield return row;
                count++;
                AfterRow?.Invoke(count);
            }
        }
    }
}
