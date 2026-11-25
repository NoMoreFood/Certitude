//
// Copyright (c) Bryan Berns.
// Licensed under GPLv3. See LICENSE.md.
//

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Markup;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using System.Xml;

namespace Certitude
{
    internal static partial class WorkflowChecks
    {
        private static readonly Dictionary<string, byte[]> fixtures = new Dictionary<string, byte[]>();
        private static readonly string[] targets = { "one\\CA One", "two\\CA Two", "three\\CA Three" };
        private const BindingFlags Private = BindingFlags.Instance | BindingFlags.NonPublic;

        [STAThread]
        private static int Main(string[] args)
        {
            try
            {
                if (args.Length == 2 && args[0] == "--probe-offline-maintenance")
                {
                    try { using var reservation = CaMaintenance.BeginOfflineMaintenance(args[1]); return 0; }
                    catch (InvalidOperationException) { return 2; }
                }

                // Render previews even when the unattended runner has no connected display.
                AppContext.SetSwitch(
                    "Switch.System.Windows.Media.ShouldRenderEvenWhenNoDisplayDevicesAreAvailable", true);
                RenderOptions.ProcessRenderMode = System.Windows.Interop.RenderMode.SoftwareOnly;
                var document = new XmlDocument();
                document.Load(Path.Combine(args[0], "Tests", "CrlFixtures.xml"));
                foreach (XmlElement element in document.DocumentElement.ChildNodes)
                    fixtures.Add(element.Name, Convert.FromBase64String(element.InnerText));
                CheckOfflineMaintenance();
                CheckAuthorityActions();
                CheckStatistics();
                CheckRenewedCrlKeys();
                CheckRevocations();
                var entries = CheckHealth();
                CheckReleasePaths(args[0]);
                CheckWorkspace(args[0], entries);
                Console.WriteLine("Release workflow checks passed, including loopback network diagnostics.");
                return 0;
            }
            catch (Exception error) { Console.Error.WriteLine(error); return 1; }
        }

        private static void Assert(bool condition, string message)
        {
            if (!condition) throw new InvalidOperationException(message);
        }

        private static void CheckOfflineMaintenance()
        {
            // A second process must fail promptly while the reservation is held and succeed after release.
            var mutexName = @"Global\Certitude.Test." + Guid.NewGuid().ToString("N");
            void Probe(bool busy)
            {
                using var child = Process.Start(new ProcessStartInfo(typeof(WorkflowChecks).Assembly.Location,
                    "--probe-offline-maintenance " + mutexName) { UseShellExecute = false, CreateNoWindow = true });
                if (!child.WaitForExit(10000))
                {
                    child.Kill();
                    throw new TimeoutException("The competing maintenance process did not finish.");
                }
                Assert(child.ExitCode == (busy ? 2 : 0),
                    "Unexpected maintenance reservation result: " + child.ExitCode);
            }

            using (CaMaintenance.BeginOfflineMaintenance(mutexName)) Probe(true);
            Probe(false);
        }

        private static void CheckAuthorityActions()
        {
            // Retain per-CA results and attempt each distinct authority even when individual calls fail.
            var calls = new List<string>();
            string Run(IEnumerable<string> names, Func<string, TimeReport> action, CancellationToken token = default)
            {
                calls.Clear();
                return CaAdministration.RunAuthorities(names, target =>
                {
                    calls.Add(target);
                    return action(target);
                }, token, null).ToString();
            }
            var report = Run(targets.Concat([targets[0].ToUpperInvariant()]), target => target == targets[1] ?
                throw new IOException("Access denied") : new TimeReport("Published on " + target));
            Assert(calls.SequenceEqual(targets) && targets.All(target => report.Contains("CA: " + target)) &&
                report.Contains("Access denied") && report.Contains("1 calls failed; 0 not attempted.") &&
                report.Contains("Published on " + targets[0]) && report.Contains("Published on " + targets[2]),
                "A failed or duplicate target changed the batch results.");
            report = Run(targets, target => throw new IOException("Offline"));
            Assert(calls.SequenceEqual(targets) && report.Contains("3 calls failed; 0 not attempted."),
                "Every offline authority must appear in the failure count.");

            // Cancellation preserves completed changes and leaves all remaining targets untouched.
            using var cancellation = new CancellationTokenSource();
            report = Run(targets, target => { cancellation.Cancel(); return new TimeReport("Published"); },
                cancellation.Token);
            Assert(calls.SequenceEqual(targets.Take(1)) && report.Contains("Published") &&
                report.Contains("2 not attempted.") && report.Contains("Completed CA changes remain applied"),
                "Cancellation lost the completed result or contacted another authority.");
            report = Run(targets, target => new TimeReport(), cancellation.Token);
            Assert(calls.Count == 0 && report.Contains("3 not attempted."), "A pre-cancelled batch contacted a CA.");
            foreach (var invalid in new string[][] { [targets[0], "All CAs"], [] })
            {
                Reject<ArgumentException>(() => Run(invalid, target => new TimeReport()),
                    "Invalid targets were accepted.");
                Assert(calls.Count == 0, "A CA was contacted before the whole target list was validated.");
            }

            // A failed certificate query must leave its authority available for administrative actions.
            var stores = targets.Select(name => new FixtureStore(name, [new CertificateRow
                { RequestId = 1, Disposition = 20 }])).ToArray();
            stores[1].FailAfter = 0;
            var all = new AllCertificateStore(stores);
            var page = all.ReadBrowserPage(new QuerySpec(), null, CancellationToken.None);
            Assert(page.Rows.Count == 2 && all.UnavailableCount == 1 &&
                new HashSet<string>(all.Configurations).SetEquals(targets),
                "A failed query hid an administrative target.");
        }

        private static void CheckStatistics()
        {
            // Verify the CA projection with absent values, mixed dispositions and dates on bucket boundaries.
            var now = new DateTime(2026, 1, 31, 12, 0, 0, DateTimeKind.Utc);
            DatabaseRecord[] rows =
            [
                new([4, "Web", "Alice", now.AddDays(-2), now.AddDays(7), 20, null, now.AddDays(-1), now, 0x100]),
                new([1, "web", "ALICE", null, now, 20, DBNull.Value, DBNull.Value, null, DBNull.Value]),
                new([3, null, null, null, null, 9, null, now.AddDays(-7), null, null]),
                new([2, "Mail", "Bob", now.AddDays(-1), now.AddDays(1), 21, 6, now.AddDays(-2), now.AddDays(-3), 0])
            ];
            var snapshot = CaStatistics.Aggregate(rows, OidNames.Windows, now, CancellationToken.None, null);
            Assert(snapshot.Total == 4 && snapshot.FirstId == 1 && snapshot.LastId == 4 &&
                snapshot.Valid == 1 && snapshot.Expired == 1 && snapshot.MissingValidity == 1 &&
                snapshot.Expiry.SequenceEqual([1L, 0, 0, 0, 0]) && snapshot.OldestPending == now.AddDays(-7) &&
                snapshot.Recent.SequenceEqual([1L, 3, 3]) && snapshot.MissingSubmission == 1 &&
                snapshot.TimedResolutions == 1 && snapshot.ResolutionSeconds == 86400 &&
                snapshot.DatedCertificates == 2 && snapshot.ValidityDays == 11, "CA statistics lost dates or counts.");
            Assert(snapshot.Templates[0].Count == 2 && snapshot.Templates[0].DueSoon == 1 &&
                snapshot.Templates[0].Expired == 1 && snapshot.Requesters[0].Count == 2 &&
                snapshot.Reasons.Single().Name == "Certificate Hold" &&
                snapshot.Types.Any(group => group.Name == "PKCS #10"),
                "CA statistics lost group membership or reasons.");
            rows[0].Values[0] = DBNull.Value;
            Reject<InvalidOperationException>(() => CaStatistics.Aggregate(rows, OidNames.Windows, now, default, null),
                "A missing request ID was accepted into a snapshot.");
        }

        private static void CheckRenewedCrlKeys()
        {
            // Certificate 1 has no readable version, certificate 2 is unreadable, and certificate 4 reuses key 3.
            var reads = new List<(int Property, int Index)>();
            var admin = new TestAdmin { ReadProperty = (property, index) =>
            {
                reads.Add((property, index));
                return property switch
                {
                    11 => 5,
                    12 when index == 2 => throw new InvalidOperationException("Certificate unavailable"),
                    12 => Convert.ToBase64String(fixtures["ca"]),
                    39 when index == 1 => throw new InvalidOperationException("Version unavailable"),
                    39 => ((index == 4 ? 3 : index) << 16) | index,
                    30 => 5, 31 => 6,
                    17 => Convert.ToBase64String(fixtures["base"]), 18 => Convert.ToBase64String(fixtures["delta"]),
                    _ => 0
                };
            } };
            var expected = new[] { 0, 2, 3 };
            var status = CaAdministration.CrlPublicationStatus(targets[0], admin);
            Assert(status.Contains("CRL key for CA certificate 1: Version unavailable") &&
                expected.All(key => status.Contains("CRL key index " + key + " · Base:")),
                "Publication status lost a key or the reason a renewal was skipped.");

            // The Statistics refresh must reuse the same count and keys for status and both metadata properties.
            reads.Clear();
            var statistics = new CaServerStatistics();
            statistics.ReadAuthorityProperties(targets[0], admin, CancellationToken.None);
            var versions = reads.Where(read => read.Property == 39).Select(read => read.Index);
            Assert(reads.Count(read => read.Property == 11) == 1 && versions.SequenceEqual(Enumerable.Range(0, 5)),
                "Statistics must read the signing count once and each certificate version once.");
            Assert(statistics.Authority.Single(row => row.Name == "CRL Publication").Value == status &&
                statistics.Authority.Count(row => row.Report != null) == expected.Length * 2,
                "Statistics lost publication status or CRL metadata after an unavailable renewal.");
            foreach (var property in new[] { 17, 18, 30, 31 })
                Assert(reads.Where(read => read.Property == property).Select(read => read.Index).OrderBy(key => key)
                    .SequenceEqual(expected), "A CRL property was skipped or queried twice for a reused key.");

            // Health must retain the unique key of an unreadable certificate and label key failures independently.
            var signers = new List<X509Certificate2>();
            var entries = new List<CrlHealthEntry>();
            try
            {
                var keys = CrlHealth.ReadSignersAndKeys(targets[0], admin, signers,
                    CancellationToken.None, entries.Add);
                Assert(keys.SetEquals(expected) && signers.Count == 4 &&
                    entries.Single(row => row.Item == "CA certificate 1").Expires.HasValue &&
                    entries.Single(row => row.Item == "CA certificate 2").Status == "Unavailable" &&
                    entries.Single(row => row.Item == "CRL key for CA certificate 1").Status == "Unavailable",
                    "Health conflated a signing-certificate failure with a CRL key failure.");
            }
            finally { foreach (var signer in signers) signer.Dispose(); }
        }

        private static void CheckRevocations()
        {
            // Exercise real per-record mutation handling and all-CA routing through an in-memory authority.
            var admin = new TestAdmin();
            var affected = new HashSet<string>();
            var store = new AllCertificateStore(targets.Select(target => new TestStore(target, admin)));
            var rows = new[] { Row(targets[0], 1, "ok"), Row(targets[0], 2, "denied"),
                Row(targets[1], 1, "denied"), Row(targets[2], 1, "ok") };
            var report = store.Apply(rows, "Revoke", 1, null, "", CancellationToken.None, null,
                config => affected.Add(config));
            Assert(affected.SetEquals(new[] { targets[0], targets[2] }) && report.Contains("Access denied"),
                "Only CAs with successful changes may be offered publication, even with duplicate request IDs.");
            affected.Clear();
            report = CaAdministration.Apply(admin, targets[0], new[] { rows[1] }, "Revoke", 1,
                null, "", CancellationToken.None, null, config => affected.Add(config));
            Assert(affected.Count == 0, "Total failure must not offer publication.");

            // Cancellation after a successful mutation must retain that target and skip later CAs.
            using var request = new CancellationTokenSource();
            admin.AfterRevoke = request.Cancel;
            affected.Clear();
            store.Apply(rows, "Revoke", 1, null, "", request.Token, null, config => affected.Add(config));
            Assert(affected.SetEquals(new[] { targets[0] }), "Cancellation lost or invented an affected CA.");
            admin.AfterRevoke = null;
            affected.Clear();
            var held = Row(targets[0], 3, "ok");
            held.Disposition = 21;
            held.RevocationReason = 6;
            CaAdministration.Apply(admin, targets[0], new[] { held }, "Release hold", 0, null, "",
                CancellationToken.None, null, config => affected.Add(config));
            Assert(affected.Contains(targets[0]) && admin.Reason == -1, "Hold release must also offer publication.");
        }

        private static CertificateRow Row(string target, int id, string serial) => new CertificateRow
            { Configuration = target, RequestId = id, SerialNumber = serial, Disposition = 20 };

        private static List<CrlHealthEntry> CheckHealth()
        {
            // Signed fixtures exercise native CRL decoding, issuing-key checks and real delta-URL discovery.
            using var ca = new X509Certificate2(fixtures["ca"]);
            using var other = new X509Certificate2(fixtures["wrongKey"]);
            using var forbidden = new X509Certificate2(fixtures["noCrlUsage"]);
            using var sample = new X509Certificate2(fixtures["sample"]);
            using var noUrls = new X509Certificate2(fixtures["noUrls"]);
            CrlResult Inspect(string name, params X509Certificate2[] issuers) =>
                CertificateValidation.InspectCrl(fixtures[name], name, null, issuers);
            var expected = new[] { Inspect("base", ca), Inspect("delta", ca) };
            Assert(expected.All(value => value.SignatureValid == true),
                "CA CRLs must be signature-checked even without a sample certificate.");
            var published = PublishedDirectory.ValidateArtifact(
                PublishedDirectory.Stores.Single(store => store.Id == "BaseCRL"), fixtures["base"], OidNames.Windows);
            Assert(published.Crl.NextUpdate.HasValue && published.Crl.SignatureValid == null,
                "Forest publication must still inspect CRLs when no signer certificates are supplied.");
            Assert(CrlHealth.CrlStatus(Inspect("base", other), false) == "Invalid signature",
                "Matching CA subjects with different keys must not validate a CRL.");
            Assert(CrlHealth.CrlStatus(Inspect("base", forbidden), false) == "Signer cannot sign CRLs",
                "CRL-sign key usage must be honored.");
            Assert(CrlHealth.CrlStatus(Inspect("expired", ca), false) == "Expired", "Expired CRLs must be visible.");
            Assert(CrlHealth.CrlStatus(Inspect("delta", ca), false) == "Wrong CRL type", "Delta is not a base CRL.");

            var entries = new List<CrlHealthEntry>();
            var calls = new List<string>();
            void Check(Func<string, List<byte[]>> retrieve, X509Certificate2 selected = null)
            {
                entries.Clear();
                calls.Clear();
                CrlHealth.CheckDistributionPoints(targets[0], selected ?? sample, new[] { ca, other }, expected,
                    CancellationToken.None, entries.Add, url => { calls.Add(url); return retrieve(url); });
            }
            Check(url =>
            {
                if (url.Contains("alternate")) throw new IOException("Simulated unreachable endpoint");
                return new List<byte[]> { fixtures[url.Contains("delta") ? "delta" : "base"] };
            });
            Assert(entries.Count(value => value.Status == "Current; matches CA") == 2 &&
                entries.Any(value => value.Status == "Unavailable") && calls.Count == 3,
                "An unreachable CDP must not hide the base or delta results.");
            Assert(entries.All(entry => entry.Details.ToString().Contains("CRL retrieval: Windows URL retrieval")),
                "CRL health omitted the retrieval route from a success or failure.");
            var preview = entries.ToList();
            Check(url => new List<byte[]> { fixtures[url.Contains("delta") ? "delta" : "oldBase"] });
            Assert(entries.Any(value => value.Status == "Current; differs from CA snapshot"),
                "A valid but older downloaded CRL must not be reported as matching the CA.");
            Check(url => new List<byte[]> { fixtures["wrongSignature"] });
            Assert(entries.All(value => value.Status != "Current; matches CA"),
                "A CRL signed with another CA key must not validate against the sample.");
            Check(url => throw new Exception("Unexpected retrieval"), noUrls);
            Assert(calls.Count == 0 && entries.Single().Status == "Not checked", "Missing CDPs are not healthy CDPs.");

            // A malformed object in a multi-object response must not discard valid objects beside it.
            Check(url => url.Contains("delta") ? new List<byte[]> { fixtures["delta"] } :
                new List<byte[]> { new byte[] { 1, 2, 3 }, fixtures["base"] });
            Assert(entries.Any(value => value.Status == "Current; matches CA") &&
                entries.Any(value => value.Status == "Unavailable"), "A malformed CRL hid later objects.");
            using var cancelled = new CancellationTokenSource();
            cancelled.Cancel();
            var stopped = false;
            try
            {
                CrlHealth.CheckDistributionPoints(targets[0], sample, new[] { ca }, expected, cancelled.Token,
                    entries.Add, url => throw new Exception("Unexpected retrieval"));
            }
            catch (OperationCanceledException) { stopped = true; }
            Assert(stopped, "A cancelled health check must not start retrieval.");
            return preview;
        }

        private static void CheckWorkspace(string repository, List<CrlHealthEntry> entries)
        {
            // Isolate all persistence and UI checks from the user's workspace and from CA discovery.
            var output = Path.Combine(repository, "Build", "Temp", "CrlWorkflowChecks");
            var path = Path.Combine(output, "workspace-" + Guid.NewGuid().ToString("N") + ".xml");
            typeof(BrowserWorkspace).GetField("DefaultPath", BindingFlags.Static | BindingFlags.NonPublic)
                .SetValue(null, path);
            var settings = BrowserWorkspace.Load(path);
            Assert(settings.PromptForCrlPublication, "The publication reminder must default to enabled.");
            settings.PromptForCrlPublication = false;
            settings.Save(path);
            Assert(!BrowserWorkspace.Load(path).PromptForCrlPublication, "Dismissal must survive a reload.");

            var app = new Application();
            SynchronizationContext.SetSynchronizationContext(new DispatcherSynchronizationContext(app.Dispatcher));
            var source = new XmlDocument();
            source.Load(Path.Combine(repository, "Code", "App.xaml"));
            app.Resources = (ResourceDictionary)XamlReader.Parse(
                "<ResourceDictionary xmlns='http://schemas.microsoft.com/winfx/2006/xaml/presentation' " +
                "xmlns:x='http://schemas.microsoft.com/winfx/2006/xaml' " +
                "xmlns:local='clr-namespace:Certitude;assembly=Certitude'>" +
                source.DocumentElement.FirstChild.InnerXml + "</ResourceDictionary>");
            var window = new MainWindow();
            app.MainWindow = window;
            window.Loaded -= (RoutedEventHandler)Delegate.CreateDelegate(typeof(RoutedEventHandler), window,
                typeof(MainWindow).GetMethod("WindowLoaded", Private));
            var preference = (BrowserWorkspace)Field(window, "savedWorkspace");
            preference.PromptForCrlPublication = true;
            var offer = (Task)Call(window, "OfferCrlPublication", (object)new[] { targets[0] });
            Render(window, Path.Combine(output, "publication-prompt.png"), 1);
            var suppress = Children(window.ActivePage).OfType<CheckBox>().Single();
            suppress.IsChecked = true;
            Click(window.ActivePage, "_Not Now");
            Complete(offer);
            Assert(!preference.PromptForCrlPublication && !BrowserWorkspace.Load(path).PromptForCrlPublication,
                "Don't show again must persist even when publication is declined.");

            // The preferences control re-enables the offer, and review opens only the confirmed affected targets.
            Call(window, "ManageViewsClick", null, null);
            var manager = (TabControl)window.ActivePage.Content;
            manager.SelectedIndex = 2;
            var toggle = Children(manager).OfType<CheckBox>().Single();
            toggle.IsChecked = true;
            toggle.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            Assert(BrowserWorkspace.Load(path).PromptForCrlPublication, "The reminder must be re-enableable.");
            CheckScep(window, path, output);
            Call(window, "ReturnToBrowser");
            offer = (Task)Call(window, "OfferCrlPublication", (object)new[] { targets[0], targets[2] });
            Click(window.ActivePage, "_Review Publication…");
            Complete(offer);
            Assert(((string[])Field(window.ActivePage, "configurations"))
                .SequenceEqual(new[] { targets[0], targets[2] }) &&
                ((TabControl)Field(window.ActivePage, "tabs")).Items.Count == 1,
                "Publication review must retain only the affected CAs and open the CRL form.");

            // Render the actual health controls with mixed results at normal and enlarged display scaling.
            var page = new CrlHealthPage(new AllCertificateStore(targets.Select(value => new CertificateStore(value))));
            var rows = (System.Collections.ObjectModel.ObservableCollection<CrlHealthEntry>)Field(page, "entries");
            foreach (var entry in entries) rows.Add(entry);
            ((DataGrid)Field(page, "grid")).SelectedIndex = 0;
            window.ShowPage(page);
            Render(window, Path.Combine(output, "crl-health.png"), 1);
            Render(window, Path.Combine(output, "crl-health-150.png"), 1.5);
            App.ApplyTheme(true, false);
            Render(window, Path.Combine(output, "crl-health-dark.png"), 1);
            CheckReleaseViews(window, output);
            File.Delete(path);
            File.Delete(path + ".lock");
            app.Shutdown();
        }

        private static object Field(object value, string name) =>
            value.GetType().GetField(name, Private).GetValue(value);
        private static void SetField(object target, string name, object value) =>
            target.GetType().GetField(name, Private).SetValue(target, value);
        private static object Call(object target, string name, params object[] arguments) =>
            target.GetType().GetMethod(name, Private).Invoke(target, arguments);

        private static IEnumerable<DependencyObject> Children(DependencyObject root)
        {
            yield return root;
            foreach (var child in LogicalTreeHelper.GetChildren(root).OfType<DependencyObject>())
                foreach (var item in Children(child)) yield return item;
        }
        private static void Click(DependencyObject page, string caption) => Children(page).OfType<Button>()
            .Single(button => Equals(button.Content, caption)).RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
        private static void Complete(Task task)
        {
            WaitFor(() => task.IsCompleted);
            task.GetAwaiter().GetResult();
        }

        private static void WaitFor(Func<bool> ready)
        {
            // Let asynchronous workspace continuations finish without blocking their dispatcher.
            var deadline = DateTime.UtcNow.AddSeconds(15);
            while (!ready())
            {
                Assert(DateTime.UtcNow < deadline, "The workspace operation did not complete within 15 seconds.");
                var frame = new DispatcherFrame();
                Dispatcher.CurrentDispatcher.BeginInvoke(DispatcherPriority.Background,
                    new Action(() => frame.Continue = false));
                Dispatcher.PushFrame(frame);
            }
        }
        private static void Render(MainWindow window, string path, double scale, double width = 900, double height = 620)
        {
            var root = (FrameworkElement)window.Content;
            root.LayoutTransform = new ScaleTransform(scale, scale);
            var size = new Size(width * scale, height * scale);
            root.Measure(size);
            root.Arrange(new Rect(size));
            root.UpdateLayout();
            window.Dispatcher.Invoke(new Action(() => { }), DispatcherPriority.ContextIdle);
            root.UpdateLayout();
            var bitmap = new RenderTargetBitmap((int)size.Width, (int)size.Height, 96, 96, PixelFormats.Pbgra32);
            var background = new DrawingVisual();
            using (var drawing = background.RenderOpen())
                drawing.DrawRectangle(window.Background, null, new Rect(size));
            bitmap.Render(background);
            bitmap.Render(root);
            var pixels = new byte[bitmap.PixelWidth * bitmap.PixelHeight * 4];
            bitmap.CopyPixels(pixels, bitmap.PixelWidth * 4, 0);
            Assert(pixels.Where((value, index) => index % 4 != 3).Distinct().Count() > 20,
                "The workspace preview is blank.");
            var encoder = new PngBitmapEncoder();
            encoder.Frames.Add(BitmapFrame.Create(bitmap));
            using var stream = File.Create(path);
            encoder.Save(stream);
        }
    }

    internal sealed class TestStore(string configuration, TestAdmin admin) : CertificateStore(configuration)
    {
        internal override string Apply(IReadOnlyList<CertificateRow> rows, string action, int reason,
            DateTime? effective, string attributes, CancellationToken token, Action<int> progress,
            Action<string> revocationChanged = null) =>
            CaAdministration.Apply(admin, Configuration, rows, action, reason, effective, attributes,
                token, progress, revocationChanged);
    }

    internal sealed class TestAdmin : ICertAdmin
    {
        public Action AfterRevoke;
        public Func<int, int, object> ReadProperty = (id, index) => throw new NotSupportedException();
        public int Reason;
        public void RevokeCertificate(string config, string serial, int reason, double date)
        {
            if (serial == "denied") throw new UnauthorizedAccessException("Access denied");
            Reason = reason;
            AfterRevoke?.Invoke();
        }
        public int IsValidCertificate(string config, string serial) => throw new NotSupportedException();
        public int GetRevocationReason() => throw new NotSupportedException();
        public void SetRequestAttributes(string config, int id, string attributes) => throw new NotSupportedException();
        public void SetCertificateExtension(string config, int id, string name, int type, int flags, IntPtr value) =>
            throw new NotSupportedException();
        public void DenyRequest(string config, int id) => throw new NotSupportedException();
        public int ResubmitRequest(string config, int id) => throw new NotSupportedException();
        public void PublishCRL(string config, double date) => throw new NotSupportedException();
        public string GetCRL(string config, int flags) => throw new NotSupportedException();
        public int ImportCertificate(string config, string certificate, int flags) => throw new NotSupportedException();
        public void PublishCRLs(string config, double date, int flags) => throw new NotSupportedException();
        public object GetCAProperty(string config, int id, int index, int type, int flags) =>
            ReadProperty(id, index);
        public void SetCAProperty(string config, int id, int index, int type, IntPtr value) =>
            throw new NotSupportedException();
        public int GetCAPropertyFlags(string config, int id) => 1;
        public string GetCAPropertyDisplayName(string config, int id) => "Property " + id;
        public string GetArchivedKey(string config, int id, int flags) => throw new NotSupportedException();
        public object GetConfigEntry(string config, string node, string name) => throw new NotSupportedException();
        public void SetConfigEntry(string config, string node, string name, IntPtr value) =>
            throw new NotSupportedException();
        public void ImportKey(string config, int id, string hash, int flags, string key) =>
            throw new NotSupportedException();
        public int GetMyRoles(string config) => throw new NotSupportedException();
        public int DeleteRow(string config, int flags, double date, int table, int id) =>
            throw new NotSupportedException();
    }
}
