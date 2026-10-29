//
// Copyright (c) Bryan Berns.
// Licensed under GPLv3. See LICENSE.md.
//

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;

namespace Certitude
{
    internal sealed class CrlHealthEntry
    {
        public string Configuration { get; set; }
        public string Item { get; set; }
        public string Status { get; set; }
        public DateTime? Expires { get; set; }
        public string Source { get; set; }
        public TimeReport Details { get; set; }
    }

    internal static class CrlHealth
    {
        internal static void Read(string configuration, CancellationToken token, Action<CrlHealthEntry> report)
        {
            // Keep signing certificates alive through both CA metadata and distribution-point checks.
            var signers = new List<X509Certificate2>();
            var crls = new List<CrlResult>();
            void Add(string item, string status, string source, TimeReport details, DateTime? expires = null) =>
                report(new CrlHealthEntry { Configuration = configuration, Item = item, Status = status,
                    Source = source, Details = details, Expires = expires });
            void Failed(string item, Exception error) =>
                Add(item, "Unavailable", configuration, new TimeReport(CaAdministration.Error(error)));
            try
            {
                // Isolate unavailable CA properties so the remaining health checks can still complete.
                token.ThrowIfCancellationRequested();
                try
                {
                    CaAdministration.Use(configuration, admin =>
                    {
                        var count = Convert.ToInt32(admin.GetCAProperty(configuration, 11, 0, 1, 0));
                        if (count < 1 || count > 1024)
                            throw new InvalidOperationException(
                                "The CA returned an invalid signing certificate count.");
                        var keys = new HashSet<int>();
                        for (var index = 0; index < count; index++)
                        {
                            token.ThrowIfCancellationRequested();
                            try
                            {
                                var certificate = new X509Certificate2(Convert.FromBase64String(Convert.ToString(
                                    admin.GetCAProperty(configuration, 12, index, 3, 1))));
                                signers.Add(certificate);
                                var start = certificate.NotBefore.ToUniversalTime();
                                var end = certificate.NotAfter.ToUniversalTime();
                                var now = DateTime.UtcNow;
                                var status = end <= now ? "Expired" : start > now ? "Not yet valid" :
                                    end <= now.AddDays(30) ? "Expires within 30 days" : "Current";
                                Add("CA certificate " + index, status, certificate.Subject,
                                    new TimeReport("CA signing certificate: " + certificate.Subject + "\r\n")
                                        .AppendLine("Thumbprint: " + certificate.Thumbprint)
                                        .Append("Valid from: ").AppendTime(start).AppendLine()
                                        .Append("Expires: ").AppendTime(end), end);
                                keys.Add((Convert.ToInt32(admin.GetCAProperty(configuration, 39, index, 1, 0)) >> 16)
                                    & 0xffff);
                            }
                            catch (Exception error) { Failed("CA certificate " + index, error); }
                        }

                        // A disabled delta schedule is different from a failed or unreadable delta CRL.
                        bool? deltas = null;
                        token.ThrowIfCancellationRequested();
                        try
                        {
                            deltas = Convert.ToInt32(admin.GetConfigEntry(
                                configuration, "", "CRLDeltaPeriodUnits")) > 0;
                        }
                        catch (Exception error) { Failed("Delta CRL settings", error); }
                        foreach (var key in keys)
                        {
                            foreach (var delta in new[] { false, true })
                            {
                                token.ThrowIfCancellationRequested();
                                var item = (delta ? "Delta" : "Base") + " CRL · key " + key;
                                if (delta && deltas == false)
                                {
                                    Add(item, "Disabled", configuration,
                                        new TimeReport("Delta CRL publication is disabled on this CA."));
                                    continue;
                                }
                                try
                                {
                                    var flags = Convert.ToInt32(admin.GetCAProperty(configuration,
                                        delta ? 31 : 30, key, 1, 0));
                                    var status = (flags & 0x3fb0) != 0 ? "Publication errors" :
                                        (flags & 4) != 0 ? "Publication completed" : "Publication not confirmed";
                                    Add(item + " publication", status, configuration,
                                        new TimeReport(CaAdministration.FormatCrlPublicationStatus(flags)));
                                }
                                catch (Exception error) { Failed(item + " publication", error); }
                                token.ThrowIfCancellationRequested();
                                try
                                {
                                    var bytes = Convert.FromBase64String(Convert.ToString(admin.GetCAProperty(
                                        configuration, delta ? 18 : 17, key, 3, 1)));
                                    var crl = CertificateValidation.InspectCrl(bytes, configuration, null, signers);
                                    crls.Add(crl);
                                    Add(item, CrlStatus(crl, delta), configuration, crl.Details, crl.NextUpdate);
                                }
                                catch (Exception error) { Failed(item, error); }
                            }
                        }
                        return true;
                    });
                }
                catch (OperationCanceledException) { throw; }
                catch (Exception error) { Failed("CA metadata", error); }

                // shortcut: Sample the newest issued certificate; expand when historical CDP coverage is required.
                token.ThrowIfCancellationRequested();
                try
                {
                    var sample = CaDatabase.Read(configuration, new[] { "RequestID", "RawCertificate" },
                        new[] { new DatabaseRestriction("RequestID", 8, 0, 2),
                            new DatabaseRestriction("Request.Disposition", 1, 20) }, token, maximum: 1, batchSize: 1)
                        .FirstOrDefault();
                    if (sample == null)
                    {
                        Add("Distribution points", "Not checked", configuration,
                            new TimeReport("No issued certificate is available to supply distribution-point URLs."));
                        return;
                    }
                    var bytes = sample.Values[1] as byte[] ??
                        Convert.FromBase64String(Convert.ToString(sample.Values[1]));
                    using var certificate = new X509Certificate2(bytes);
                    var source = "Request " + Convert.ToInt32(sample.Values[0]);
                    Add("CDP sample", "Newest issued certificate", source,
                        new TimeReport(source + "\r\nSubject: " + certificate.Subject +
                            "\r\nIssuer: " + certificate.Issuer + "\r\nThumbprint: " + certificate.Thumbprint +
                            "\r\nOlder certificates may reference different distribution points."));
                    CheckDistributionPoints(configuration, certificate, signers.ToArray(), crls, token, report);
                }
                catch (OperationCanceledException) { throw; }
                catch (Exception error) { Failed("Distribution points", error); }
            }
            finally { foreach (var signer in signers) signer.Dispose(); }
        }

        internal static string CrlStatus(CrlResult crl, bool delta)
        {
            // Keep unavailable signature evidence distinct from an invalid or mismatched CRL.
            if (crl.IsDelta != delta) return "Wrong CRL type";
            if (crl.SignatureValid != true)
                return crl.SignatureValid == false ? "Invalid signature" : "Signature not verified";
            if (crl.SignerAllowsCrlSigning != true) return "Signer cannot sign CRLs";
            if (!crl.NextUpdate.HasValue) return "No next update";
            if (crl.NextUpdate <= DateTime.UtcNow) return "Expired";
            return crl.Current ? "Current" : "Not yet valid or invalid dates";
        }

        internal static void CheckDistributionPoints(string configuration, X509Certificate2 certificate,
            X509Certificate2[] signers, IReadOnlyList<CrlResult> expected, CancellationToken token,
            Action<CrlHealthEntry> report, Func<string, List<byte[]>> retrieve = null)
        {
            // Verify the sample's issuing key before accepting a CRL from a CA with a reused subject name.
            token.ThrowIfCancellationRequested();
            signers = signers.Where(signer => CertificateValidation.SignedBy(certificate, signer)).ToArray();
            var urls = new Queue<(string Url, bool Delta)>(CertificateValidation.Urls(certificate.Handle, 2)
                .Select(url => (url, false)).Concat(CertificateValidation.Urls(certificate.Handle, 6)
                    .Select(url => (url, true))));
            var seen = new HashSet<(string, bool)>();
            if (urls.Count == 0)
                report(new CrlHealthEntry { Configuration = configuration, Item = "Distribution points",
                    Status = "Not checked", Source = certificate.Subject,
                    Details = new TimeReport("The sampled certificate has no URL distribution points.") });
            retrieve ??= url => CertificateValidation.RetrieveCrls(url, false, 15);
            while (urls.Count > 0)
            {
                token.ThrowIfCancellationRequested();
                var location = urls.Dequeue();
                if (!seen.Add(location)) continue;
                var entry = new CrlHealthEntry { Configuration = configuration,
                    Item = location.Delta ? "Delta CDP" : "Base CDP", Source = location.Url };
                if (seen.Count > 64)
                {
                    entry.Status = "Not checked";
                    entry.Details = new TimeReport(
                        "The distribution-point limit was reached; remaining URLs were not checked.");
                    report(entry);
                    break;
                }
                try
                {
                    // Retain each object's result when an LDAP distribution point returns several CRLs.
                    var results = retrieve(location.Url);
                    if (results.Count == 0) throw new InvalidOperationException("The location did not return a CRL.");
                    foreach (var bytes in results)
                    {
                        token.ThrowIfCancellationRequested();
                        try
                        {
                            var crl = CertificateValidation.InspectCrl(bytes, location.Url, certificate, signers);
                            var status = CrlStatus(crl, location.Delta);
                            if (!crl.IssuerMatches || !crl.ScopeMatches) status = "Wrong issuer or scope";
                            if (status == "Current")
                            {
                                var comparable = expected.Where(value => value.IsDelta == crl.IsDelta &&
                                    value.IssuingDistributionPoint.SequenceEqual(crl.IssuingDistributionPoint) &&
                                    signers.Any(signer => signer.Thumbprint == value.SignerThumbprint)).ToArray();
                                var matches = comparable.Any(value => value.Encoded.SequenceEqual(bytes));
                                status = comparable.Length == 0 ? "Current; CA comparison unavailable" :
                                    matches ? "Current; matches CA" : "Current; differs from CA snapshot";
                            }
                            report(new CrlHealthEntry { Configuration = configuration, Item = entry.Item,
                                Source = location.Url, Status = status,
                                Expires = crl.NextUpdate, Details = crl.Details });
                            if (!crl.IsDelta && crl.SignatureValid == true && crl.IssuerMatches && crl.ScopeMatches)
                                foreach (var url in CertificateValidation.DeltaUrls(certificate.Handle, bytes))
                                    urls.Enqueue((url, true));
                        }
                        catch (Exception error)
                        {
                            report(new CrlHealthEntry { Configuration = configuration, Item = entry.Item,
                                Source = location.Url, Status = "Unavailable",
                                Details = new TimeReport(CaAdministration.Error(error)) });
                        }
                    }
                }
                catch (OperationCanceledException) { throw; }
                catch (Exception error)
                {
                    entry.Status = "Unavailable";
                    entry.Details = new TimeReport(CaAdministration.Error(error));
                    report(entry);
                }
            }
        }
    }

    internal sealed class CrlHealthPage : WorkspacePage
    {
        private readonly string[] configurations;
        private readonly ObservableCollection<CrlHealthEntry> entries = new ObservableCollection<CrlHealthEntry>();
        private readonly DataGrid grid = new DataGrid { SelectionMode = DataGridSelectionMode.Single,
            RowHeight = double.NaN, MinRowHeight = 24 };
        private readonly TextBox details = new TextBox { IsReadOnly = true, TextWrapping = TextWrapping.Wrap,
            AcceptsReturn = true, VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            VerticalContentAlignment = VerticalAlignment.Top };
        private readonly TextBlock status = new TextBlock { TextWrapping = TextWrapping.Wrap };
        private readonly Button refresh, cancel, report;
        private CancellationTokenSource cancellation;
        private bool initialized;

        public CrlHealthPage(CertificateStore store)
        {
            // Show both metadata and sampled endpoint checks for the connected authority snapshot.
            configurations = store.Configurations;
            Title = "CRL Health — " + store.Configuration;
            var layout = new DockPanel { Margin = new Thickness(8) };
            var header = new StackPanel();
            DockPanel.SetDock(header, Dock.Top);
            layout.Children.Add(header);
            Dialogs.Note(header, "CA certificates, CRLs and publication status. Download checks use the newest " +
                "issued certificate from each CA and run from this computer; older certificates may use other " +
                "locations. Use Certificate / CRL Check for certificate-chain and revocation validation.");
            var actions = new WrapPanel();
            header.Children.Add(actions);
            refresh = Dialogs.Button(actions, "_Refresh", async () => await Refresh());
            cancel = Dialogs.Button(actions, "_Cancel", () =>
            {
                cancellation?.Cancel();
                cancel.IsEnabled = false;
                status.Text = "Cancelling after the current native call returns…";
            });
            cancel.IsEnabled = false;
            report = Dialogs.Button(actions, "View _Report…", () =>
            {
                var text = new TimeReport("CRL health — sampled distribution points from this computer\r\n\r\n");
                foreach (var item in entries)
                    text.AppendLine(item.Configuration + " · " + item.Item + " · " + item.Status)
                        .AppendLine("Source: " + item.Source).AppendLine(item.Details).AppendLine();
                Dialogs.Report(this, "CRL Health Report", text);
            });
            report.IsEnabled = false;
            DockPanel.SetDock(status, Dock.Bottom);
            status.Margin = new Thickness(0, 6, 0, 0);
            layout.Children.Add(status);

            // Keep results scrollable and selected details readable when the window or text size changes.
            var content = new Grid();
            content.RowDefinitions.Add(new RowDefinition { Height = new GridLength(2, GridUnitType.Star) });
            content.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            grid.ItemsSource = entries;
            var wrapped = new Style(typeof(TextBlock));
            wrapped.Setters.Add(new Setter(TextBlock.TextWrappingProperty, TextWrapping.Wrap));
            foreach (var column in new[] { ("CA", "Configuration"), ("Check", "Item"), ("Status", "Status") })
                grid.Columns.Add(new DataGridTextColumn { Header = column.Item1, Binding = new Binding(column.Item2),
                    ElementStyle = wrapped, Width = new DataGridLength(1, DataGridLengthUnitType.Star),
                    MinWidth = column.Item2 == "Status" ? 160 : 115 });
            var expires = new DataGridTextColumn { Header = "Expires / Next Update (UTC)",
                Binding = TimeDisplay.Binding("Expires"), SortMemberPath = "Expires", Width = 190 };
            TimeDisplay.Label(expires, DataGridColumn.HeaderProperty, "Expires / Next Update (UTC)");
            grid.Columns.Add(expires);
            grid.Columns.Add(new DataGridTextColumn
                { Header = "Source", Binding = new Binding("Source"), Width = 240 });
            string SelectionText() => grid.SelectedItem is CrlHealthEntry item ?
                item.Configuration + " · " + item.Item + " · " + item.Status + "\r\nSource: " + item.Source +
                    "\r\n\r\n" + item.Details : "Select a check for details.";
            TimeDisplay.Text(details, SelectionText);
            grid.SelectionChanged += (sender, e) => TimeDisplay.Text(details, SelectionText);
            content.Children.Add(grid);
            Grid.SetRow(details, 1);
            details.Margin = new Thickness(0, 6, 0, 0);
            content.Children.Add(details);
            layout.Children.Add(content);
            Content = layout;
            Loaded += async (sender, e) =>
            {
                if (initialized) return;
                initialized = true;
                await Refresh();
            };
            Closing += (sender, e) =>
            {
                if (cancellation == null) return;
                cancellation.Cancel();
                cancel.IsEnabled = false;
                status.Text = "Cancelling after the current native call returns…";
                e.Cancel = true;
            };
        }

        private async Task Refresh()
        {
            // Clear stale results and publish completed checks incrementally while keeping the UI responsive.
            if (cancellation != null) return;
            using var request = new CancellationTokenSource();
            cancellation = request;
            entries.Clear();
            refresh.IsEnabled = report.IsEnabled = false;
            cancel.IsEnabled = true;
            var completed = 0;
            try
            {
                foreach (var configuration in configurations)
                {
                    request.Token.ThrowIfCancellationRequested();
                    status.Text = $"Checking CA {completed + 1:N0} of {configurations.Length:N0}: {configuration}";
                    await Task.Run(() => CrlHealth.Read(configuration, request.Token,
                        entry => Dispatcher.Invoke(() => entries.Add(entry))));
                    completed++;
                }
                var checkedAt = DateTime.UtcNow;
                TimeDisplay.Text(status, () => $"{completed:N0} CAs checked · {entries.Count:N0} results · " +
                    TimeDisplay.Stamp(checkedAt) + " · Review individual checks for errors and unavailable data.");
            }
            catch (OperationCanceledException)
            {
                status.Text = $"Cancelled. {completed:N0} of {configurations.Length:N0} CAs fully checked; " +
                    "completed checks remain visible.";
            }
            catch (Exception error) { status.Text = CaAdministration.Error(error); }
            finally
            {
                cancellation = null;
                refresh.IsEnabled = true;
                cancel.IsEnabled = false;
                report.IsEnabled = entries.Count > 0;
            }
        }
    }
}
