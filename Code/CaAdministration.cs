//
// Copyright (c) Bryan Berns.
// Licensed under GPLv3. See LICENSE.md.
//

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Text;
using System.Threading;

namespace Certitude
{
    internal static class CaAdministration
    {
        public static T Use<T>(Func<ICertAdmin, T> operation)
        {
            // Keep each administration call and its COM cleanup on the invoking worker.
            using var admin = ComScope<ICertAdmin>.Create("CertificateAuthority.Admin");
            return operation(admin.Value);
        }

        public static void Use(Action<ICertAdmin> operation)
        {
            using var admin = ComScope<ICertAdmin>.Create("CertificateAuthority.Admin");
            operation(admin.Value);
        }

        internal static TimeReport RunAuthorities(IEnumerable<string> configurations, Func<string, TimeReport> operation,
            CancellationToken token, Action<string> progress)
        {
            // Validate every target before starting and attempt each CA once, even after another CA fails.
            var targets = configurations.Select(config => new CertificateStore(config).Configuration)
                .Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            if (targets.Length == 0) throw new ArgumentException("No certificate authorities are connected.");
            var report = new TimeReport();
            var attempted = 0;
            var failed = 0;
            foreach (var target in targets)
            {
                if (token.IsCancellationRequested) break;
                progress?.Invoke($"CA {attempted + 1:N0} of {targets.Length:N0}: {target}");
                report.AppendLine("CA: " + target);
                try { report.AppendLine(operation(target)); }
                catch (Exception error)
                {
                    report.AppendLine("FAILED: " + Error(error));
                    failed++;
                }
                attempted++;
                report.AppendLine();
            }

            // Preserve partial results and distinguish returned calls from their reported publication outcomes.
            report.AppendLine($"{attempted:N0} of {targets.Length:N0} CAs attempted; {failed:N0} calls failed; " +
                $"{targets.Length - attempted:N0} not attempted.");
            if (attempted < targets.Length)
                report.AppendLine("Cancelled. Completed CA changes remain applied; remaining CAs were not attempted.")
                    .AppendLine("Not attempted: " + string.Join(", ", targets.Skip(attempted)));
            return report;
        }

        internal static void ValidateCrlPublication(int flags, DateTime? nextUpdate)
        {
            // Reject unsupported publication flags and expiry overrides that conflict with republishing.
            if ((flags & 3) == 0 || (flags & ~0x13) != 0)
                throw new ArgumentException("Select base CRLs, delta CRLs, or both.");
            if (nextUpdate.HasValue && ((flags & 0x10) != 0 || nextUpdate.Value <= DateTime.UtcNow))
                throw new ArgumentException(
                    "Use a future next-update time for new CRLs; leave it empty when republishing.");
        }

        public static string PublishCrls(string config, int flags, DateTime? nextUpdate)
        {
            // Validate publication settings before asking the CA to generate or redistribute CRLs.
            ValidateCrlPublication(flags, nextUpdate);
            return Use(admin =>
            {
                // Preserve publication feedback even when the follow-up status query fails.
                admin.PublishCRLs(config, nextUpdate?.ToOADate() ?? 0, flags);
                try { return "CA generation/publication call completed.\r\n\r\n" + CrlPublicationStatus(config, admin); }
                catch (Exception error)
                {
                    return "CA generation/publication call completed, but status retrieval failed:\r\n" + Error(error);
                }
            });
        }

        internal static int SigningCertificateCount(string config, ICertAdmin admin) =>
            Convert.ToInt32(admin.GetCAProperty(config, 11, 0, 1, 0));

        internal static HashSet<int> ReadCrlKeys(string config, ICertAdmin admin, int count, CancellationToken token,
            Action<string, Exception> failed)
        {
            // A renewal can reuse a key, and an unavailable version must leave later renewals readable.
            var keys = new HashSet<int>();
            for (var index = 0; index < count; index++)
            {
                token.ThrowIfCancellationRequested();
                try { keys.Add(CrlIndex(config, admin, index)); }
                catch (Exception error) when (error is not OperationCanceledException)
                { failed("CRL key for CA certificate " + index, error); }
            }
            return keys;
        }

        public static string CrlPublicationStatus(string config, ICertAdmin admin) =>
            ReadCrlPublication(config, admin, SigningCertificateCount(config, admin), CancellationToken.None).Status;

        internal static (string Status, HashSet<int> Keys) ReadCrlPublication(string config, ICertAdmin admin,
            int count, CancellationToken token)
        {
            // Keep each failed key lookup in the report alongside the available publication results.
            var text = new StringBuilder("CRL publication status — " + config + "\r\n");
            var keys = ReadCrlKeys(config, admin, count, token,
                (label, error) => text.AppendLine(label + ": " + Error(error)));
            foreach (var crlIndex in keys)
            {
                // Read base and delta results independently so one failed property does not hide the others.
                foreach (var property in new[] { 30, 31 })
                {
                    token.ThrowIfCancellationRequested();
                    var label = "CRL key index " + crlIndex + (property == 30 ? " · Base: " : " · Delta: ");
                    try
                    {
                        var flags = Convert.ToInt32(admin.GetCAProperty(config, property, crlIndex, 1, 0));
                        text.AppendLine(label + FormatCrlPublicationStatus(flags));
                    }
                    catch (Exception error) when (error is not OperationCanceledException)
                    { text.AppendLine(label + Error(error)); }
                }
            }
            text.AppendLine("These are the CA's reported publication results. Validate the certificate's CDP URLs to check client reachability.");
            return (text.ToString(), keys);
        }

        private static readonly string[] publicationFlags =
        [
            "Base", "Delta", "Complete", "Empty delta alongside base", "CA store ERROR", "Invalid URL ERROR",
            "Manual", "Signature ERROR", "LDAP ERROR", "File ERROR", "FTP ERROR", "HTTP ERROR",
            "Postponed base LDAP ERROR", "Postponed base file ERROR"
        ];

        internal static string FormatCrlPublicationStatus(int flags)
        {
            // Decode publication flags while retaining their raw value for diagnostics.
            var values = publicationFlags.Where((name, index) => (flags & (1 << index)) != 0);
            return $"0x{flags:X8} · " + (flags == 0 ? "No publication status reported" : string.Join(", ", values));
        }

        public static byte[] ReadCrl(string config, bool delta, int index)
        {
            // Read the requested CRL using its signing-key index rather than its certificate renewal index.
            if (index < 0) throw new ArgumentException("The CA certificate index must be zero or greater.");
            return Use(admin => Convert.FromBase64String(Convert.ToString(
                admin.GetCAProperty(config, delta ? 18 : 17, CrlIndex(config, admin, index), 3, 1),
                CultureInfo.InvariantCulture)));
        }

        private static int CrlIndex(string config, ICertAdmin admin, int certificateIndex) =>
            (Convert.ToInt32(admin.GetCAProperty(config, 39, certificateIndex, 1, 0)) >> 16) & 0xffff;

        public static string Apply(string config, IReadOnlyList<CertificateRow> rows, string action, int reason,
            DateTime? effective, string attributes, CancellationToken token, Action<int> progress,
            Action<string> revocationChanged = null) => Use(admin =>
                Apply(admin, config, rows, action, reason, effective, attributes, token, progress, revocationChanged));

        internal static string Apply(ICertAdmin admin, string config, IReadOnlyList<CertificateRow> rows,
            string action, int reason, DateTime? effective, string attributes, CancellationToken token,
            Action<int> progress, Action<string> revocationChanged)
        {
            // Track requests independently so bulk changes can continue after a row fails.
            var report = new StringBuilder();
            var completed = 0;
            var failed = 0;
            foreach (var row in rows)
            {
                if (token.IsCancellationRequested) break;
                try
                {
                    var result = "Completed";
                    switch (action)
                    {
                        // Report the actual resubmission outcome instead of assuming issuance.
                        case "Issue":
                            if (row.Disposition is not (9 or 31))
                                throw new InvalidOperationException(
                                    "Only pending or denied requests can be resubmitted.");
                            var disposition = admin.ResubmitRequest(config, row.RequestId);
                            result = RequestDisposition(disposition);
                            if (disposition is not (3 or 4)) failed++;
                            break;

                        // Deny only requests still waiting for a CA decision.
                        case "Deny":
                            if (row.Disposition != 9)
                                throw new InvalidOperationException("The request is not pending.");
                            admin.DenyRequest(config, row.RequestId);
                            break;

                        // Revoke issued serials and note that CRL publication distributes the change.
                        case "Revoke":
                            if (row.Disposition != 20 || string.IsNullOrEmpty(row.SerialNumber))
                                throw new InvalidOperationException("The certificate is not issued.");
                            admin.RevokeCertificate(config, row.SerialNumber, reason, effective?.ToOADate() ?? 0);
                            revocationChanged?.Invoke(config);
                            result = "Revoked; publish a CRL to distribute the change";
                            break;

                        // Allow reinstatement only for certificates revoked for certificate hold.
                        case "Release hold":
                            if (row.Disposition != 21 || row.RevocationReason != 6)
                                throw new InvalidOperationException("Only certificates on hold can be reinstated.");
                            admin.RevokeCertificate(config, row.SerialNumber, -1, 0);
                            revocationChanged?.Invoke(config);
                            result = "Hold released; publish a CRL to distribute the change";
                            break;

                        // Delete the database row without treating deletion as revocation.
                        case "Delete":
                            result = admin.DeleteRow(config, 0, 0, 0, row.RequestId) + " row(s) deleted";
                            break;

                        // Limit attribute edits to pending requests that can still use them.
                        case "Set attributes":
                            if (row.Disposition != 9)
                                throw new InvalidOperationException("The request is not pending.");
                            admin.SetRequestAttributes(config, row.RequestId, attributes);
                            break;
                        default: throw new ArgumentException("Unknown request action.");
                    }
                    report.AppendLine($"{row.RequestId}: {result}");
                }
                // Record failures and advance progress without aborting unrelated requests.
                catch (Exception error)
                {
                    failed++;
                    report.AppendLine($"{row.RequestId}: FAILED — {Error(error)}");
                }
                completed++;
                if (completed % 50 == 0 || completed == rows.Count) progress?.Invoke(completed);
            }
            // Summarize completed and unattempted requests, including cancellation between rows.
            return $"{action} on {config}\r\n{completed:N0} attempted; {failed:N0} failed or not issued; " +
                    $"{rows.Count - completed:N0} not attempted.\r\n\r\n" + report;
        }

        public static string RequestDisposition(int value)
        {
            // Distinguish pending and out-of-band issuance when labeling native outcomes.
            return value switch
            {
                0 => "Incomplete", 1 => "Failed", 2 => "Denied", 3 => "Issued", 4 => "Issued out of band",
                5 => "Still pending", 6 => "Revoked", _ => "Disposition " + value
            };
        }

        public static string Submit(string config, string path, string attributes)
        {
            // Submit the normalized request and retain its identifier and native status.
            using var request = ComScope<ICertRequest>.Create("CertificateAuthority.Request");
            return Enrollment.Submit(request.Value, config, CertificateUtilities.ReadBytes(path), attributes).Report;
        }

        public static void SetExtension(string config, int requestId, string oid, int flags, byte[] bytes)
        {
            Use(admin =>
            {
                // Keep the native extension payload alive until the administration call completes.
                using var value = new VariantValue(bytes);
                admin.SetCertificateExtension(config, requestId, oid, 3, flags, value.Pointer);
            });
        }

        public static object ParseValue(string text, int type)
        {
            // Convert edited property text into the native type required by the CA API.
            return type switch
            {
                1 => text.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ?
                    Convert.ToInt32(text.Substring(2), 16) : int.Parse(text, CultureInfo.InvariantCulture),
                2 => TimeDisplay.Parse(text),
                3 => Convert.FromBase64String(text), 4 => text, 5 => text.Replace("\r", "").Split('\n'),
                _ => throw new ArgumentException("Unknown value type.")
            };
        }

        public static string Service(string config, string operation)
        {
            // Address Certificate Services on the server named by the selected CA configuration.
            var server = config.Substring(0, config.IndexOf('\\'));
            using var service = new ServiceController("CertSvc", server);
            // Complete the stop phase before attempting any restart.
            if (operation is "Stop" or "Restart")
            {
                if (service.Status != ServiceControllerStatus.Stopped) service.Stop();
                service.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(45));
            }
            // Start the service and wait for its running state before probing the CA interface.
            if (operation is "Start" or "Restart")
            {
                service.Refresh();
                if (service.Status != ServiceControllerStatus.Running) service.Start();
                service.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(45));

                // Allow transient RPC startup failures until the administration endpoint is ready.
                var watch = Stopwatch.StartNew();
                while (true)
                {
                    try { Use(admin => admin.GetMyRoles(config)); break; }
                    catch (COMException error) when (watch.Elapsed.TotalSeconds < 45 &&
                        (error.HResult == unchecked((int)0x800706BA) || error.HResult == unchecked((int)0x800706BE)))
                    {
                        Thread.Sleep(250);
                    }
                }
            }
            // Read the final service state after the requested transition finishes.
            service.Refresh();
            return "Certificate Services on " + server + ": " + service.Status;
        }

        public static string Error(Exception error) =>
            $"{error.Message} (0x{(error is Win32Exception native ? native.NativeErrorCode : error.HResult):X8})";
    }
}
