//
// Copyright (c) Bryan Berns.
// Licensed under GPLv3. See LICENSE.md.
//

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace Certitude
{
    internal static class CaAdministration
    {
        public static T Use<T>(string config, Func<ICertAdmin, T> operation)
        {
            // Keep each administration call and its COM cleanup on the invoking worker.
            using (var admin = ComScope<ICertAdmin>.Create("CertificateAuthority.Admin"))
                return operation(admin.Value);
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
            return Use(config, admin =>
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

        public static string CrlPublicationStatus(string config, ICertAdmin admin)
        {
            // Resolve renewed CA certificates to unique CRL signing-key indexes.
            var text = new StringBuilder("CRL publication status — " + config + "\r\n");
            var count = Convert.ToInt32(admin.GetCAProperty(config, 11, 0, 1, 0));
            var seen = new HashSet<int>();
            for (var index = 0; index < count; index++)
            {
                var crlIndex = CrlIndex(config, admin, index);
                if (!seen.Add(crlIndex)) continue;

                // Read base and delta results independently so one failed property does not hide the others.
                foreach (var property in new[] { 30, 31 })
                {
                    var label = "CRL key index " + crlIndex + (property == 30 ? " · Base: " : " · Delta: ");
                    try
                    {
                        var flags = Convert.ToInt32(admin.GetCAProperty(config, property, crlIndex, 1, 0));
                        text.AppendLine(label + FormatCrlPublicationStatus(flags));
                    }
                    catch (Exception error) { text.AppendLine(label + Error(error)); }
                }
            }
            text.AppendLine("These are the CA's reported publication results. Validate the certificate's CDP URLs to check client reachability.");
            return text.ToString();
        }

        internal static string FormatCrlPublicationStatus(int flags)
        {
            // Decode publication flags while retaining their raw value for diagnostics.
            var bits = new[] { 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192 };
            var names = new[]
            {
                "Base", "Delta", "Complete", "Empty delta alongside base", "CA store ERROR", "Invalid URL ERROR",
                "Manual", "Signature ERROR", "LDAP ERROR", "File ERROR", "FTP ERROR", "HTTP ERROR",
                "Postponed base LDAP ERROR", "Postponed base file ERROR"
            };
            var values = bits.Select((bit, i) => (flags & bit) != 0 ? names[i] : null).Where(name => name != null);
            return $"0x{flags:X8} · " + (flags == 0 ? "No publication status reported" : string.Join(", ", values));
        }

        public static byte[] ReadCrl(string config, bool delta, int index)
        {
            // Read the requested CRL using its signing-key index rather than its certificate renewal index.
            if (index < 0) throw new ArgumentException("The CA certificate index must be zero or greater.");
            return Use(config, admin => Convert.FromBase64String(Convert.ToString(
                admin.GetCAProperty(config, delta ? 18 : 17, CrlIndex(config, admin, index), 3, 1),
                CultureInfo.InvariantCulture)));
        }

        private static int CrlIndex(string config, ICertAdmin admin, int certificateIndex) =>
            (Convert.ToInt32(admin.GetCAProperty(config, 39, certificateIndex, 1, 0)) >> 16) & 0xffff;

        public static string Apply(string config, IReadOnlyList<CertificateRow> rows, string action, int reason,
            DateTime? effective, string attributes, CancellationToken token, Action<int> progress)
        {
            return Use(config, admin =>
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
                                if (row.Disposition != 9 && row.Disposition != 31)
                                    throw new InvalidOperationException(
                                        "Only pending or denied requests can be resubmitted.");
                                var disposition = admin.ResubmitRequest(config, row.RequestId);
                                result = RequestDisposition(disposition);
                                if (disposition != 3 && disposition != 4) failed++;
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
                                result = "Revoked; publish a CRL to distribute the change";
                                break;

                            // Allow reinstatement only for certificates revoked for certificate hold.
                            case "Release hold":
                                if (row.Disposition != 21 || row.RevocationReason != 6)
                                    throw new InvalidOperationException("Only certificates on hold can be reinstated.");
                                admin.RevokeCertificate(config, row.SerialNumber, -1, 0);
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
                    if (completed % 50 == 0 || completed == rows.Count) progress(completed);
                }
                // Summarize completed and unattempted requests, including cancellation between rows.
                return $"{action} on {config}\r\n{completed:N0} attempted; {failed:N0} failed or not issued; " +
                    $"{rows.Count - completed:N0} not attempted.\r\n\r\n" + report;
            });
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
            using (var request = ComScope<ICertRequest>.Create("CertificateAuthority.Request"))
            {
                // Submit the normalized request and retain its identifier and native status.
                var data = ReadBase64(path);
                var result = request.Value.Submit(0x101, data, attributes, config);
                return $"Request {request.Value.GetRequestId()}: {RequestDisposition(result)}\r\n" +
                    request.Value.GetDispositionMessage() + $"\r\nStatus: 0x{request.Value.GetLastStatus():X8}";
            }
        }

        public static string ReadBase64(string path)
        {
            // Normalize DER or bare base64 input into the encoding expected by the CA interface.
            var bytes = File.ReadAllBytes(path);
            var text = Encoding.ASCII.GetString(bytes).Trim();
            if (!text.StartsWith("-----BEGIN", StringComparison.Ordinal))
            {
                if (text.Length > 0 && Regex.IsMatch(text, @"^[A-Za-z0-9+/=\s]+$"))
                    return Convert.ToBase64String(Convert.FromBase64String(text));
                return Convert.ToBase64String(bytes);
            }
            // Strip PEM armor and re-encode only its validated base64 body.
            var body = string.Concat(text.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                .Where(line => !line.StartsWith("-----", StringComparison.Ordinal)));
            return Convert.ToBase64String(Convert.FromBase64String(body));
        }

        public static void SetExtension(string config, int requestId, string oid, int flags, byte[] bytes)
        {
            Use(config, admin =>
            {
                // Keep the native extension payload alive until the administration call completes.
                using (var value = new VariantValue(bytes))
                    admin.SetCertificateExtension(config, requestId, oid, 3, flags, value.Pointer);
                return 0;
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
            using (var service = new ServiceController("CertSvc", server))
            {
                // Complete the stop phase before attempting any restart.
                if (operation == "Stop" || operation == "Restart")
                {
                    if (service.Status != ServiceControllerStatus.Stopped) service.Stop();
                    service.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(45));
                }
                // Start the service and wait for its running state before probing the CA interface.
                if (operation == "Start" || operation == "Restart")
                {
                    service.Refresh();
                    if (service.Status != ServiceControllerStatus.Running) service.Start();
                    service.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(45));

                    // Allow transient RPC startup failures until the administration endpoint is ready.
                    var watch = Stopwatch.StartNew();
                    while (true)
                    {
                        try { Use(config, admin => admin.GetMyRoles(config)); break; }
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
        }

        public static string Error(Exception error) =>
            $"{error.Message} (0x{(error is Win32Exception native ? native.NativeErrorCode : error.HResult):X8})";
    }
}
