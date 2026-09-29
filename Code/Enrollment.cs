//
// Copyright (c) Bryan Berns.
// Licensed under GPLv3. See LICENSE.md.
//

using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace Certitude
{
    internal sealed class CsrOptions
    {
        public string Subject { get; set; } = "";
        public string DnsNames { get; set; } = "";
        public string IpAddresses { get; set; } = "";
        public string Template { get; set; } = "";
        public string Algorithm { get; set; } = "RSA 3072";
        public bool Machine { get; set; } = true;
        public bool Exportable { get; set; }
        public bool ServerAuthentication { get; set; } = true;
        public bool ClientAuthentication { get; set; }

        public string CreateInf()
        {
            // Reject subjects, algorithms, and template values that cannot be represented safely in a certreq INF.
            if (string.IsNullOrWhiteSpace(Subject) || Subject.IndexOfAny(new[] { '\r', '\n', '\0', '"', '%' }) >= 0)
                throw new ArgumentException("Enter an X.500 subject (for example CN=server.example.com), " +
                    "without quotes or percent signs.");
            new X500DistinguishedName(Subject);
            if (Algorithm is not ("RSA 2048" or "RSA 3072" or "RSA 4096" or "ECDSA P-256" or "ECDSA P-384"))
                throw new ArgumentException("Choose a supported RSA or ECDSA key.");
            if (Template.Length > 0 && !Regex.IsMatch(Template, @"^[A-Za-z0-9_.-]+$"))
                throw new ArgumentException("Enter the template's internal name or OID, without spaces.");

            // Normalize and deduplicate DNS SANs separately from IP SANs.
            var dns = DnsNames.Split(new[] { '\r', '\n', ',', ';', ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(value => CertificateUtilities.NormalizeHost(value, true))
                .Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            if (dns.Any(value => IPAddress.TryParse(value, out _)))
                throw new ArgumentException("Put IP addresses in the IP SAN field, not the DNS SAN field.");

            // Parse address SANs and require at least one endpoint identity for a TLS server request.
            var ips = IpAddresses.Split(new[] { '\r', '\n', ',', ';', ' ', '\t' },
                StringSplitOptions.RemoveEmptyEntries)
                .Select(value => IPAddress.TryParse(value, out var ip) && value.IndexOf('%') < 0 ? ip.ToString() :
                    throw new ArgumentException("Enter valid IPv4 or IPv6 SAN addresses without scope IDs."))
                .Distinct().ToArray();
            if (ServerAuthentication && dns.Length + ips.Length == 0)
                throw new ArgumentException("Add at least one DNS or IP SAN for a TLS server request.");

            // Describe the key provider, algorithm, usage, and storage context for native request generation.
            var rsa = Algorithm.StartsWith("RSA", StringComparison.Ordinal);
            var text = new StringBuilder("[Version]\r\nSignature=\"$Windows NT$\"\r\n\r\n[NewRequest]\r\n");
            text.AppendLine("Subject = \"" + Subject.Trim() + "\"").AppendLine("RequestType = PKCS10");
            text.AppendLine("ProviderName = \"Microsoft Software Key Storage Provider\"");
            text.AppendLine("ProviderType = 0").AppendLine("KeySpec = 0");
            text.AppendLine("KeyAlgorithm = " +
                (rsa ? "RSA" : Algorithm == "ECDSA P-256" ? "ECDSA_P256" : "ECDSA_P384"));
            if (rsa) text.AppendLine("KeyLength = " + Algorithm.Substring(4));
            text.AppendLine("HashAlgorithm = " + (Algorithm == "ECDSA P-384" ? "SHA384" : "SHA256"));
            text.AppendLine("KeyUsage = " + (rsa ? "0xa0" : "0x80"));
            text.AppendLine("MachineKeySet = " + Machine.ToString().ToUpperInvariant());
            text.AppendLine("Exportable = FALSE").AppendLine(
                "ExportableEncrypted = " + Exportable.ToString().ToUpperInvariant());

            // Encode all SAN values as one continued extension without losing their individual types.
            text.AppendLine().AppendLine("[Extensions]");
            if (dns.Length + ips.Length > 0)
            {
                var sans = dns.Select(value => "DNS=" + value)
                    .Concat(ips.Select(value => "IPAddress=" + value)).ToArray();
                text.AppendLine("2.5.29.17 = \"{text}\"");
                for (var i = 0; i < sans.Length; i++)
                    text.AppendLine("_continue_ = \"" + sans[i] + (i == sans.Length - 1 ? "" : "&") + "\"");
            }
            // Add the requested authentication purposes and optional template enrollment attribute.
            var purposes = new[] { ServerAuthentication ? "1.3.6.1.5.5.7.3.1" : null,
                ClientAuthentication ? "1.3.6.1.5.5.7.3.2" : null }.Where(value => value != null);
            if (purposes.Any()) text.AppendLine("2.5.29.37 = \"{text}" + string.Join(",", purposes) + "\"");
            if (Template.Length > 0)
                text.AppendLine().AppendLine("[RequestAttributes]").AppendLine("CertificateTemplate = " + Template);
            return text.ToString();
        }
    }

    internal sealed class EnrollmentResult
    {
        public int RequestId { get; set; }
        public int Disposition { get; set; }
        public string Report { get; set; }
        public byte[] Certificate { get; set; }
    }

    internal static class Enrollment
    {
        public static EnrollmentResult Request(string configuration, byte[] requestBytes,
            int requestId, string template)
        {
            // Validate the CA and request identifiers before making an enrollment call.
            new CertificateStore(configuration);
            if (template.Length > 0 && !Regex.IsMatch(template, @"^[A-Za-z0-9_.-]+$"))
                throw new ArgumentException("Enter the template's internal name or OID.");
            if (requestBytes == null && requestId <= 0) throw new ArgumentException("Enter a positive request ID.");
            using (var scope = ComScope<ICertRequest>.Create("CertificateAuthority.Request"))
            {
                // Submit a new request or retrieve the existing request while retaining the CA disposition.
                var request = scope.Value;
                var disposition = requestBytes == null ? request.RetrievePending(requestId, configuration) :
                    request.Submit(0x101, Convert.ToBase64String(DecodeRequest(requestBytes)),
                        template.Length == 0 ? "" : "CertificateTemplate:" + template, configuration);
                var result = new EnrollmentResult { Disposition = disposition, RequestId = request.GetRequestId() };
                result.Report = $"CA: {configuration}\r\nRequest {result.RequestId}: " +
                    CaAdministration.RequestDisposition(disposition) + "\r\n" + request.GetDispositionMessage() +
                    $"\r\nStatus: 0x{request.GetLastStatus():X8}";

                // Download issued certificate bytes without losing the request ID if retrieval alone fails.
                if (disposition == 3)
                {
                    try { result.Certificate = Convert.FromBase64String(request.GetCertificate(1)); }
                    catch (Exception error)
                    {
                        result.Report += "\r\nIssued, but downloading the response failed. " +
                            "Retrieve this request ID again: " + CaAdministration.Error(error);
                    }
                }
                return result;
            }
        }

        internal static byte[] DecodeRequest(byte[] bytes)
        {
            // Accept standard PEM request labels and reject malformed request armor.
            var text = Encoding.ASCII.GetString(bytes).Trim();
            if (text.StartsWith("-----BEGIN", StringComparison.Ordinal))
            {
                var match = Regex.Match(text,
                    @"\A-----BEGIN (?:NEW )?CERTIFICATE REQUEST-----\s*([A-Za-z0-9+/=\s]+?)\s*" +
                    @"-----END (?:NEW )?CERTIFICATE REQUEST-----\z");
                if (!match.Success) throw new ArgumentException("Select a PKCS #10 certificate request.");
                return Convert.FromBase64String(match.Groups[1].Value);
            }
            // Decode bare base64 requests while allowing existing DER bytes through unchanged.
            return Regex.IsMatch(text, @"\A[A-Za-z0-9+/=\s]+\z") ? Convert.FromBase64String(text) : bytes;
        }

        public static async Task<string> CreateRequest(string inf, string path, CancellationToken token)
        {
            // Stage request input and output separately so failures do not replace the chosen destination.
            var input = Path.Combine(Path.GetTempPath(), "Certitude-" + Guid.NewGuid().ToString("N") + ".inf");
            var output = path + "." + Guid.NewGuid().ToString("N") + ".req";
            try
            {
                // Run native request creation and publish its completed CSR with an atomic replacement.
                File.WriteAllText(input, inf, Encoding.Unicode);
                var report = await RunCertReq("-new -q " + ToolWindow.QuoteArgument(input) + " " +
                    ToolWindow.QuoteArgument(output), token).ConfigureAwait(false);
                if (File.Exists(path)) File.Replace(output, path, null);
                else File.Move(output, path);
                return report + "\r\nCSR saved: " + path +
                    "\r\nThe private key and pending request remain in Windows. Accept the issued certificate " +
                    "on this machine using the same machine/user context. " +
                    "The CA controls the final extensions and validity.";
            }
            finally
            {
                // Remove temporary request files on both successful and failed enrollment attempts.
                if (File.Exists(input)) File.Delete(input);
                if (File.Exists(output)) File.Delete(output);
            }
        }

        public static async Task<string> RunCertReq(string arguments, CancellationToken token)
        {
            // Launch certreq without a console and capture its Unicode output for the inline result.
            token.ThrowIfCancellationRequested();
            var start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "certreq.exe"),
                "-unicode " + arguments)
            {
                UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true,
                RedirectStandardError = true, RedirectStandardInput = true,
                StandardOutputEncoding = Encoding.Unicode, StandardErrorEncoding = Encoding.Unicode
            };
            using (var process = new Process { StartInfo = start })
            {
                // Disable interactive input and stop the process if the user cancels the operation.
                process.Start();
                process.StandardInput.Close();
                using (token.Register(() =>
                {
                    try { if (!process.HasExited) process.Kill(); }
                    catch (InvalidOperationException) { }
                    catch (System.ComponentModel.Win32Exception) { }
                }))
                {
                    // Drain both output streams together before interpreting completion or cancellation.
                    var output = ReadOutput(process.StandardOutput);
                    var errors = ReadOutput(process.StandardError);
                    await Task.Run(() => process.WaitForExit()).ConfigureAwait(false);
                    var text = await output.ConfigureAwait(false) + "\r\n" + await errors.ConfigureAwait(false);
                    token.ThrowIfCancellationRequested();

                    // Report native failures with guidance about key or store changes already completed.
                    if (process.ExitCode != 0) throw new InvalidOperationException(
                        $"certreq exited with 0x{process.ExitCode:X8}.\r\n{text}\r\n" +
                        "Completed key/store changes may remain. " +
                        "Review the Windows Request/Personal stores before retrying.");
                    return text.Trim();
                }
            }
        }

        private static async Task<string> ReadOutput(StreamReader reader)
        {
            // Continue draining the process stream while bounding the text retained for display.
            var text = new StringBuilder();
            var buffer = new char[4096];
            int count;
            while ((count = await reader.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false)) > 0)
                if (text.Length < 65536) text.Append(buffer, 0, Math.Min(count, 65536 - text.Length));
            return text.ToString();
        }
    }
}
