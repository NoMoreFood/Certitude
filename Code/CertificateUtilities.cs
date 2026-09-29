//
// Copyright (c) Bryan Berns.
// Licensed under GPLv3. See LICENSE.md.
//

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace Certitude
{
    internal sealed class InventoryCertificate
    {
        public byte[] Encoded { get; set; }
        public string Subject { get; set; }
        public string Issuer { get; set; }
        public string FriendlyName { get; set; }
        public string Thumbprint { get; set; }
        public string Sha256 { get; set; }
        public string SerialNumber { get; set; }
        public string AlternativeNames { get; set; }
        public string Purposes { get; set; }
        public string Template { get; set; }
        internal OidNames Oids { get; set; }
        public string Algorithm { get; set; }
        public int KeyBits { get; set; }
        public string Signature { get; set; }
        public bool HasPrivateKey { get; set; }
        public bool IsCa { get; set; }
        public DateTime NotBefore { get; set; }
        public DateTime NotAfter { get; set; }
        public string Findings { get; set; }
        public string Validity => NotBefore > DateTime.UtcNow ? "Not yet valid" :
            NotAfter <= DateTime.UtcNow ? "Expired" : "Within validity dates";
        public int DaysLeft => (int)Math.Ceiling((NotAfter - DateTime.UtcNow).TotalDays);

        public bool Matches(string text, int validity, int key, DateTime now)
        {
            // Apply private-key and validity filters before searching certificate metadata.
            if (key == 1 && !HasPrivateKey || key == 2 && HasPrivateKey) return false;
            if (validity == 1 && NotAfter > now || validity == 2 &&
                (NotAfter <= now || NotAfter > now.AddDays(30)) || validity == 3 &&
                (NotAfter <= now || NotAfter > now.AddDays(90)) || validity == 4 && NotBefore <= now) return false;

            // Search the displayed identities, names, purposes, and diagnostic findings.
            return string.IsNullOrWhiteSpace(text) || new[] { Subject, Issuer, FriendlyName, Thumbprint, Sha256,
                SerialNumber, AlternativeNames, Purposes, Template, Algorithm, Signature, Findings }.Any(value =>
                    (value ?? "").IndexOf(text.Trim(), StringComparison.OrdinalIgnoreCase) >= 0);
        }
    }

    internal sealed class TlsProbeResult
    {
        public string Report { get; set; }
        public byte[] Certificate { get; set; }
        public List<byte[]> Chain { get; } = new List<byte[]>();
        public SslPolicyErrors PolicyErrors { get; set; }
        public bool HandshakeCompleted { get; set; }
        public bool? ExpectedCertificateMatches { get; set; }
    }

    internal static class CertificateUtilities
    {
        public static readonly string[] StoreNames = { "My", "WebHosting", "CA", "Root", "TrustedPeople",
            "TrustedPublisher", "Disallowed", "Request" };

        public static InventoryCertificate Describe(X509Certificate2 certificate, OidNames names = null)
        {
            // Capture certificate metadata independently of the native certificate lifetime.
            names ??= OidNames.Windows;
            var item = new InventoryCertificate
            {
                Encoded = certificate.RawData, Subject = certificate.Subject, Issuer = certificate.Issuer,
                FriendlyName = certificate.FriendlyName, Thumbprint = certificate.Thumbprint,
                SerialNumber = certificate.SerialNumber, HasPrivateKey = certificate.HasPrivateKey,
                NotBefore = certificate.NotBefore.ToUniversalTime(), NotAfter = certificate.NotAfter.ToUniversalTime(),
                Algorithm = names.Name(certificate.PublicKey.Oid.Value, 3),
                Signature = names.Name(certificate.SignatureAlgorithm.Value, 4), Oids = names, Template = "",
                AlternativeNames = "", Purposes = "All purposes (no EKU restriction)"
            };

            // Calculate a strong fingerprint and obtain the key size when its provider supports it.
            using (var hash = SHA256.Create()) item.Sha256 = Hex(hash.ComputeHash(item.Encoded));
            try
            {
                using (var rsa = certificate.GetRSAPublicKey())
                using (var ec = certificate.GetECDsaPublicKey())
                using (var dsa = certificate.GetDSAPublicKey())
                    item.KeyBits = rsa?.KeySize ?? ec?.KeySize ?? dsa?.KeySize ?? 0;
            }
            catch (CryptographicException) { }

            // Decode extensions that supply inventory fields while retaining decoding failures.
            var notes = new List<string>();
            foreach (var extension in certificate.Extensions.Cast<X509Extension>())
            {
                try
                {
                    if (extension.Oid.Value == "2.5.29.17") item.AlternativeNames = extension.Format(false);
                    if (extension.Oid.Value == "2.5.29.19")
                        item.IsCa = new X509BasicConstraintsExtension(
                            extension, extension.Critical).CertificateAuthority;
                    if (extension.Oid.Value == "1.3.6.1.4.1.311.21.7" ||
                        extension.Oid.Value == "1.3.6.1.4.1.311.20.2" && item.Template.Length == 0)
                        item.Template = names.FormatExtension(extension).Split(new[] { '\r', '\n' })[0];
                    if (extension.Oid.Value == "2.5.29.37")
                        item.Purposes = string.Join("; ", new X509EnhancedKeyUsageExtension(extension,
                            extension.Critical).EnhancedKeyUsages.Cast<Oid>().Select(oid =>
                                names.Describe(oid.Value, 7)));
                }
                catch (CryptographicException) { notes.Add("Cannot decode extension " + extension.Oid.Value); }
            }
            // Flag basic algorithm concerns without treating them as a trust validation result.
            if (certificate.SignatureAlgorithm.Value is "1.2.840.113549.1.1.4" or "1.2.840.113549.1.1.5" or
                "1.2.840.10040.4.3" or "1.2.840.10045.4.1")
                notes.Add("Legacy MD5/SHA-1 signature");
            if (certificate.PublicKey.Oid.Value == "1.2.840.113549.1.1.1" && item.KeyBits > 0 && item.KeyBits < 2048)
                notes.Add("RSA key below 2048 bits");
            if (item.KeyBits == 0) notes.Add("Key size unavailable");
            item.Findings = string.Join("; ", notes);
            return item;
        }

        public static string Details(InventoryCertificate item)
        {
            // Summarize identity, validity, keys, and intended purposes for the details view.
            var text = new StringBuilder();
            text.AppendLine("Subject: " + item.Subject).AppendLine("Issuer: " + item.Issuer);
            text.AppendLine("Friendly Name: " + item.FriendlyName).AppendLine("Serial: " + item.SerialNumber);
            text.AppendLine("SHA-1 Thumbprint: " + item.Thumbprint).AppendLine("SHA-256: " + item.Sha256);
            text.AppendLine($"Validity (UTC): {item.NotBefore:u} to {item.NotAfter:u} · {item.Validity}");
            text.AppendLine($"Public Key: {item.Algorithm} · {item.KeyBits} bits · Signature: {item.Signature}");
            text.AppendLine("Private Key Association: " +
                (item.HasPrivateKey ? "Present; access not yet tested" : "Absent"));
            text.AppendLine("Certificate Authority: " + item.IsCa).AppendLine("Purposes: " + item.Purposes);
            text.AppendLine("Certificate Template: " + item.Template);

            // Add OID context and qualify the scope of the inventory findings.
            var names = item.Oids ?? OidNames.Windows;
            text.AppendLine("OID Resolution: " + names.Status);
            text.AppendLine("Certificate Object Identifiers:").AppendLine(names.Identifiers(item.Encoded));
            text.AppendLine("Review Findings: " +
                (item.Findings.Length == 0 ? "None from the basic checks" : item.Findings));
            text.AppendLine("Validity dates and basic findings do not establish trust or revocation status.");

            // Append readable extension details from the captured certificate bytes.
            using (var certificate = new X509Certificate2(item.Encoded))
                foreach (var extension in certificate.Extensions.Cast<X509Extension>())
                {
                    text.AppendLine().AppendLine(names.Describe(extension.Oid.Value, 6) +
                        (extension.Critical ? " · Critical" : ""));
                    text.AppendLine(names.FormatExtension(extension));
                }
            return text.ToString();
        }

        public static List<InventoryCertificate> ReadStore(StoreLocation location, string name, CancellationToken token,
            OidNames names = null)
        {
            // Refresh OID names and read the existing store without retaining native certificates.
            names = names?.Refresh() ?? OidNames.Local;
            token.ThrowIfCancellationRequested();
            using (var store = new X509Store(name, location))
            {
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                var certificates = store.Certificates;
                try { return DescribeAll(certificates, token, names); }
                finally { foreach (var certificate in certificates) certificate.Dispose(); }
            }
        }

        public static List<InventoryCertificate> ReadFile(byte[] bytes, string password, CancellationToken token,
            OidNames names = null)
        {
            // Inspect file contents with ephemeral keys so reading a PFX does not persist them.
            names = names?.Refresh() ?? OidNames.Local;
            token.ThrowIfCancellationRequested();
            var certificates = new X509Certificate2Collection();
            try
            {
                certificates.Import(DecodePublicPem(bytes), password, X509KeyStorageFlags.EphemeralKeySet);
                return DescribeAll(certificates, token, names);
            }
            finally { foreach (var certificate in certificates) certificate.Dispose(); }
        }

        private static List<InventoryCertificate> DescribeAll(X509Certificate2Collection certificates,
            CancellationToken token, OidNames names)
        {
            // Describe certificates with cancellation support and order them by expiration.
            var rows = new List<InventoryCertificate>(certificates.Count);
            foreach (var certificate in certificates)
            {
                token.ThrowIfCancellationRequested();
                rows.Add(Describe(certificate, names));
            }
            return rows.OrderBy(row => row.NotAfter).ToList();
        }

        public static byte[] DecodePublicPem(byte[] bytes)
        {
            // Recognize public PEM blocks while rejecting unsupported private-key PEM input.
            var text = Encoding.ASCII.GetString(bytes).Trim();
            if (!text.StartsWith("-----BEGIN", StringComparison.Ordinal)) return bytes;
            var matches = Regex.Matches(text,
                @"-----BEGIN (CERTIFICATE|PKCS7)-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END \1-----");
            if (matches.Count == 0 || text.Contains("PRIVATE KEY"))
                throw new ArgumentException("Use a certificate/PKCS #7 PEM file, or a PFX for private keys.");
            if (matches.Count == 1) return Convert.FromBase64String(matches[0].Groups[2].Value);

            // Combine multiple public PEM blocks into a single importable PKCS #7 payload.
            var collection = new X509Certificate2Collection();
            try
            {
                foreach (Match match in matches) collection.Import(Convert.FromBase64String(match.Groups[2].Value));
                return collection.Export(X509ContentType.Pkcs7);
            }
            finally { foreach (var certificate in collection) certificate.Dispose(); }
        }

        public static string Import(byte[] bytes, string password, StoreLocation location,
            string name, bool exportable, CancellationToken token)
        {
            // Open the selected destination store for a cancellable import.
            token.ThrowIfCancellationRequested();
            using (var store = new X509Store(name, location))
            {
                store.Open(OpenFlags.ReadWrite | OpenFlags.OpenExistingOnly);
                var certificates = new X509Certificate2Collection();
                var report = new StringBuilder($"Import destination: {location}\\{name}\r\n");
                try
                {
                    // Persist imported keys in the selected user or machine scope.
                    var flags = X509KeyStorageFlags.PersistKeySet | (location == StoreLocation.LocalMachine ?
                        X509KeyStorageFlags.MachineKeySet : X509KeyStorageFlags.UserKeySet);
                    if (exportable) flags |= X509KeyStorageFlags.Exportable;
                    certificates.Import(DecodePublicPem(bytes), password, flags);

                    // Report each import independently and stop remaining additions on cancellation.
                    foreach (var certificate in certificates)
                    {
                        if (token.IsCancellationRequested)
                        {
                            report.AppendLine("Cancelled; remaining certificates were not added to the store.");
                            break;
                        }
                        try { store.Add(certificate); report.AppendLine(certificate.Thumbprint + ": Imported"); }
                        catch (Exception error)
                        {
                            report.AppendLine(certificate.Thumbprint + ": FAILED — " + CaAdministration.Error(error));
                        }
                    }
                    return report + "Private keys loaded from PFX are persisted. Service bindings are unchanged.";
                }
                finally { foreach (var certificate in certificates) certificate.Dispose(); }
            }
        }

        public static T WithCertificate<T>(StoreLocation location, string name, string thumbprint,
            bool writable, Func<X509Store, X509Certificate2, T> action)
        {
            // Open the requested store with only the access required by the operation.
            using (var store = new X509Store(name, location))
            {
                store.Open((writable ? OpenFlags.ReadWrite : OpenFlags.ReadOnly) | OpenFlags.OpenExistingOnly);
                var certificates = store.Certificates;
                try
                {
                    // Resolve the certificate by thumbprint immediately before invoking the action.
                    var certificate = certificates.Cast<X509Certificate2>().FirstOrDefault(item =>
                        string.Equals(item.Thumbprint, thumbprint, StringComparison.OrdinalIgnoreCase));
                    if (certificate == null)
                        throw new InvalidOperationException("The certificate is no longer in this store. Reload it.");
                    return action(store, certificate);
                }
                finally { foreach (var certificate in certificates) certificate.Dispose(); }
            }
        }

        public static string Transfer(StoreLocation location, string source, string destination,
            IEnumerable<string> thumbprints, bool move, CancellationToken token)
        {
            // Require a distinct destination and prepare the certificate transfer report.
            if (string.Equals(source, destination, StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("Choose a different destination store.");
            using (var target = new X509Store(destination, location))
            {
                target.Open(OpenFlags.ReadWrite | OpenFlags.OpenExistingOnly);
                var report = new StringBuilder($"{location}\\{source} → {location}\\{destination}\r\n");

                // Process each distinct certificate independently while honoring cancellation.
                foreach (var thumbprint in thumbprints.Distinct(StringComparer.OrdinalIgnoreCase))
                {
                    if (token.IsCancellationRequested)
                    { report.AppendLine("Cancelled; remaining certificates were not attempted."); break; }
                    try
                    {
                        WithCertificate(location, source, thumbprint, move, (store, certificate) =>
                        {
                            // Keep the source when the certificate already exists in the destination.
                            var existing = target.Certificates;
                            try
                            {
                                if (existing.Cast<X509Certificate2>().Any(item => item.Thumbprint == certificate.Thumbprint))
                                    throw new InvalidOperationException("Already in the destination; source retained.");
                            }
                            finally { foreach (var item in existing) item.Dispose(); }

                            // Verify that the copied certificate retains its private-key association.
                            target.Add(certificate);
                            WithCertificate(location, destination, thumbprint, false, (destinationStore, copied) =>
                            {
                                if (certificate.HasPrivateKey && !copied.HasPrivateKey)
                                    throw new InvalidOperationException("Private key association was not retained; source retained.");
                                return true;
                            });

                            // Remove the source only after the destination copy has been verified.
                            if (move) store.Remove(certificate);
                            return true;
                        });
                        report.AppendLine(thumbprint + (move ? ": Moved" : ": Copied"));
                    }
                    catch (Exception error)
                    { report.AppendLine(thumbprint + ": FAILED — " + CaAdministration.Error(error)); }
                }
                return report.ToString();
            }
        }

        public static string TestPrivateKey(X509Certificate2 certificate)
        {
            // Require a private key and generate a fresh challenge to check its usability.
            if (!certificate.HasPrivateKey)
                throw new InvalidOperationException("No private key is associated with this certificate.");
            var challenge = new byte[32];
            using (var random = RandomNumberGenerator.Create()) random.GetBytes(challenge);
            bool matched;

            // Sign and verify the challenge with the matching RSA or ECDSA key pair.
            using (var rsa = certificate.GetRSAPrivateKey())
            using (var ec = certificate.GetECDsaPrivateKey())
            {
                if (rsa != null)
                {
                    using (var publicKey = certificate.GetRSAPublicKey())
                        matched = publicKey.VerifyData(challenge, rsa.SignData(challenge, HashAlgorithmName.SHA256,
                            RSASignaturePadding.Pkcs1), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                }
                else if (ec != null)
                {
                    using (var publicKey = certificate.GetECDsaPublicKey())
                        matched = publicKey.VerifyData(challenge, ec.SignData(challenge, HashAlgorithmName.SHA256),
                            HashAlgorithmName.SHA256);
                }
                else throw new NotSupportedException("The access test supports RSA and ECDSA signing keys.");
            }
            // Report a mismatch or qualify what successful private-key access establishes.
            if (!matched)
                throw new CryptographicException("The private key does not match the certificate's public key.");
            return "Private key is accessible to the current identity and matches the certificate. " +
                "A random challenge was signed and verified; " +
                "service-account access and other key usages were not tested.";
        }

        public static byte[] ExportPublic(IEnumerable<byte[]> certificates, int format)
        {
            // Validate selection counts and encode DER or PEM exports directly.
            var rows = certificates.ToArray();
            if (rows.Length == 0) throw new ArgumentException("Select at least one certificate.");
            if (format == 0 && rows.Length != 1)
                throw new ArgumentException("DER exports require one selected certificate.");
            if (format == 0) return rows[0];
            if (format == 1) return Encoding.ASCII.GetBytes(string.Concat(rows.Select(bytes =>
                "-----BEGIN CERTIFICATE-----\r\n" +
                Convert.ToBase64String(bytes, Base64FormattingOptions.InsertLineBreaks) +
                "\r\n-----END CERTIFICATE-----\r\n")));
            if (format != 2) throw new ArgumentException("Unknown export format.");

            // Build a disposable certificate collection for a PKCS #7 export.
            var collection = new X509Certificate2Collection();
            try
            {
                foreach (var bytes in rows) collection.Add(new X509Certificate2(bytes));
                return collection.Export(X509ContentType.Pkcs7);
            }
            finally { foreach (var certificate in collection) certificate.Dispose(); }
        }

        public static void WriteAtomic(string path, byte[] bytes)
        {
            // Write beside the destination and replace it only after the complete file is ready.
            var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try
            {
                File.WriteAllBytes(temporary, bytes);
                if (File.Exists(path)) File.Replace(temporary, path, null);
                else File.Move(temporary, path);
            }
            finally { if (File.Exists(temporary)) File.Delete(temporary); }
        }

        public static void ExportInventory(IEnumerable<InventoryCertificate> rows, string path)
        {
            // Serialize the inventory fields with CSV escaping and a UTF-8 signature.
            var csv = new StringBuilder("Subject,Issuer,Friendly name,Serial number,Thumbprint,SHA256," +
                "Valid from (UTC),Expires (UTC),Private key,CA,Algorithm,Key bits,Signature,SAN,EKU,Findings\r\n");
            foreach (var row in rows)
                csv.AppendLine(string.Join(",", new[] { row.Subject, row.Issuer, row.FriendlyName, row.SerialNumber,
                    row.Thumbprint, row.Sha256, row.NotBefore.ToString("u"), row.NotAfter.ToString("u"),
                    row.HasPrivateKey.ToString(), row.IsCa.ToString(), row.Algorithm, row.KeyBits.ToString(),
                    row.Signature, row.AlternativeNames, row.Purposes, row.Findings }.Select(CertificateStore.Csv)));
            WriteAtomic(path, new UTF8Encoding(true).GetPreamble()
                .Concat(Encoding.UTF8.GetBytes(csv.ToString())).ToArray());
        }

        public static string NormalizeHost(string value, bool wildcard = false)
        {
            // Normalize IP or internationalized DNS names and reject URL-style input.
            value = (value ?? "").Trim();
            if (IPAddress.TryParse(value, out var address)) return address.ToString();
            var prefix = wildcard && value.StartsWith("*.", StringComparison.Ordinal) ? "*." : "";
            var host = prefix.Length > 0 ? value.Substring(2) : value;
            host = new IdnMapping().GetAscii(host.TrimEnd('.'));
            if (host.Length == 0 || host.Length > 253 || host.Split('.').Any(part =>
                part.Length == 0 || part.Length > 63 ||
                !Regex.IsMatch(part, @"^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$")))
                throw new ArgumentException("Enter a DNS hostname or IP address, without a URL, port or path.");
            return prefix + host.ToLowerInvariant();
        }

        public static async Task<TlsProbeResult> Probe(string host, int port, string serverName,
            bool revocation, int seconds, string expectedThumbprint, CancellationToken token, OidNames names = null)
        {
            // Validate the endpoint, expected name, timeout, and optional certificate fingerprint.
            names = names?.Refresh() ?? OidNames.Local;
            host = NormalizeHost(host);
            serverName = NormalizeHost(string.IsNullOrWhiteSpace(serverName) ? host : serverName);
            if (port is < 1 or > 65535 || seconds is < 1 or > 120)
                throw new ArgumentException("Use port 1–65535 and timeout 1–120 seconds.");
            var expected = Regex.Replace(expectedThumbprint ?? "", @"[\s:]", "").ToUpperInvariant();
            if (expected.Length > 0 && !Regex.IsMatch(expected, @"^(?:[0-9A-F]{40}|[0-9A-F]{64})$"))
                throw new ArgumentException("The expected thumbprint must be SHA-1 (40 hex digits) or SHA-256 (64).");

            // Initialize a diagnostic report and a connection deadline linked to cancellation.
            token.ThrowIfCancellationRequested();
            var result = new TlsProbeResult { PolicyErrors = SslPolicyErrors.RemoteCertificateNotAvailable };
            var report = new StringBuilder($"TLS endpoint: {host}:{port}\r\nSNI / expected name: {serverName}\r\n" +
                $"Checked (UTC): {DateTime.UtcNow:u}\r\n" +
                $"Revocation: {(revocation ? "Windows online check" : "NOT CHECKED")}\r\n");
            using (var deadline = CancellationTokenSource.CreateLinkedTokenSource(token))
            using (var client = new TcpClient(Socket.OSSupportsIPv6 ?
                AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork))
            {
                // Close the socket on cancellation so connection and handshake waits can end.
                deadline.CancelAfter(TimeSpan.FromSeconds(seconds));
                using (deadline.Token.Register(client.Close))
                {
                    try
                    {
                        // Connect with IPv4 or IPv6 support before starting certificate negotiation.
                        if (client.Client.AddressFamily == AddressFamily.InterNetworkV6) client.Client.DualMode = true;
                        await client.ConnectAsync(host, port).ConfigureAwait(false);
                        report.AppendLine("Connected address: " + client.Client?.RemoteEndPoint);
                        using (var ssl = new SslStream(client.GetStream(), false,
                            (sender, certificate, chain, errors) =>
                        {
                            // Capture the presented certificate and Windows policy result for diagnosis.
                            result.PolicyErrors = errors;
                            report.AppendLine("Windows TLS policy: " + errors);
                            if (certificate != null)
                            {
                                result.Certificate = certificate.GetRawCertData();
                                using (var leaf = new X509Certificate2(result.Certificate))
                                    report.AppendLine().AppendLine(Details(Describe(leaf, names)));
                            }
                            // Record the Windows-built chain and each element validation result.
                            if (chain != null)
                            {
                                report.AppendLine("Windows-built chain (may include cached/downloaded issuers):");
                                foreach (var element in chain.ChainElements.Cast<X509ChainElement>())
                                {
                                    result.Chain.Add(element.Certificate.RawData);
                                    report.AppendLine("  " + element.Certificate.Subject);
                                    foreach (var state in element.ChainElementStatus)
                                        report.AppendLine("    " + state.Status + ": " +
                                            state.StatusInformation.Trim());
                                }
                            }
                            // Capture diagnostics while preserving the normal TLS validation decision.
                            return errors == SslPolicyErrors.None;
                        }))
                        {
                            // Complete the handshake and report the negotiated TLS parameters.
                            await ssl.AuthenticateAsClientAsync(serverName, new X509CertificateCollection(),
                                SslProtocols.None, revocation).ConfigureAwait(false);
                            result.HandshakeCompleted = true;
                            report.AppendLine($"Negotiated: {ssl.SslProtocol}; " +
                                $"{ssl.CipherAlgorithm} {ssl.CipherStrength} bits; " +
                                $"hash {ssl.HashAlgorithm}; exchange {ssl.KeyExchangeAlgorithm}");
                        }
                    }
                    // .NET Framework EndConnect can throw when cancellation closes its socket concurrently.
                    catch (Exception error) when (deadline.IsCancellationRequested ||
                        error is SocketException or IOException or AuthenticationException or
                            InvalidOperationException or CryptographicException)
                    {
                        // Distinguish user cancellation from a timeout or rejected TLS connection.
                        if (token.IsCancellationRequested) throw new OperationCanceledException(token);
                        report.AppendLine(deadline.IsCancellationRequested ? "Connection or handshake timed out." :
                            "TLS connection rejected/failed: " + error.Message);
                    }
                    // Compare the presented certificate against the optional expected fingerprint.
                    token.ThrowIfCancellationRequested();
                    if (result.Certificate != null && expected.Length > 0)
                    {
                        using (var certificate = new X509Certificate2(result.Certificate))
                        {
                            var item = Describe(certificate);
                            result.ExpectedCertificateMatches = expected ==
                                (expected.Length == 40 ? item.Thumbprint : item.Sha256);
                            report.AppendLine("Expected certificate thumbprint: " +
                                (result.ExpectedCertificateMatches.Value ? "MATCH" : "MISMATCH"));
                        }
                    }
                    // Finish the report with the scope of the endpoint check.
                    report.AppendLine("No application data was sent. Direct TLS only; " +
                        "STARTTLS and client authentication are not tested.");
                    report.AppendLine("A certificate installed or renewed in a store " +
                        "may still require a service binding update.");
                    result.Report = report.ToString();
                    return result;
                }
            }
        }

        private static string Hex(byte[] bytes) => BitConverter.ToString(bytes).Replace("-", "");
    }
}
