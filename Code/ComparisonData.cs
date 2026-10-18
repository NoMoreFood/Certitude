//
// Copyright (c) Bryan Berns.
// Licensed under GPLv3. See LICENSE.md.
//

using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace Certitude
{
    internal sealed class ComparisonValue
    {
        public string Group { get; set; }
        public string Name { get; set; }
        public string Canonical { get; set; }
        public Func<string> Render { get; set; }
        public string Text => Render();
    }

    internal sealed class ComparisonRow
    {
        public string Group { get; set; }
        public string Property { get; set; }
        internal ComparisonValue First { get; set; }
        internal ComparisonValue Second { get; set; }
        public string Basis => First == null ? "(Not Present)" : First.Text is { Length: > 0 } text ? text : "(Empty)";
        public string Compared => Second == null ? "(Not Present)" : Second.Text is { Length: > 0 } text ? text : "(Empty)";
        public bool Different => First == null || Second == null || First.Canonical != Second.Canonical;
        public string Result => First == null ? "Comparison Only" : Second == null ? "Basis Only" :
            Different ? "Different" : "Same";
    }

    internal sealed class ComparisonDocument
    {
        public string Kind { get; set; }
        public string Source { get; set; }
        public Dictionary<string, ComparisonValue> Values { get; } = new Dictionary<string, ComparisonValue>();

        internal void Add(string group, string name, string text, string canonical = null, Func<string> render = null,
            string key = null)
        {
            // Keep identity separate from display names so OID labels cannot change the comparison result.
            Values.Add(group + "/" + (key ?? name), new ComparisonValue
            {
                Group = group, Name = name, Canonical = canonical ?? text ?? "", Render = render ?? (() => text ?? "")
            });
        }

        internal void Date(string group, string name, DateTime? value)
        {
            if (value.HasValue) Add(group, name, "", value.Value.ToUniversalTime().ToString("O"),
                () => TimeDisplay.Stamp(value));
        }

        public static ComparisonRow[] Compare(ComparisonDocument first, ComparisonDocument second)
        {
            // Align the union of properties while preserving missing values as distinct from empty ones.
            if (first == null || second == null) return Array.Empty<ComparisonRow>();
            return first.Values.Keys.Union(second.Values.Keys).Select(key =>
            {
                first.Values.TryGetValue(key, out var left);
                second.Values.TryGetValue(key, out var right);
                return new ComparisonRow { Group = (left ?? right).Group, Property = (left ?? right).Name,
                    First = left, Second = right };
            }).OrderBy(row => row.Group, StringComparer.Ordinal).ThenBy(row => row.Property,
                StringComparer.Ordinal).ToArray();
        }
    }

    internal sealed class ComparisonSource
    {
        public string Label { get; }
        public Func<CancellationToken, ComparisonDocument> Read { get; }
        public ComparisonSource(string label, Func<CancellationToken, ComparisonDocument> read)
        { Label = label; Read = read; }

        public static ComparisonSource Encoded(byte[] bytes, string label) =>
            new ComparisonSource(label, token => ComparisonData.Read(bytes, label, token));

        public static ComparisonSource File(string path) => new ComparisonSource(path, token =>
            ComparisonData.Read(CertificateUtilities.ReadBytes(path, token: token), path, token));

        public static ComparisonSource Record(string configuration, int id, bool request) =>
            new ComparisonSource(configuration + " · " + (request ? "CSR " : "Certificate ") + id, token =>
            {
                // Use the row's actual CA and retrieve the original request independently of issuance status.
                if (id <= 0) throw new ArgumentException("Enter a positive request ID.");
                var bytes = new CertificateStore(configuration).ReadEncoded(id,
                    request ? "Request.RawRequest" : "RawCertificate", token);
                if (bytes == null) throw new InvalidOperationException(request ?
                    "This CA record has no stored request." : "This CA record has no issued certificate.");
                var result = ComparisonData.Read(bytes, configuration + " · Request " + id, token);
                if (result.Kind != (request ? "CSR" : "Certificate"))
                    throw new InvalidDataException("The CA returned a different artifact type.");
                return result;
            });

        public static ComparisonSource Crl(string configuration, int index, bool delta) =>
            new ComparisonSource(configuration + " · " + (delta ? "Delta" : "Base") + " CRL · Index " + index,
                token =>
                {
                    token.ThrowIfCancellationRequested();
                    return ComparisonData.Read(CaAdministration.ReadCrl(configuration, delta, index),
                        configuration + " · " + (delta ? "Delta" : "Base") + " CRL · Index " + index, token);
                });

        public static ComparisonSource Template(string target, string name, string configuration = null) =>
            new ComparisonSource("Template · " + name, token =>
            {
                // Resolve templates in the CA's domain when the source came from a CA record or editor.
                var directory = string.IsNullOrEmpty(configuration) ? OidDirectory.Connect(target) :
                    OidNames.DirectoryFor(configuration);
                return ComparisonData.ReadTemplate(directory, name, token);
            });
    }

    internal sealed class ComparisonTemplate
    {
        public string Name { get; set; }
        public string DisplayName { get; set; }
        public string Oid { get; set; }
        public string DistinguishedName { get; set; }
    }

    internal static class ComparisonData
    {
        internal const string FileFilter = "Certificates, CSRs And CRLs|" +
            "*.cer;*.crt;*.pem;*.der;*.csr;*.req;*.crl|All Files|*.*";

        public static ComparisonDocument Read(byte[] encoded, string source, CancellationToken token)
        {
            // Accept one public artifact and reject extra PEM blocks or trailing DER data.
            token.ThrowIfCancellationRequested();
            if (encoded == null || encoded.Length == 0 || encoded.Length > 32 * 1024 * 1024)
                throw new InvalidDataException("Select a nonempty public certificate, CSR or CRL up to 32 MB.");
            var bytes = encoded;
            var text = Encoding.ASCII.GetString(bytes).Trim();
            if (text.StartsWith("-----BEGIN", StringComparison.Ordinal))
            {
                var match = Regex.Match(text, @"\A-----BEGIN (CERTIFICATE|(?:NEW )?CERTIFICATE REQUEST|" +
                    @"X509 CRL|PKCS7|CMS)-----([A-Za-z0-9+/=\s]+)-----END \1-----\z");
                if (!match.Success) throw new InvalidDataException(
                    "Select one public certificate, CSR or CRL. " +
                    "For a certificate bundle, select a certificate in Certificate Manager.");
                bytes = Convert.FromBase64String(match.Groups[2].Value);
            }
            else if (Regex.IsMatch(text, @"\A[A-Za-z0-9+/=\s]+\z")) bytes = Convert.FromBase64String(text);

            var root = ComparisonDer.Parse(bytes);
            var parts = root.Children(0x30);
            if (parts.Length > 0 && parts[0].Tag == 6)
            {
                // Unwrap signed PKCS #10 and CMC requests without validating or trusting their signers.
                var message = new SignedCms();
                message.Decode(bytes);
                if (message.ContentInfo.Content.Length == 0) throw new InvalidDataException(
                    "This container has no CSR. " +
                    "For a certificate bundle, select a certificate in Certificate Manager.");
                var payload = ComparisonDer.Parse(message.ContentInfo.Content);
                var requests = new List<ComparisonDer>();
                FindRequests(payload, requests, 0, token);
                if (requests.Count != 1) throw new InvalidDataException(
                    "Select a PKCS #10 CSR or a signed request containing exactly one PKCS #10 CSR. " +
                    "For a certificate bundle, select a certificate in Certificate Manager.");
                var wrapped = Request(requests[0], source, token);
                wrapped.Add("Request", "Container", message.ContentInfo.ContentType.Value);
                return wrapped;
            }
            if (IsRequest(root)) return Request(root, source, token);
            if (parts.Length != 3 || parts[0].Tag != 0x30 || parts[1].Tag != 0x30 || parts[2].Tag != 3)
                throw new InvalidDataException("Select one public certificate, PKCS #10 CSR or CRL.");
            var body = parts[0].Children();
            if (body.Length >= 6 && (body[0].Tag == 0xa0 ||
                body[0].Tag == 2 && body[3].Tag == 0x30)) return Certificate(root, source, token);
            return Crl(root, source, token);
        }

        private static bool IsRequest(ComparisonDer root)
        {
            // Distinguish PKCS #10 from certificates and CRLs using its signed content structure.
            if (root.Tag != 0x30) return false;
            var parts = root.Children();
            if (parts.Length != 3 || parts[0].Tag != 0x30 || parts[1].Tag != 0x30 || parts[2].Tag != 3) return false;
            var body = parts[0].Children();
            return body.Length == 4 && body[0].Tag == 2 && body[1].Tag == 0x30 &&
                body[2].Tag == 0x30 && body[3].Tag == 0xa0;
        }

        private static void FindRequests(ComparisonDer value, List<ComparisonDer> requests, int depth,
            CancellationToken token)
        {
            // Bound nested CMC traversal and retain ambiguity instead of choosing an arbitrary request.
            token.ThrowIfCancellationRequested();
            if (depth > 16) throw new InvalidDataException("The request container is nested too deeply.");
            if (IsRequest(value)) { requests.Add(value); return; }
            if ((value.Tag & 32) != 0)
                foreach (var child in value.Children()) FindRequests(child, requests, depth + 1, token);
        }

        private static ComparisonDocument Certificate(ComparisonDer root, string source, CancellationToken token)
        {
            // Decode certificate fields with Windows and align public-key and extension properties with CSRs.
            var bytes = root.Encoded;
            using var certificate = new X509Certificate2(bytes);
            var result = new ComparisonDocument { Kind = "Certificate", Source = source };
            var body = root.Children()[0].Children();
            var offset = body[0].Tag == 0xa0 ? 1 : 0;
            result.Add("Identity", "Subject", certificate.Subject,
                Convert.ToBase64String(certificate.SubjectName.RawData));
            result.Add("Identity", "Issuer", certificate.Issuer,
                Convert.ToBase64String(certificate.IssuerName.RawData));
            result.Add("Identity", "Serial Number", certificate.SerialNumber);
            result.Add("Identity", "Version", certificate.Version.ToString(CultureInfo.InvariantCulture));
            result.Date("Validity", "Valid From", certificate.NotBefore.ToUniversalTime());
            result.Date("Validity", "Expires", certificate.NotAfter.ToUniversalTime());
            PublicKey(result, body[offset + 5]);
            foreach (var extension in certificate.Extensions.Cast<X509Extension>())
            {
                token.ThrowIfCancellationRequested();
                Extension(result, extension);
            }
            Signature(result, root);
            return result;
        }

        private static ComparisonDocument Request(ComparisonDer root, string source, CancellationToken token)
        {
            // Decode the subject, public key, and signed attributes without creating a key or enrollment request.
            var body = root.Children()[0].Children();
            if (body[0].Integer != "0") throw new InvalidDataException("Unsupported PKCS #10 request version.");
            var result = new ComparisonDocument { Kind = "CSR", Source = source };
            var name = new X500DistinguishedName(body[1].Encoded);
            result.Add("Identity", "Subject", name.Name, body[1].Base64);
            result.Add("Request", "Version", body[0].Integer);
            PublicKey(result, body[2]);
            foreach (var attribute in body[3].Children())
            {
                token.ThrowIfCancellationRequested();
                var fields = attribute.Children(0x30);
                if (fields.Length != 2) throw new InvalidDataException("Invalid CSR attribute.");
                var oid = fields[0].Oid;
                var values = fields[1].Children(0x31);
                if (oid == "1.2.840.113549.1.9.14" || oid == "1.3.6.1.4.1.311.2.1.14")
                {
                    if (values.Length != 1) throw new InvalidDataException("Ambiguous CSR extension request.");
                    foreach (var extension in values[0].Children(0x30))
                    {
                        token.ThrowIfCancellationRequested();
                        Extension(result, DecodeExtension(extension));
                    }
                }
                else result.Add("Request Attributes", OidNames.Windows.Describe(oid),
                    string.Join(Environment.NewLine, values.Select(value => value.Text).OrderBy(value => value,
                        StringComparer.Ordinal)), string.Join("\n", values.Select(value => value.Base64)
                        .OrderBy(value => value, StringComparer.Ordinal)), key: oid);
            }
            Signature(result, root);
            return result;
        }

        private static void PublicKey(ComparisonDocument result, ComparisonDer key)
        {
            // Compare algorithm parameters and key bytes independently of the enclosing certificate or CSR.
            var fields = key.Children(0x30);
            if (fields.Length != 2 || fields[1].Tag != 3 || fields[1].Content.Length < 2 || fields[1].Content[0] != 0)
                throw new InvalidDataException("Invalid public key.");
            var algorithm = fields[0].Children(0x30);
            if (algorithm.Length < 1 || algorithm.Length > 2) throw new InvalidDataException("Invalid key algorithm.");
            var oid = algorithm[0].Oid;
            result.Add("Public Key", "Algorithm", OidNames.Windows.Describe(oid, 3), oid);
            var parameters = algorithm.Length == 2 ? algorithm[1].Encoded : Array.Empty<byte>();
            result.Add("Public Key", "Parameters", algorithm.Length == 2 ? algorithm[1].Text : "",
                Convert.ToBase64String(parameters));
            var encodedKey = fields[1].Content.Skip(1).ToArray();
            result.Add("Public Key", "Key SHA-256", Hash(encodedKey));
            result.Add("Public Key", "Key (Base64)", Convert.ToBase64String(encodedKey));
            if (oid is "1.2.840.113549.1.1.1" or "1.2.840.113549.1.1.10")
            {
                var modulus = ComparisonDer.Parse(encodedKey).Children(0x30)[0].Content.SkipWhile(value => value == 0)
                    .ToArray();
                if (modulus.Length == 0) throw new InvalidDataException("Invalid RSA modulus.");
                var bits = (modulus.Length - 1) * 8;
                for (int value = modulus[0]; value > 0; value >>= 1) bits++;
                result.Add("Public Key", "Size (Bits)", bits.ToString(CultureInfo.InvariantCulture));
            }
            else if (oid == "1.2.840.10045.2.1" && algorithm.Length == 2 && algorithm[1].Tag == 6)
            {
                var bits = algorithm[1].Oid switch { "1.2.840.10045.3.1.7" => 256, "1.3.132.0.34" => 384,
                    "1.3.132.0.35" => 521, _ => 0 };
                if (bits > 0) result.Add("Public Key", "Size (Bits)", bits.ToString(CultureInfo.InvariantCulture));
            }
        }

        private static void Signature(ComparisonDocument result, ComparisonDer root)
        {
            // Expose signed encoding differences separately from meaningful identity and extension fields.
            var parts = root.Children();
            var algorithm = parts[1].Children(0x30);
            if (algorithm.Length < 1 || algorithm.Length > 2 || algorithm[0].Tag != 6 ||
                parts[2].Content.Length < 2 || parts[2].Content[0] != 0)
                throw new InvalidDataException("Invalid signature encoding.");
            result.Add("Signature", "Algorithm", OidNames.Windows.Describe(algorithm[0].Oid, 4), algorithm[0].Oid);
            if (algorithm.Length > 1) result.Add("Signature", "Parameters", algorithm[1].Text, algorithm[1].Base64);
            result.Add("Encoding", "SHA-256", Hash(root.Encoded));
            result.Add("Encoding", "Size (Bytes)", root.Encoded.Length.ToString(CultureInfo.InvariantCulture));
            result.Add("Encoding", "Signature (Base64)", parts[2].Base64);
        }

        private static X509Extension DecodeExtension(ComparisonDer extension)
        {
            // Preserve the OID, optional critical flag, and extension payload as distinct values.
            var fields = extension.Children(0x30);
            if (fields.Length < 2 || fields.Length > 3 || fields[fields.Length - 1].Tag != 4 ||
                fields.Length == 3 && (fields[1].Tag != 1 || fields[1].Content.Length != 1))
                throw new InvalidDataException("Invalid extension encoding.");
            return new X509Extension(fields[0].Oid, fields[fields.Length - 1].Content,
                fields.Length == 3 && fields[1].Content[0] != 0);
        }

        private static void Extension(ComparisonDocument result, X509Extension extension)
        {
            // Normalize unordered SAN and EKU members, retaining exact encodings in their own section.
            var oid = extension.Oid.Value;
            var name = OidNames.Windows.Describe(oid, 6);
            var raw = Convert.ToBase64String(extension.RawData);
            var canonical = raw;
            if (oid is "2.5.29.17" or "2.5.29.18" or "2.5.29.37")
                canonical = string.Join("\n", ComparisonDer.Parse(extension.RawData).Children(0x30)
                    .Select(item => item.Base64).OrderBy(value => value, StringComparer.Ordinal));
            string formatted;
            Func<string> render = null;
            try
            {
                formatted = OidNames.Windows.FormatExtension(extension).Trim();
                if (oid is "2.5.29.16" or "2.5.29.24")
                    render = () => OidNames.Windows.FormatExtension(extension).Trim();
            }
            catch (CryptographicException) { formatted = "DER (Base64): " + raw; }
            result.Add("Extensions", name, formatted, canonical, render, oid);
            result.Add("Extension Flags", name + " · Critical", extension.Critical.ToString(), key: oid);
            result.Add("Encoding", name + " · DER (Base64)", raw, key: "Extension/" + oid);
        }

        private static ComparisonDocument Crl(ComparisonDer root, string source, CancellationToken token)
        {
            // Use Windows to validate the CRL structure before comparing metadata and individual entries.
            var bytes = root.Encoded;
            var metadata = CertificateValidation.InspectCrl(bytes, source, null, Array.Empty<X509Certificate2>());
            var result = new ComparisonDocument { Kind = "CRL", Source = source };
            var body = root.Children()[0].Children(0x30);
            var index = body[0].Tag == 2 ? 1 : 0;
            result.Add("Identity", "Issuer", metadata.Issuer, body[index + 1].Base64);
            result.Add("CRL", "Type", metadata.IsDelta ? "Delta" : "Base");
            result.Add("CRL", "Number", metadata.Number);
            result.Add("CRL", "Entry Count", metadata.EntryCount.ToString(CultureInfo.InvariantCulture));
            result.Date("Validity", "This Update", metadata.ThisUpdate);
            result.Date("Validity", "Next Update", metadata.NextUpdate);
            index += 3;
            if (index < body.Length && body[index].Tag is 23 or 24) index++;
            if (index < body.Length && body[index].Tag == 0x30)
            {
                // Include issuer changes when identifying entries in indirect CRLs.
                var issuer = body[(body[0].Tag == 2 ? 1 : 0) + 1].Base64;
                var issuerName = metadata.Issuer;
                foreach (var entry in body[index++].Children())
                {
                    token.ThrowIfCancellationRequested();
                    var fields = entry.Children(0x30);
                    var serial = fields[0].Integer;
                    var extensions = fields.Length > 2 ? fields[2].Children(0x30).Select(DecodeExtension).ToArray() :
                        Array.Empty<X509Extension>();
                    var changedIssuer = extensions.FirstOrDefault(value => value.Oid.Value == "2.5.29.29");
                    if (changedIssuer != null)
                    {
                        var names = ComparisonDer.Parse(changedIssuer.RawData).Children(0x30);
                        var directoryName = names.FirstOrDefault(value => value.Tag == 0xa4);
                        issuer = directoryName == null ? Convert.ToBase64String(changedIssuer.RawData) :
                            directoryName.Children()[0].Base64;
                        issuerName = directoryName == null ? OidNames.Windows.FormatExtension(changedIssuer) :
                            new X500DistinguishedName(directoryName.Children()[0].Encoded).Name;
                    }
                    var date = fields[1].Time;
                    var details = new TimeReport();
                    foreach (var extension in extensions)
                    {
                        details.AppendLine().Append(OidNames.Windows.Describe(extension.Oid.Value, 6) + ": ");
                        if (extension.Oid.Value == "2.5.29.24")
                            details.Append(() => OidNames.Windows.FormatExtension(extension));
                        else details.Append(OidNames.Windows.FormatExtension(extension));
                    }
                    var canonical = fields[1].Base64 + "\n" + string.Join("\n", extensions
                        .Where(value => value.Oid.Value != "2.5.29.29")
                        .OrderBy(value => value.Oid.Value, StringComparer.Ordinal)
                        .Select(value => value.Oid.Value + ":" + value.Critical + ":" +
                            Convert.ToBase64String(value.RawData)));
                    result.Add("Revoked Certificates", "Serial " + fields[0].Hex + " · " + issuerName, "", canonical,
                        () => TimeDisplay.Stamp(date) + details, serial + "/" + issuer);
                }
            }
            if (index < body.Length && body[index].Tag == 0xa0)
                foreach (var extension in body[index].Children()[0].Children(0x30))
                    Extension(result, DecodeExtension(extension));
            Signature(result, root);
            return result;
        }

        public static ComparisonTemplate[] Templates(OidDirectory directory, CancellationToken token)
        {
            // Read lightweight template identities before fetching the selected template's settings.
            using var root = directory.Open(directory.TemplatesName);
            using var search = new DirectorySearcher(root, "(objectClass=pKICertificateTemplate)",
                new[] { "cn", "displayName", "msPKI-Cert-Template-OID", "distinguishedName" }, SearchScope.OneLevel)
            {
                PageSize = 1000, ClientTimeout = TimeSpan.FromSeconds(30),
                ServerTimeLimit = TimeSpan.FromSeconds(30), ReferralChasing = ReferralChasingOption.None
            };
            using var results = search.FindAll();
            var templates = new List<ComparisonTemplate>();
            foreach (SearchResult item in results)
            {
                token.ThrowIfCancellationRequested();
                string Text(string name) => item.Properties[name].Count == 0 ? "" :
                    Convert.ToString(item.Properties[name][0], CultureInfo.InvariantCulture);
                templates.Add(new ComparisonTemplate { Name = Text("cn"), DisplayName = Text("displayName"),
                    Oid = Text("msPKI-Cert-Template-OID"), DistinguishedName = Text("distinguishedName") });
            }
            return templates.OrderBy(item => item.DisplayName, StringComparer.OrdinalIgnoreCase).ToArray();
        }

        public static ComparisonDocument ReadTemplate(OidDirectory directory, string identity, CancellationToken token)
        {
            // Resolve an exact name, OID, or distinguished name within the chosen forest's template container.
            var matches = Templates(directory, token).Where(item =>
                new[] { item.Name, item.Oid, item.DistinguishedName }.Contains(identity,
                    StringComparer.OrdinalIgnoreCase)).ToArray();
            if (matches.Length != 1) throw new InvalidOperationException("Select one template from the directory.");
            token.ThrowIfCancellationRequested();
            using var entry = directory.Open(matches[0].DistinguishedName);
            entry.Options.SecurityMasks = SecurityMasks.Owner | SecurityMasks.Group | SecurityMasks.Dacl;
            entry.RefreshCache();
            var result = new ComparisonDocument { Kind = "Template",
                Source = directory.Server + " · " + matches[0].Name };
            var attributes = entry.Properties.PropertyNames.Cast<string>().Where(name =>
                name.StartsWith("pKI", StringComparison.OrdinalIgnoreCase) ||
                name.StartsWith("msPKI-", StringComparison.OrdinalIgnoreCase) ||
                new[] { "cn", "displayName", "flags", "revision" }.Contains(name, StringComparer.OrdinalIgnoreCase));
            foreach (var attribute in attributes.OrderBy(name => name, StringComparer.OrdinalIgnoreCase))
            {
                token.ThrowIfCancellationRequested();
                var values = entry.Properties[attribute].Cast<object>().Select(value => TemplateValue(attribute, value))
                    .OrderBy(value => value, StringComparer.Ordinal).ToArray();
                result.Add("Template Settings", attribute, string.Join(Environment.NewLine, values),
                    key: attribute.ToLowerInvariant());
            }

            // Preserve the complete DACL and owner without claiming to calculate effective permissions.
            token.ThrowIfCancellationRequested();
            var security = entry.ObjectSecurity;
            result.Add("Template Security", "Owner / Group / DACL", security.GetSecurityDescriptorSddlForm(
                AccessControlSections.Owner | AccessControlSections.Group | AccessControlSections.Access));
            return result;
        }

        private static string TemplateValue(string name, object value)
        {
            // Render AD duration and flag attributes alongside stable raw representations.
            if (value is byte[] bytes)
            {
                if ((name.Equals("pKIExpirationPeriod", StringComparison.OrdinalIgnoreCase) ||
                    name.Equals("pKIOverlapPeriod", StringComparison.OrdinalIgnoreCase)) && bytes.Length == 8)
                {
                    var ticks = BitConverter.ToInt64(bytes, 0);
                    if (ticks <= 0 && ticks != long.MinValue) return TimeSpan.FromTicks(-ticks) +
                        " (" + ticks.ToString(CultureInfo.InvariantCulture) + " ticks)";
                }
                return "Base64: " + Convert.ToBase64String(bytes);
            }
            var text = Convert.ToString(value, CultureInfo.InvariantCulture);
            if (name.IndexOf("flag", StringComparison.OrdinalIgnoreCase) >= 0 &&
                long.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var flags))
                return text + " (0x" + unchecked((uint)flags).ToString("X8") + ")";
            return text;
        }

        private static string Hash(byte[] bytes)
        {
            using var hash = SHA256.Create();
            return BitConverter.ToString(hash.ComputeHash(bytes)).Replace("-", "");
        }
    }

    internal sealed class ComparisonDer
    {
        private readonly byte[] bytes;
        private readonly int start, content, end;
        public int Tag { get; }
        public byte[] Encoded => Slice(start, end);
        public byte[] Content => Slice(content, end);
        public string Base64 => Convert.ToBase64String(bytes, start, end - start);
        public string Hex => BitConverter.ToString(Content).Replace("-", "").TrimStart('0') is { Length: > 0 } value ?
            value : "0";
        public string Oid => Tag == 6 ? OidNames.DecodeOid(bytes, content, end) :
            throw new InvalidDataException("Expected an object identifier.");
        public string Integer => Tag == 2 && end > content && end - content <= 1024 ?
            new BigInteger(Content.Reverse().ToArray()).ToString(CultureInfo.InvariantCulture) :
            throw new InvalidDataException("Expected an integer of at most 1,024 bytes.");
        public DateTime Time
        {
            get
            {
                // Apply the X.509 UTC-time century boundary independently of Windows calendar settings.
                var text = Encoding.ASCII.GetString(Content);
                if (Tag == 23 && text.Length == 13)
                    text = (int.Parse(text.Substring(0, 2), CultureInfo.InvariantCulture) < 50 ? "20" : "19") + text;
                if (Tag is not (23 or 24)) throw new InvalidDataException("Expected an X.509 time.");
                return DateTime.ParseExact(text, "yyyyMMddHHmmss'Z'", CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);
            }
        }
        public string Text => Tag switch
        {
            2 => Integer, 5 => "NULL", 6 => OidNames.Windows.Describe(Oid),
            12 => Encoding.UTF8.GetString(Content), 19 or 20 or 22 => Encoding.ASCII.GetString(Content),
            30 => Encoding.BigEndianUnicode.GetString(Content), _ => "DER (Base64): " + Base64
        };

        private ComparisonDer(byte[] bytes, int start, int limit)
        {
            this.bytes = bytes;
            this.start = start;
            var position = start;
            Tag = OidNames.ReadElement(bytes, ref position, limit, out end);
            content = position;
        }

        private byte[] Slice(int first, int last)
        {
            // Copy directly so reading many CRL entries remains linear in the encoded input size.
            var result = new byte[last - first];
            Buffer.BlockCopy(bytes, first, result, 0, result.Length);
            return result;
        }

        public static ComparisonDer Parse(byte[] bytes)
        {
            var value = new ComparisonDer(bytes, 0, bytes.Length);
            if (value.end != bytes.Length)
                throw new InvalidDataException("Select a single encoded artifact without trailing data.");
            return value;
        }

        public ComparisonDer[] Children(int tag = -1)
        {
            // Walk only the requested container and reject unreasonable element counts before allocating rows.
            if ((Tag & 32) == 0 || tag >= 0 && Tag != tag)
                throw new InvalidDataException("Unexpected ASN.1 structure.");
            var values = new List<ComparisonDer>();
            for (var position = content; position < end;)
            {
                if (values.Count == 100000)
                    throw new InvalidDataException("This artifact contains more than 100,000 entries.");
                var value = new ComparisonDer(bytes, position, end);
                values.Add(value);
                position = value.end;
            }
            return values.ToArray();
        }
    }
}
