//
// Copyright (c) Bryan Berns.
// Licensed under GPLv3. See LICENSE.md.
//

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace Certitude
{
    internal sealed class ScepTester
    {
        internal const string AgentOid = "1.3.6.1.4.1.311.20.2.1";
        internal const int Timeout = 15, ResponseLimit = 4 * 1024 * 1024;
        internal Uri Endpoint { get; }
        private readonly string identifier;
        internal string[] Capabilities { get; private set; } = Array.Empty<string>();
        internal byte[][] Certificates { get; private set; } = Array.Empty<byte[]>();
        internal TimeReport Report { get; } = new TimeReport();
        internal string Summary { get; private set; }

        internal ScepTester(string endpoint, string identifier)
        {
            // Preserve endpoint-specific parameters while keeping the SCEP operation and message unambiguous.
            if (!Uri.TryCreate(endpoint?.Trim(), UriKind.Absolute, out var uri) ||
                uri.Scheme is not ("http" or "https") || uri.Port == 0 || uri.UserInfo.Length != 0 ||
                uri.Fragment.Length != 0 || !uri.IsWellFormedOriginalString())
                throw new ArgumentException("Enter an HTTP(S) SCEP endpoint URL without credentials or a fragment.");
            if (uri.Query.TrimStart('?').Split('&').Select(part => Uri.UnescapeDataString(part.Split('=')[0]))
                .Any(key => key.Equals("operation", StringComparison.OrdinalIgnoreCase) ||
                    key.Equals("message", StringComparison.OrdinalIgnoreCase)))
                throw new ArgumentException("Enter the base SCEP URL without an operation or message parameter.");
            Endpoint = uri;
            this.identifier = identifier?.Trim();
        }

        internal Uri Operation(string name, string message = null)
        {
            var query = Endpoint.Query.TrimStart('?');
            return new UriBuilder(Endpoint) { Query = (query.Length == 0 ? "" : query + "&") + "operation=" + name +
                (string.IsNullOrEmpty(message) ? "" : "&message=" + Uri.EscapeDataString(message)) }.Uri;
        }

        internal void Discover(CancellationToken token)
        {
            // Probe independently so a legacy capability failure leaves the CA certificate diagnostic available.
            var network = NetworkAccess.Current;
            Report.AppendLine(Endpoint.GetLeftPart(UriPartial.Path)).Append("Checked: ").AppendTime(DateTime.UtcNow)
                .AppendLine().AppendLine("HTTP route: " + network.Route(Endpoint));
            var capsRead = false;
            try
            {
                var caps = network.Fetch(Operation("GetCACaps", identifier), Timeout, 64 * 1024, token);
                Report.AppendLine().AppendLine($"GetCACaps · HTTP {caps.Status} · {caps.MediaType}");
                var lines = Encoding.ASCII.GetString(caps.Body).Split(new[] { '\r', '\n' },
                    StringSplitOptions.RemoveEmptyEntries).Select(line => line.Trim()).Where(line => line.Length > 0)
                    .Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
                if (lines.Any(line => !Regex.IsMatch(line, @"\A[A-Za-z0-9][A-Za-z0-9._-]*\z")))
                    throw new InvalidDataException("The response does not contain SCEP capability keywords.");
                Capabilities = lines;
                capsRead = true;
                Report.AppendLine(lines.Length == 0 ? "No capabilities advertised." : string.Join(", ", lines));
            }
            catch (Exception error) when (error is not OperationCanceledException)
            { Report.AppendLine("GetCACaps failed: " + error.Message); }

            // Accept public X.509 and certificates-only CMS responses without importing them into a Windows store.
            try
            {
                var ca = network.Fetch(Operation("GetCACert", identifier), Timeout, ResponseLimit, token);
                Report.AppendLine().AppendLine($"GetCACert · HTTP {ca.Status} · {ca.MediaType}");
                var certs = ReadCertificates(ca.Body);
                try
                {
                    foreach (var cert in certs)
                    {
                        Report.AppendLine().AppendLine((IsCa(cert) ? "CA: " : "Certificate: ") + cert.Subject)
                            .AppendLine("Issuer: " + cert.Issuer).AppendLine("SHA-256: " +
                                CertificateUtilities.Sha256(cert.RawData)).Append("Valid from: ")
                            .AppendTime(cert.NotBefore).Append(" through ").AppendTime(cert.NotAfter).AppendLine();
                    }
                    if (!certs.Cast<X509Certificate2>().Any(IsCa))
                        throw new InvalidDataException("The response contains no CA certificate.");
                    Certificates = certs.Cast<X509Certificate2>().Select(cert => cert.RawData).ToArray();
                    if (Endpoint.Scheme == "http") Report.AppendLine().AppendLine(
                        "Obtain the enrollment fingerprint separately from your CA administrator.");
                }
                finally { foreach (var cert in certs) cert.Dispose(); }
            }
            catch (Exception error) when (error is not OperationCanceledException)
            { Report.AppendLine("GetCACert failed: " + error.Message); }
            Summary = Certificates.Length == 0 ? "CA certificate check failed." : capsRead ?
                "Endpoint check passed." : "CA certificates retrieved. Capability check failed.";
        }

        internal static X509Certificate2Collection ReadCertificates(byte[] bytes)
        {
            // Check the container before decoding so a network response can never load a private key.
            var certs = new X509Certificate2Collection();
            var type = X509Certificate2.GetCertContentType(bytes);
            if (type == X509ContentType.Cert)
                certs.Add(CertificateUtilities.SingleCertificate(bytes));
            else if (type == X509ContentType.Pkcs7)
            {
                var cms = new SignedCms();
                cms.Decode(bytes);
                if (cms.SignerInfos.Count != 0 || cms.ContentInfo.Content.Length != 0)
                    throw new InvalidDataException("Expected a certificates-only PKCS #7 response.");
                certs = cms.Certificates;
            }
            else throw new InvalidDataException("Expected a public X.509 certificate or PKCS #7 certificate bundle.");
            if (certs.Count is > 0 and <= 128) return certs;
            foreach (var cert in certs) cert.Dispose();
            throw new InvalidDataException("Expected between one and 128 public certificates.");
        }

        internal static bool IsCa(X509Certificate2 cert) =>
            cert.Extensions.OfType<X509BasicConstraintsExtension>().Any(ext => ext.CertificateAuthority);

        internal bool Supports(string name) => Capabilities.Contains(name, StringComparer.OrdinalIgnoreCase);

        internal void LoadAuthorities(string expected, X509Certificate2Collection trusted)
        {
            // Authenticate the CA itself so RA rollover does not change the administrator's trust anchor.
            var pin = Regex.Replace(expected ?? "", @"[\s:\u200e\u200f]", "");
            if (pin.Length == 0 && Endpoint.Scheme != "https" ||
                pin.Length != 0 && !Regex.IsMatch(pin, @"\A(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\z"))
                throw new ArgumentException("Enter a trusted SHA-256 or SHA-1 CA certificate fingerprint. " +
                    "A fingerprint is required for HTTP enrollment.");
            var supplied = new X509Certificate2Collection();
            try
            {
                foreach (var bytes in Certificates) supplied.Add(new X509Certificate2(bytes));
                var cas = supplied.Cast<X509Certificate2>().Where(IsCa).ToArray();
                var now = DateTime.Now;
                var anchors = cas.Where(cert => pin.Length == 0 ?
                    CertificateValidation.SignedBy(cert, cert) ||
                        !cas.Any(parent => parent != cert && CertificateValidation.SignedBy(cert, parent)) :
                    pin.Equals(pin.Length == 40 ? cert.Thumbprint : CertificateUtilities.Sha256(cert.RawData),
                        StringComparison.OrdinalIgnoreCase))
                    .Where(cert => cert.NotBefore <= now && now <= cert.NotAfter).ToArray();
                if (anchors.Length == 0) throw new InvalidDataException(
                    "No current CA certificate matches the trusted CA fingerprint or HTTPS discovery chain.");
                foreach (var cert in CertificateValidation.ScepAuthorities(supplied.Cast<X509Certificate2>().ToArray(),
                    anchors, requireAgentUsage: Endpoint.Scheme == "http" || pin.Length > 0))
                    trusted.Add(new X509Certificate2(cert.RawData));
            }
            finally { foreach (var cert in supplied) cert.Dispose(); }
        }
    }

    internal sealed class ScepEnrollment : IDisposable
    {
        private const string AttributePrefix = "2.16.840.1.113733.1.9.";
        private readonly ScepTester server;
        private readonly X509Certificate2Collection authorities = new X509Certificate2Collection();
        private readonly RSACng key;
        private readonly CertificateRequest request;
        private readonly X509Certificate2 client, recipient;
        internal string TransactionId { get; }
        internal string AuthoritySummary { get; }
        internal bool CanPoll { get; private set; }
        internal byte[] IssuedCertificate { get; private set; }

        internal ScepEnrollment(ScepTester server, string subject, string fingerprint)
        {
            // Authenticate the discovery response before selecting a recipient for a challenge password.
            this.server = server;
            try
            {
                server.LoadAuthorities(fingerprint, authorities);
                var candidates = authorities.Cast<X509Certificate2>().Where(cert =>
                    cert.PublicKey.Oid.Value == "1.2.840.113549.1.1.1").ToArray();
                recipient = candidates.Where(cert => Allows(cert, X509KeyUsageFlags.KeyEncipherment))
                    .OrderBy(ScepTester.IsCa).ThenBy(cert => candidates.Any(other => other != cert &&
                        ScepTester.IsCa(other) && CertificateValidation.SignedBy(other, cert)))
                    .ThenByDescending(cert => cert.NotBefore).FirstOrDefault();
                // Single-CA SCEP servers can advertise their sole RSA key for both operations.
                if (recipient == null && server.Certificates.Length == 1 && candidates.Length == 1 &&
                    ScepTester.IsCa(candidates[0])) recipient = candidates[0];
                if (recipient == null) throw new InvalidDataException(
                    "No trusted RSA encryption certificate was found. HTTP RA certificates need the " +
                    "Certificate Request Agent application policy.");
                var signers = authorities.Cast<X509Certificate2>().Where(cert =>
                    Allows(cert, X509KeyUsageFlags.DigitalSignature)).ToArray();
                if (signers.Length == 0)
                    throw new InvalidDataException("No trusted SCEP signing certificate was found.");
                string Describe(X509Certificate2 cert) => cert.Subject + " · SHA-256 " +
                    CertificateUtilities.Sha256(cert.RawData);
                AuthoritySummary = "Encryption certificate: " + Describe(recipient) + "\r\nReply signer: " +
                    string.Join("\r\nReply signer: ", signers.Select(Describe));

                // Use a software-only, ephemeral RSA key for both the PKCS #10 and the SCEP signer.
                key = new RSACng(2048);
                request = new CertificateRequest(new X500DistinguishedName(subject), key, HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1);
                var identity = new CertificateRequest(request.SubjectName, key, HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1);
                identity.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature |
                    X509KeyUsageFlags.KeyEncipherment, true));
                client = identity.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5),
                    DateTimeOffset.UtcNow.AddDays(1));
                TransactionId = CertificateUtilities.Sha256(client.GetPublicKey());
            }
            catch { Dispose(); throw; }
        }

        private static bool Allows(X509Certificate2 cert, X509KeyUsageFlags use) =>
            cert.Extensions.OfType<X509KeyUsageExtension>().All(usage => (usage.KeyUsages & use) == use);

        internal string Exchange(string challenge, bool poll, CancellationToken token)
        {
            // Reuse the original transaction and key for CertPoll, with a fresh nonce for every exchange.
            token.ThrowIfCancellationRequested();
            var issuer = ScepTester.IsCa(recipient) ? recipient.SubjectName : recipient.IssuerName;
            var payload = poll ? Der(0x30, issuer.RawData, client.SubjectName.RawData) : SigningRequest(challenge);
            byte[] message;
            var nonce = new byte[16];
            using (var random = RandomNumberGenerator.Create()) random.GetBytes(nonce);
            try
            {
                var standard = server.Supports("SCEPStandard");
                var tripleDes = !standard && !server.Supports("AES") && server.Supports("DES3");
                var envelope = new EnvelopedCms(new ContentInfo(payload), new AlgorithmIdentifier(
                    new Oid(tripleDes ? "1.2.840.113549.3.7" : "2.16.840.1.101.3.4.1.2")));
                envelope.Encrypt(new CmsRecipient(recipient));
                var cms = new SignedCms(new ContentInfo(envelope.Encode()));
                var digest = standard ? "SHA-256" : new[] { "SHA-256", "SHA-512", "SHA-1" }
                    .FirstOrDefault(server.Supports) ?? "SHA-256";
                var signer = new CmsSigner(client) { IncludeOption = X509IncludeOption.EndCertOnly,
                    DigestAlgorithm = new Oid(CryptoConfig.MapNameToOID(digest.Replace("-", ""))) };
                void Attribute(string number, byte[] value) =>
                    signer.SignedAttributes.Add(new AsnEncodedData(new Oid(AttributePrefix + number), value));
                Attribute("2", Der(19, Encoding.ASCII.GetBytes(poll ? "20" : "19")));
                Attribute("5", Der(4, nonce));
                Attribute("7", Der(19, Encoding.ASCII.GetBytes(TransactionId)));
                cms.ComputeSignature(signer, true);
                message = cms.Encode();
            }
            finally { Array.Clear(payload, 0, payload.Length); }

            // A dropped response can still mean the CA accepted the request. Keep its polling identity available.
            var post = server.Supports("SCEPStandard") || server.Supports("POSTPKIOperation");
            var url = server.Operation("PKIOperation", post ? null : Convert.ToBase64String(message));
            token.ThrowIfCancellationRequested();
            CanPoll = true;
            var response = NetworkAccess.Current.Fetch(url, ScepTester.Timeout, ScepTester.ResponseLimit, token,
                post ? message : null);
            return ReadReply(response.Body, nonce);
        }

        private byte[] SigningRequest(string challenge)
        {
            // .NET Framework emits a PKCS #10 with an empty attribute set. Sign the challenge with the same key.
            var csr = request.CreateSigningRequest();
            if (string.IsNullOrEmpty(challenge)) return csr;
            var parts = ComparisonDer.Parse(csr).Children(0x30);
            var info = parts[0].Children(0x30);
            var secret = Encoding.UTF8.GetBytes(challenge);
            try
            {
                var tag = Regex.IsMatch(challenge, @"\A[A-Za-z0-9 '()+,./:=?-]*\z") ? (byte)19 : (byte)12;
                var attribute = Der(0x30, CryptoConfig.EncodeOID("1.2.840.113549.1.9.7"), Der(0x31, Der(tag, secret)));
                var body = Der(0x30, info[0].Encoded, info[1].Encoded, info[2].Encoded, Der(0xa0, attribute));
                var signature = key.SignData(body, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                return Der(0x30, body, parts[1].Encoded, Der(3, new byte[] { 0 }, signature));
            }
            finally { Array.Clear(secret, 0, secret.Length); }
        }

        private string ReadReply(byte[] bytes, byte[] nonce)
        {
            // Authenticate the CertRep against the reviewed CA/RA certificates before using any status or content.
            var cms = new SignedCms();
            cms.Decode(bytes);
            if (cms.SignerInfos.Count != 1) throw new InvalidDataException("Expected one CertRep signer.");
            var signer = cms.SignerInfos[0];
            using var embedded = signer.Certificate;
            if (!authorities.Cast<X509Certificate2>().Any(cert => Allows(cert, X509KeyUsageFlags.DigitalSignature) &&
                (embedded == null ? Matches(signer.SignerIdentifier, cert) :
                    cert.RawData.SequenceEqual(embedded.RawData))))
                throw new InvalidDataException("The CertRep signer is outside the endpoint's CA/RA response.");
            signer.CheckSignature(authorities, true);
            byte[] Attribute(string number, int tag)
            {
                var attr = signer.SignedAttributes.Cast<CryptographicAttributeObject>()
                    .SingleOrDefault(item => item.Oid.Value == AttributePrefix + number);
                if (attr?.Values.Count != 1)
                    throw new InvalidDataException("Missing or repeated SCEP attribute " + number + ".");
                var value = ComparisonDer.Parse(attr.Values[0].RawData);
                if (value.Tag != tag) throw new InvalidDataException("Invalid SCEP attribute " + number);
                return value.Content;
            }
            string Code(string number) => Encoding.ASCII.GetString(Attribute(number, 19));
            if (Code("2") != "3" || Code("7") != TransactionId || !Attribute("6", 4).SequenceEqual(nonce))
                throw new InvalidDataException("The CertRep type, transaction ID or recipient nonce does not match.");

            // Report the authenticated disposition and verify that an issued certificate belongs to this request.
            var status = Code("3");
            var notice = status is "2" or "3" && cms.ContentInfo.Content.Length != 0 ?
                "\r\nThe CA included extra signed content with this status. Certitude ignored it." : "";
            switch (status)
            {
                case "3": return "Pending. Use Check Pending Request to poll this transaction." + notice;
                case "2":
                    var failure = Code("4") switch { "0" => "bad algorithm", "1" => "bad message check",
                        "2" => "bad request", "3" => "bad time", "4" => "bad certificate ID", var code => code };
                    CanPoll = false;
                    return "Rejected by the CA: " + failure + "." + notice;
                case "0": break;
                default: throw new InvalidDataException("The CertRep contains an unknown enrollment status.");
            }
            var envelope = new EnvelopedCms();
            envelope.Decode(cms.ContentInfo.Content);
            var ours = envelope.RecipientInfos.Cast<RecipientInfo>().FirstOrDefault(info =>
                Matches(info.RecipientIdentifier, client)) ??
                throw new InvalidDataException("The issued response was encrypted for a different recipient.");
            envelope.Decrypt(ours, new X509Certificate2Collection(client));
            var issued = ScepTester.ReadCertificates(envelope.ContentInfo.Content);
            try
            {
                var certificate = issued.Cast<X509Certificate2>().FirstOrDefault(cert =>
                    cert.GetPublicKey().SequenceEqual(client.GetPublicKey()) && authorities.Cast<X509Certificate2>()
                        .Any(ca => ScepTester.IsCa(ca) && CertificateValidation.SignedBy(cert, ca))) ??
                    throw new InvalidDataException("No issued certificate matched the test key and issuing CA.");
                IssuedCertificate = certificate.RawData;
                CanPoll = false;
                return "Issued: " + certificate.Subject + "\r\nSerial: " + certificate.SerialNumber +
                    "\r\nSHA-256: " + CertificateUtilities.Sha256(IssuedCertificate);
            }
            finally { foreach (var cert in issued) cert.Dispose(); }
        }

        private static bool Matches(SubjectIdentifier id, X509Certificate2 cert) => id.Value switch
        {
            X509IssuerSerial issuer => issuer.IssuerName == cert.Issuer &&
                issuer.SerialNumber.Equals(cert.SerialNumber, StringComparison.OrdinalIgnoreCase),
            string ski => cert.Extensions.OfType<X509SubjectKeyIdentifierExtension>()
                .Any(ext => ski.Equals(ext.SubjectKeyIdentifier, StringComparison.OrdinalIgnoreCase)),
            _ => false
        };

        internal static byte[] Der(byte tag, params byte[][] values)
        {
            // Encode the small DER fields used by SCEP attributes, PKCS #10 and IssuerAndSubject.
            var length = values.Sum(value => value.Length);
            var header = new List<byte> { tag };
            if (length < 128) header.Add((byte)length);
            else
            {
                var octets = new List<byte>();
                for (var left = length; left > 0; left >>= 8) octets.Add((byte)left);
                octets.Reverse();
                header.Add((byte)(0x80 | octets.Count));
                header.AddRange(octets);
            }
            foreach (var value in values) header.AddRange(value);
            return header.ToArray();
        }

        public void Dispose()
        {
            client?.Dispose();
            key?.Dispose();
            foreach (var cert in authorities) cert.Dispose();
        }
    }
}
