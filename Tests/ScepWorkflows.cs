//
// Copyright (c) Bryan Berns.
// Licensed under GPLv3. See LICENSE.md.
//

using System;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Controls;
using System.Windows.Automation;
using static Certitude.ScepEnrollment;

namespace Certitude
{
    internal static partial class WorkflowChecks
    {
        private static void CheckNetworkViews(MainWindow window, string path, string output, string proxyUrl,
            string endpointUrl, string pin, Action discovery, Action<Action> reply, Action<Action> stall)
        {
            // Open the shared setting from Preferences, reject malformed input, and restore it from disk.
            Click(window.ActivePage, "Network Pro_xy…");
            var proxy = window.ActivePage;
            var mode = Children(proxy).OfType<ComboBox>().Single();
            Assert(AutomationProperties.GetLabeledBy(mode) is Label, "The connection mode has no accessible label.");
            mode.SelectedIndex = 2;
            var address = Children(proxy).OfType<TextBox>().Single();
            address.Text = "http://user:pass@proxy.invalid/";
            Click(proxy, "_Save");
            Assert(window.ActivePage == proxy && NetworkAccess.Current.Setting == NetworkAccess.SystemProxy,
                "An invalid proxy changed the active route.");
            address.Text = proxyUrl;
            Render(window, Path.Combine(output, "network-proxy.png"), 1);
            Click(proxy, "_Save");
            Assert(BrowserWorkspace.Load(path).NetworkProxy == NetworkAccess.Current.Setting &&
                NetworkAccess.Current.Address.Authority == new Uri(proxyUrl).Authority,
                "The active proxy did not persist.");

            // Open the tester without a CA and cancel its review before any enrollment traffic can start.
            Call(window, "ToolsClick", null, null);
            Click(window.ActivePage, "Network Pro_xy…");
            proxy = window.ActivePage;
            Assert(Children(proxy).OfType<ComboBox>().Single().SelectedIndex == 2, "Incorrect saved proxy selection.");
            Click(proxy, "_Cancel");
            Click(window.ActivePage, "SCEP _Tester…");
            var tester = (ScepPage)window.ActivePage;
            Assert(!((Expander)Field(tester, "enrollment")).IsEnabled, "Enrollment was available before discovery.");
            ((TextBox)Field(tester, "endpoint")).Text = endpointUrl;
            ((TextBox)Field(tester, "identifier")).Text = "A & B";
            Click(tester, "_Check Endpoint");
            discovery();
            WaitFor(() => Field(tester, "cancellation") == null);
            var enrollment = (Expander)Field(tester, "enrollment");
            Assert(enrollment.IsEnabled, ((TextBox)Field(tester, "output")).Text);
            enrollment.IsExpanded = true;
            ((TextBox)Field(tester, "fingerprint")).Text = pin;
            var challenge = (PasswordBox)Field(tester, "challenge");
            var report = (TextBox)Field(tester, "output");
            void Review()
            {
                Click(tester, "Sub_mit Test Enrollment…");
                WaitFor(() => window.ActivePage.Title == "Submit Test Enrollment" ||
                    Field(tester, "cancellation") == null);
                Assert(window.ActivePage.Title == "Submit Test Enrollment", report.Text);
                Assert(Children(window.ActivePage).OfType<TextBox>().Single().Text.Contains("Encryption certificate:"),
                    "The confirmation did not identify the encryption recipient.");
            }
            challenge.Password = "test-only-PIN";
            Review();
            Assert(!tester.CanClose(), "Closing the parent during confirmation discarded a live transaction.");
            WaitFor(() => window.ActivePage == tester && Field(tester, "cancellation") == null);
            challenge.Password = "test-only-PIN";
            Review();
            Click(window.ActivePage, "_Cancel");
            WaitFor(() => Field(tester, "cancellation") == null);
            Assert(Field(tester, "transaction") == null && challenge.Password == "" &&
                !report.Text.Contains("test-only-PIN"), "Cancellation retained a secret.");

            // Confirm an actual enrollment through the UI and verify the public PEM in the resulting report.
            challenge.Password = "test-only-PIN";
            Review();
            reply(() =>
            {
                Click(window.ActivePage, "_Continue");
                WaitFor(() => Field(tester, "cancellation") == null);
            });
            var pem = report.Text.IndexOf("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal);
            Assert(pem >= 0 && !report.Text.Contains("test-only-PIN"), report.Text);
            var publicCert = (byte[])Field(tester, "issued");
            Assert(report.Text.Contains(Encoding.ASCII.GetString(CertificateUtilities.ExportPublic([publicCert], 1))),
                "The exported report is missing the issued public certificate.");
            Render(window, Path.Combine(output, "scep-light.png"), 1);
            App.ApplyTheme(true, false);
            Render(window, Path.Combine(output, "scep-dark.png"), 1);
            window.FontSize = 18;
            Render(window, Path.Combine(output, "scep-text-150.png"), 1);
            window.FontSize = 12;
            App.ApplyTheme(false, false);
            ((TextBox)Field(tester, "endpoint")).Text += "/changed";
            Assert(!((Expander)Field(tester, "enrollment")).IsEnabled && ((TextBox)Field(tester, "output")).Text == "",
                "Changing the endpoint retained stale enrollment state.");
            Click(tester, "_Check Endpoint");
            stall(() =>
            {
                Click(tester, "C_ancel");
                WaitFor(() => Field(tester, "cancellation") == null);
                Assert(((TextBlock)Field(tester, "status")).Text.Contains("cancelled"),
                    "Cancel did not stop discovery.");
            });
        }

        private static byte[] EmptyCertRep(CmsSigner signer, X509Certificate2 cert, bool includeCertificate)
        {
            // Sign the attributes over empty content. A PENDING or FAILURE CertRep omits the PKI envelope.
            byte[] OidBytes(string value) => CryptoConfig.EncodeOID(value);
            byte[] Set(params byte[][] fields) => Der(0x31, fields);
            byte[] Seq(params byte[][] fields) => Der(0x30, fields);
            var dataOid = OidBytes("1.2.840.113549.1.7.1");
            var sha256 = Seq(OidBytes("2.16.840.1.101.3.4.2.1"), Der(5));
            using var hash = SHA256.Create();
            var attributes = signer.SignedAttributes.Cast<CryptographicAttributeObject>().Select(attribute =>
                Seq(OidBytes(attribute.Oid.Value), Set(attribute.Values[0].RawData))).ToList();
            attributes.Add(Seq(OidBytes("1.2.840.113549.1.9.3"), Set(dataOid)));
            attributes.Add(Seq(OidBytes("1.2.840.113549.1.9.4"), Set(Der(4, hash.ComputeHash(Array.Empty<byte>())))));
            var sorted = attributes.OrderBy(value => BitConverter.ToString(value), StringComparer.Ordinal).ToArray();
            using var key = cert.GetRSAPrivateKey();
            var signature = key.SignData(Set(sorted), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var serial = cert.GetSerialNumber().Reverse().ToArray();
            if (serial[0] >= 128) serial = new byte[] { 0 }.Concat(serial).ToArray();
            var version = Der(2, new byte[] { 1 });
            var info = Seq(version, Seq(cert.IssuerName.RawData, Der(2, serial)), sha256, Der(0xa0, sorted),
                Seq(OidBytes("1.2.840.113549.1.1.1"), Der(5)), Der(4, signature));
            var signedData = Seq(version, Set(sha256), Seq(dataOid),
                includeCertificate ? Der(0xa0, cert.RawData) : Array.Empty<byte>(), Set(info));
            return Seq(OidBytes("1.2.840.113549.1.7.2"), Der(0xa0, signedData));
        }

        private static void CheckScep(MainWindow window, string path, string output)
        {
            // Exercise HTTP and CONNECT using a real loopback proxy and a deliberately unresolvable CA hostname.
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            var original = NetworkAccess.Current;
            var target = new ScepTester("http://ca.invalid/mscep?tenant=one", "A & B");
            try
            {
                NetworkAccess.Current = NetworkAccess.Parse("http://127.0.0.1:" + port);
                var secret = "test-only-PIN";
                var standard = true;
                var legacyDigest = "SHA-512";
                var single = false;
                var disposition = "3";
                var wrongNonce = false;
                var unexpectedEnvelope = false;
                var wrongSigner = false;
                string transactionId = null;
                using var rootKey = new RSACng(2048);
                var rootRequest = new CertificateRequest("CN=SCEP Fixture Root", rootKey, HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1);
                rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
                using var root = rootRequest.CreateSelfSigned(DateTimeOffset.Now.AddDays(-3),
                    DateTimeOffset.Now.AddDays(5));
                using var otherKey = new RSACng(2048);
                var otherRequest = new CertificateRequest("CN=Separate Test CA", otherKey, HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1);
                otherRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
                using var otherCa = otherRequest.CreateSelfSigned(DateTimeOffset.Now.AddDays(-2),
                    DateTimeOffset.Now.AddDays(3));
                using var caKey = new RSACng(2048);
                var caRequest = new CertificateRequest("CN=SCEP Fixture CA", caKey, HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1);
                caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
                using var caPublic = caRequest.Create(root, DateTimeOffset.Now.AddDays(-1),
                    DateTimeOffset.Now.AddDays(2), new byte[] { 11 });
                using var ca = caPublic.CopyWithPrivateKey(caKey);
                X509Certificate2 Leaf(string name, int serial, X509KeyUsageFlags usage, string purpose)
                {
                    using var key = new RSACng(2048);
                    var request = new CertificateRequest("CN=" + name, key, HashAlgorithmName.SHA256,
                        RSASignaturePadding.Pkcs1);
                    request.CertificateExtensions.Add(new X509KeyUsageExtension(usage, true));
                    request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                        new OidCollection { new Oid(purpose) }, false));
                    using var cert = request.Create(ca, DateTimeOffset.Now.AddHours(-2), DateTimeOffset.Now.AddDays(1),
                        new byte[] { (byte)serial });
                    return cert.CopyWithPrivateKey(key);
                }
                using var ra = Leaf("SCEP Encryption", 17, X509KeyUsageFlags.KeyEncipherment, ScepTester.AgentOid);
                using var signingRa = Leaf("SCEP Signing", 18, X509KeyUsageFlags.DigitalSignature, ScepTester.AgentOid);
                using var tlsCert = Leaf("sni.invalid", 19, X509KeyUsageFlags.DigitalSignature |
                    X509KeyUsageFlags.KeyEncipherment, "1.3.6.1.5.5.7.3.1");
                var bundle = new X509Certificate2Collection(new[] { root, ca, ra, signingRa, tlsCert, otherCa })
                    .Export(X509ContentType.Pkcs7);
                const string prefix = "2.16.840.1.113733.1.9.";
                string[] headers = null;

                void Serve(Action run, Func<byte[], (byte[] Body, string Mime)> respond,
                    Action<NetworkStream> tunnel = null, X509Certificate2 https = null)
                {
                    // Consume one complete HTTP request, including its signed binary body.
                    var worker = Task.Run(() =>
                    {
                        using var socket = listener.AcceptTcpClient();
                        socket.ReceiveTimeout = socket.SendTimeout = 5000;
                        using var transport = socket.GetStream();
                        using var tls = https == null ? null : new SslStream(transport, true);
                        if (tls != null) tls.AuthenticateAsServer(https, false, SslProtocols.Tls12, false);
                        Stream stream = tls ?? (Stream)transport;
                        var header = new StringBuilder();
                        while (header.Length < 32000)
                        {
                            var next = stream.ReadByte();
                            if (next < 0) throw new EndOfStreamException();
                            header.Append((char)next);
                            if (next == 10 && header.Length >= 4 && header[header.Length - 3] == 10) break;
                        }
                        headers = header.ToString().Split(new[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries);
                        var length = headers.FirstOrDefault(line =>
                            line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase));
                        using var reader = new BinaryReader(stream, Encoding.ASCII, true);
                        var body = reader.ReadBytes(length == null ? 0 : int.Parse(length.Split(':')[1]));
                        var reply = respond(body);
                        var status = reply.Mime == null ? "407 Proxy Authentication Required" : "200 OK";
                        var response = Encoding.ASCII.GetBytes(tunnel != null && reply.Mime != null ?
                            "HTTP/1.1 200 Connection Established\r\n\r\n" :
                            $"HTTP/1.1 {status}\r\nConnection: close\r\nContent-Type: {reply.Mime}\r\n" +
                            $"Content-Length: {reply.Body.Length}\r\n\r\n");
                        stream.Write(response, 0, response.Length);
                        stream.Write(reply.Body, 0, reply.Body.Length);
                        tunnel?.Invoke(transport);
                    });
                    try { run(); }
                    finally
                    {
                        if (worker.IsCompleted || worker.Wait(5000)) worker.GetAwaiter().GetResult();
                        else throw new TimeoutException("Loopback endpoint was never contacted.");
                    }
                }

                void ServeDiscovery(X509Certificate2 https = null)
                {
                    // Both discovery operations must reach the proxy with the original tenant and CA identifier.
                    foreach (var operation in new[] { "GetCACaps", "GetCACert" })
                        Serve(() => { }, _ =>
                        {
                            var endpoint = https == null ? target.Endpoint.AbsoluteUri : target.Endpoint.PathAndQuery;
                            Assert(headers[0] == "GET " + endpoint + "&operation=" + operation +
                                "&message=A%20%26%20B HTTP/1.1", "Unexpected SCEP proxy request: " + headers[0]);
                            if (operation == "GetCACert") return single ? (ca.RawData, "application/x-x509-ca-cert") :
                                (bundle, "application/x-x509-ca-ra-cert");
                            return (Encoding.ASCII.GetBytes(standard ? "SCEPStandard\r\nAES\nSHA-256\n" :
                                "DES3\n" + legacyDigest + "\n"), "text/plain");
                        }, https: https);
                }

                void Discover()
                {
                    var check = Task.Run(() => target.Discover(default));
                    ServeDiscovery();
                    check.GetAwaiter().GetResult();
                    Assert(target.Certificates.Length == (single ? 1 : 6) && target.Summary == "Endpoint check passed.",
                        target.Report.ToString());
                }

                (byte[], string) Reply(byte[] body)
                {
                    // Unwrap an actual signed PKCSReq or CertPoll as an independent RA.
                    if (standard)
                        Assert(headers[0].StartsWith(target.Endpoint.Scheme == "https" ? "POST /mscep?" :
                            "POST http://ca.invalid/") &&
                            headers.Any(line => line.Equals("Content-Type: application/x-pki-message",
                                StringComparison.OrdinalIgnoreCase)), "Expected SCEP binary POST.");
                    else
                    {
                        Assert(headers[0].StartsWith("GET http://ca.invalid/"), "Expected SCEP legacy GET.");
                        var query = new Uri(headers[0].Split(' ')[1]).Query;
                        body = Convert.FromBase64String(Uri.UnescapeDataString(query.Substring(query.IndexOf(
                            "&message=", StringComparison.Ordinal) + 9)));
                    }
                    var signed = new SignedCms();
                    signed.Decode(body);
                    signed.CheckSignature(true);
                    var signer = signed.SignerInfos[0];
                    using var client = signer.Certificate;
                    var uses = client.Extensions.OfType<X509KeyUsageExtension>().Single().KeyUsages;
                    Assert(uses == (X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment),
                        "The client certificate needs both SCEP key usages.");
                    Assert(signer.DigestAlgorithm.Value == CryptoConfig.MapNameToOID(standard ? "SHA256" :
                        legacyDigest.Replace("-", "")), "Unexpected request signing algorithm.");
                    byte[] Attr(string id) => signer.SignedAttributes.Cast<CryptographicAttributeObject>()
                        .Single(attribute => attribute.Oid.Value == prefix + id).Values[0].RawData;
                    var id = ComparisonDer.Parse(Attr("7")).Text;
                    var type = ComparisonDer.Parse(Attr("2")).Text;
                    var envelope = new EnvelopedCms();
                    envelope.Decode(signed.ContentInfo.Content);
                    Assert(envelope.ContentEncryptionAlgorithm.Oid.Value == (standard ?
                        "2.16.840.1.101.3.4.1.2" : "1.2.840.113549.3.7"), "Unexpected content encryption.");
                    envelope.Decrypt(new X509Certificate2Collection(single ? ca : ra));
                    var content = ComparisonDer.Parse(envelope.ContentInfo.Content).Children(0x30);
                    if (type == "19")
                    {
                        transactionId = id;
                        var csr = content[0].Children(0x30);
                        using var key = client.GetRSAPublicKey();
                        Assert(key.VerifyData(content[0].Encoded, content[2].Content.Skip(1).ToArray(),
                            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1) &&
                            csr[3].Children()[0].Children()[1].Children()[0].Text == secret,
                            "The signed PKCS #10 is missing its challenge or proof of possession.");
                    }
                    else Assert(type == "20" && id == transactionId &&
                        content[0].Encoded.SequenceEqual(ca.SubjectName.RawData) &&
                        content[1].Encoded.SequenceEqual(client.SubjectName.RawData), "Invalid pending request poll.");

                    var signingCert = wrongSigner ? tlsCert : single ? ca : signingRa;
                    var cmsSigner = new CmsSigner(signingCert) { IncludeOption = single && !wrongSigner ?
                        X509IncludeOption.None : X509IncludeOption.EndCertOnly };
                    void Add(string number, byte[] value) => cmsSigner.SignedAttributes.Add(
                        new AsnEncodedData(new Oid(prefix + number), value));
                    Add("2", new byte[] { 19, 1, 51 });
                    Add("3", new byte[] { 19, 1, (byte)disposition[0] });
                    if (disposition == "2") Add("4", new byte[] { 19, 1, 50 });
                    Add("7", Attr("7"));
                    var nonce = Attr("5");
                    if (wrongNonce) nonce[2] ^= 1;
                    Add("6", nonce);
                    if (disposition != "0" && !unexpectedEnvelope)
                        return (EmptyCertRep(cmsSigner, signingCert, !single || wrongSigner),
                            "application/x-pki-message");

                    // Encrypt only a successful reply, using the public key from the client's request.
                    var issue = new CertificateRequest(client.SubjectName, client.PublicKey, HashAlgorithmName.SHA256);
                    using var leaf = issue.Create(ca.SubjectName, X509SignatureGenerator.CreateForRSA(caKey,
                        RSASignaturePadding.Pkcs1), DateTimeOffset.Now.AddMinutes(-1), DateTimeOffset.Now.AddHours(1),
                        new byte[] { 31 });
                    var issued = new X509Certificate2Collection(leaf).Export(X509ContentType.Pkcs7);
                    var encrypted = new EnvelopedCms(new ContentInfo(issued));
                    encrypted.Encrypt(new CmsRecipient(client));
                    var reply = new SignedCms(new ContentInfo(encrypted.Encode()));
                    reply.ComputeSignature(cmsSigner, true);
                    return (reply.Encode(), "application/x-pki-message");
                }

                Discover();
                Reject<ArgumentException>(() => new ScepEnrollment(target, "CN=Test", ""), "Unpinned HTTP enrollment.");
                Reject<InvalidDataException>(() => new ScepEnrollment(target, "CN=Test",
                    CertificateUtilities.Sha256(bundle)), "Accepted a bundle hash in place of the pinned CA.");
                using (var test = new ScepEnrollment(target, "CN=Test", CertificateUtilities.Sha256(root.RawData)))
                {
                    Assert(test.AuthoritySummary.Contains("CN=SCEP Encryption") &&
                        test.AuthoritySummary.Contains("Reply signer: CN=SCEP Signing") &&
                        !test.AuthoritySummary.Contains(tlsCert.Subject) &&
                        !test.AuthoritySummary.Contains(otherCa.Subject),
                        "An ordinary TLS leaf or unrelated CA became a trusted authority.");
                    string result = null;
                    wrongSigner = true;
                    Serve(() => Reject<InvalidDataException>(() => test.Exchange(secret, false, default),
                        "An advertised certificate without the enrollment-agent purpose signed a reply."), Reply);
                    wrongSigner = false;
                    Serve(() => result = test.Exchange(secret, false, default), Reply);
                    Assert(test.CanPoll && result.StartsWith("Pending"), result);
                    unexpectedEnvelope = true;
                    Serve(() => result = test.Exchange(null, true, default), Reply);
                    Assert(test.CanPoll && test.IssuedCertificate == null && result.Contains("ignored"),
                        "Extra signed content in a pending reply was treated as an issued certificate.");
                    unexpectedEnvelope = false;
                    disposition = "0";
                    wrongNonce = true;
                    Serve(() => Reject<InvalidDataException>(() => test.Exchange(null, true, default),
                        "Accepted a CertRep with an unrelated nonce."), Reply);
                    wrongNonce = false;
                    Serve(() => result = test.Exchange(null, true, default), Reply);
                    using var issued = new X509Certificate2(test.IssuedCertificate);
                    Assert(!test.CanPoll && result.StartsWith("Issued: CN=Test") &&
                        issued.Subject == "CN=Test", result);
                }
                single = true;
                standard = false;
                target = new ScepTester(target.Endpoint.AbsoluteUri, "A & B");
                Discover();
                disposition = "2";
                using (var test = new ScepEnrollment(target, "CN=Test", CertificateUtilities.Sha256(ca.RawData)))
                {
                    wrongSigner = true;
                    Serve(() => Reject<InvalidDataException>(() => test.Exchange(secret, false, default),
                        "An unadvertised signer was accepted."), Reply);
                    wrongSigner = false;
                    Serve(() => Assert(test.Exchange(null, true, default).Contains("bad request") && !test.CanPoll,
                        "Missing CA rejection."), Reply);
                }

                legacyDigest = "SHA-1";
                Discover();
                using (var test = new ScepEnrollment(target, "CN=Test", ca.Thumbprint))
                    Serve(() => Assert(test.Exchange(secret, false, default).Contains("Rejected"),
                        "Missing rejection."), Reply);

                Console.WriteLine("Signed SCEP enrollment, CA pinning, polling and rejection passed.");

                // An HTTP 200 sign-in page is not a working SCEP endpoint.
                var invalid = new ScepTester("http://ca.invalid/login", "");
                var failed = Task.Run(() => invalid.Discover(default));
                for (var i = 0; i < 2; i++)
                    Serve(() => { }, _ => (Encoding.ASCII.GetBytes("<html>Sign in</html>"), "text/html"));
                failed.GetAwaiter().GetResult();
                Assert(invalid.Certificates.Length == 0 && invalid.Report.ToString().Contains("GetCACaps failed") &&
                    invalid.Report.ToString().Contains("GetCACert failed"), "A sign-in page passed discovery.");

                // Exercise both CRL call paths and ensure a proxy refusal cannot fall through to direct TLS.
                const string remoteCrl = "http://crl.invalid/base.crl";
                Serve(() => Assert(CertificateValidation.RetrieveCrls(remoteCrl, false, 3)
                    .Single().SequenceEqual(fixtures["oldBase"]), "Proxied CRL changed."), _ =>
                {
                    Assert(headers[0] == "GET " + remoteCrl + " HTTP/1.1", "Unexpected proxy target: " + headers[0]);
                    return (fixtures["oldBase"], "application/pkix-crl");
                });
                Reject<Win32Exception>(() => CertificateValidation.RetrieveCrls(
                    "http://ca.invalid/" + Guid.NewGuid() + ".crl", true, 1), "An uncached offline CRL was retrieved.");
                Assert(!listener.Pending(), "An offline lookup contacted the proxy.");
                Serve(() =>
                {
                    var tls = CertificateUtilities.Probe("ca.invalid", 636, "sni.invalid", false, 5, "", default,
                        OidNames.Windows).GetAwaiter().GetResult();
                    Assert(!tls.HandshakeCompleted && tls.Report.ToString().Contains("HTTP 407"),
                        tls.Report.ToString());
                }, _ =>
                {
                    Assert(headers[0] == "CONNECT ca.invalid:636 HTTP/1.1", "CONNECT used the wrong target.");
                    return (Array.Empty<byte>(), null);
                });
                void TlsServer(NetworkStream stream)
                {
                    // Schannel requires a key container for its server credential on .NET Framework.
                    using var credential = new X509Certificate2(tlsCert.Export(X509ContentType.Pfx));
                    using var ssl = new SslStream(stream, true);
                    try { ssl.AuthenticateAsServer(credential, false, SslProtocols.Tls12, false); }
                    catch (AuthenticationException) { }
                    catch (IOException) { }
                }
                Serve(() =>
                {
                    var tls = CertificateUtilities.Probe("ca.invalid", 443, "sni.invalid", false, 5, "", default,
                        OidNames.Windows).GetAwaiter().GetResult();
                    Assert(!tls.HandshakeCompleted && tls.Certificate != null &&
                        tls.Certificate.SequenceEqual(tlsCert.RawData) && tls.PolicyErrors ==
                        SslPolicyErrors.RemoteCertificateChainErrors,
                        "Tunnelling lost the expected TLS name or accepted an untrusted CA. " + tls.Report);
                }, _ => (Array.Empty<byte>(), ""), TlsServer);
                Serve(() => Reject<WebException>(() => NetworkAccess.Current.Fetch(
                    new Uri("https://sni.invalid/mscep"), 5, 4096, default), "HTTPS accepted an untrusted CA."), _ =>
                {
                    Assert(headers[0].StartsWith("CONNECT sni.invalid:443 HTTP/1."), "HTTPS bypassed the proxy.");
                    return (Array.Empty<byte>(), "");
                }, TlsServer);
                Console.WriteLine("Manual HTTP proxy and TLS tunnel checks passed.");

                // A manual proxy must leave loopback destinations on this computer.
                NetworkAccess.Current = NetworkAccess.Parse("http://127.0.0.1:1");
                foreach (var policy in new[] { NetworkAccess.Current, NetworkAccess.Parse(NetworkAccess.Direct),
                    NetworkAccess.Parse(NetworkAccess.SystemProxy) })
                {
                    NetworkAccess.Current = policy;
                    var url = $"http://127.0.0.1:{port}/{Guid.NewGuid():N}.crl";
                    Serve(() => Assert(CertificateValidation.RetrieveCrls(url, false, 3).Single()
                        .SequenceEqual(fixtures["oldBase"]), "Missing local CRL."), _ =>
                    {
                        Assert(headers[0].StartsWith("GET /"), "A loopback CRL used proxy form.");
                        return (fixtures["oldBase"], "application/pkix-crl");
                    });
                    var handshake = Task.Run(() =>
                    {
                        using var peer = listener.AcceptTcpClient();
                        TlsServer(peer.GetStream());
                    });
                    var local = CertificateUtilities.Probe("127.0.0.1", port, "sni.invalid", false, 5, "", default,
                        OidNames.Windows).GetAwaiter().GetResult();
                    Assert(handshake.Wait(5000) && local.Certificate?.SequenceEqual(tlsCert.RawData) == true &&
                        local.Report.ToString().Contains("Route: Direct connection (loopback)"),
                        local.Report.ToString());
                }

                // Trust only this fixture in the test process for a successful HTTPS discovery and enrollment.
                var certificateCheck = ServicePointManager.ServerCertificateValidationCallback;
                try
                {
                    using var credential = new X509Certificate2(tlsCert.Export(X509ContentType.Pfx));
                    ServicePointManager.ServerCertificateValidationCallback = (sender, cert, chain, errors) =>
                        sender is HttpWebRequest request && request.RequestUri.IsLoopback &&
                        request.RequestUri.Port == port && cert.GetRawCertData().SequenceEqual(tlsCert.RawData);
                    target = new ScepTester($"https://127.0.0.1:{port}/mscep?tenant=one", "A & B");
                    single = false;
                    standard = true;
                    disposition = "0";
                    var check = Task.Run(() => target.Discover(default));
                    ServeDiscovery(credential);
                    check.GetAwaiter().GetResult();
                    using var test = new ScepEnrollment(target, "CN=HTTPS", "");
                    Serve(() => Assert(test.Exchange(secret, false, default).StartsWith("Issued: CN=HTTPS"),
                        "HTTPS enrollment failed."), Reply, https: credential);
                }
                finally { ServicePointManager.ServerCertificateValidationCallback = certificateCheck; }

                // Interrupt a stalled response both before headers and midway through a declared response body.
                void Stall(Action act)
                {
                    WaitFor(listener.Pending);
                    using var peer = listener.AcceptTcpClient();
                    act();
                }
                NetworkAccess.Current = NetworkAccess.Parse(NetworkAccess.Direct);
                var timeout = Task.Run(() => Reject<TimeoutException>(() => NetworkAccess.Current.Fetch(
                    new Uri($"http://127.0.0.1:{port}/slow"), 1, 4096, default), "HTTP deadline was ignored."));
                Stall(() => Assert(timeout.Wait(5000), "The HTTP deadline left the request blocked."));
                using (var stop = new CancellationTokenSource())
                {
                    var download = Task.Run(() => Reject<OperationCanceledException>(() => NetworkAccess.Current.Fetch(
                        new Uri($"http://127.0.0.1:{port}/body"), 30, 4096, stop.Token), "Download ignored Cancel."));
                    WaitFor(listener.Pending);
                    using var peer = listener.AcceptTcpClient();
                    using var stream = peer.GetStream();
                    using var reader = new StreamReader(stream, Encoding.ASCII, false, 1024, true);
                    while (!string.IsNullOrEmpty(reader.ReadLine())) { }
                    var partial = Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n1");
                    stream.Write(partial, 0, partial.Length);
                    stop.CancelAfter(150);
                    Assert(download.Wait(4000), "Cancellation left a partially read response blocked.");
                }

                NetworkAccess.Current = original;
                target = new ScepTester("http://ca.invalid/mscep?tenant=one", "A & B");
                CheckNetworkViews(window, path, output, $"http://127.0.0.1:{port}", target.Endpoint.AbsoluteUri,
                    CertificateUtilities.Sha256(root.RawData), () => ServeDiscovery(), run => Serve(run, Reply), Stall);
            }
            finally { NetworkAccess.Current = original; listener.Stop(); }
            Console.WriteLine("SCEP discovery, enrollment, polling and rejection passed through the loopback proxy.");
        }
    }
}
