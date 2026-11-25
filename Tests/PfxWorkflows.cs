//
// Copyright (c) Bryan Berns.
// Licensed under GPLv3. See LICENSE.md.
//

using System;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Controls;

namespace Certitude
{
    internal static partial class WorkflowChecks
    {
        private static void CheckPfxExport(MainWindow window, CertificateToolsWindow manager, string output)
        {
            // Bundle two distinct keys with the same subject and an unrelated public-only certificate.
            using var rsa = new RSACng(2048);
            using var ec = new ECDsaCng(384);
            var now = DateTimeOffset.UtcNow;
            using var rsaCert = new CertificateRequest("CN=PFX Test", rsa, HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1).CreateSelfSigned(now.AddDays(-1), now.AddDays(1));
            using var ecCert = new CertificateRequest("CN=PFX Test", ec, HashAlgorithmName.SHA256)
                .CreateSelfSigned(now.AddDays(-1), now.AddDays(2));
            using var publicCert = new X509Certificate2(fixtures["ca"]);
            var bundle = new X509Certificate2Collection { ecCert, publicCert, rsaCert };
            const string password = "PFX fixture Ω";
            var input = Path.Combine(output, Guid.NewGuid().ToString("N") + ".p12");
            var destination = Path.ChangeExtension(input, ".key");
            var copy = Path.ChangeExtension(input, ".pfx");
            var original = bundle.Export(X509ContentType.Pfx, password);
            var grid = (DataGrid)Field(manager, "inventory");

            void Open(string enteredPassword)
            {
                var operation = (Task)Call(manager, "OpenFile", false);
                var picker = (FilePicker)window.ActivePage;
                picker.FileName = input;
                picker.DialogResult = true;
                WaitFor(() => window.ActivePage.Title == "Open PFX");
                Children(window.ActivePage).OfType<PasswordBox>().First().Password = enteredPassword;
                Click(window.ActivePage, "_Continue");
                Complete(operation);
            }

            Task Save(CertificateExportFormat format, string path, bool accept = true)
            {
                var operation = (Task)Call(manager, "Export");
                WaitFor(() => window.ActivePage is FilePicker);
                var picker = (FilePicker)window.ActivePage;
                Assert(picker.Filter.Split('|').Length / 2 >= (int)format, "The expected export format is missing.");
                picker.FilterIndex = (int)format;
                picker.FileName = path;
                picker.DialogResult = accept;
                return operation;
            }

            try
            {
                // A bad password leaves the inventory intact, and opening the PFX unlocks both keys in one prompt.
                File.WriteAllBytes(input, original);
                var previous = grid.ItemsSource;
                Open("wrong password");
                Assert(ReferenceEquals(grid.ItemsSource, previous), "A failed PFX open replaced the inventory.");
                Open(password);
                Assert(grid.Items.Count == 3, "The PFX inventory lost a certificate.");
                foreach (var (certificate, key) in new[] { (rsaCert, rsa.Key), (ecCert, ec.Key) })
                {
                    grid.SelectedItem = grid.Items.Cast<InventoryCertificate>()
                        .Single(row => row.Thumbprint == certificate.Thumbprint);
                    foreach (var format in new[] { CertificateExportFormat.Pkcs8Pem, CertificateExportFormat.Pkcs8Der,
                        CertificateExportFormat.TraditionalPem, CertificateExportFormat.TraditionalDer })
                    {
                        Complete(Save(format, destination));
                        var bytes = File.ReadAllBytes(destination);
                        var traditional = format is CertificateExportFormat.TraditionalPem or
                            CertificateExportFormat.TraditionalDer;
                        if (format is CertificateExportFormat.Pkcs8Pem or CertificateExportFormat.TraditionalPem)
                        {
                            var label = !traditional ? "PRIVATE KEY" :
                                certificate == rsaCert ? "RSA PRIVATE KEY" : "EC PRIVATE KEY";
                            var lines = Encoding.ASCII.GetString(bytes).TrimEnd().Split(new[] { "\r\n" },
                                StringSplitOptions.None);
                            Assert(lines.First() == "-----BEGIN " + label + "-----" &&
                                lines.Last() == "-----END " + label + "-----" &&
                                lines.Skip(1).Take(lines.Length - 3).All(line => line.Length == 64),
                                "The private-key PEM armor or wrapping is incorrect.");
                            bytes = Convert.FromBase64String(string.Concat(lines.Skip(1).Take(lines.Length - 2)));
                        }

                        // Verify the standalone RSA/EC structure or import the PKCS #8 and match its public key.
                        if (traditional)
                        {
                            var expected = ComparisonDer.Parse(key.Export(CngKeyBlobFormat.Pkcs8PrivateBlob))
                                .Children(0x30)[2].Content;
                            Assert(bytes.SequenceEqual(expected), "The traditional key differs from the selected key.");
                            if (certificate == ecCert)
                                Assert(ComparisonDer.Parse(bytes).Children(0x30).Any(field => field.Tag == 0xa0),
                                    "The standalone EC key lacks curve parameters.");
                        }
                        else
                        {
                            using var restored = CngKey.Import(bytes, CngKeyBlobFormat.Pkcs8PrivateBlob);
                            Assert(restored.Export(CngKeyBlobFormat.GenericPublicBlob)
                                .SequenceEqual(key.Export(CngKeyBlobFormat.GenericPublicBlob)),
                                "The exported PKCS #8 does not match the selected certificate.");
                        }
                    }

                    // Repackage this identity under a new password and sign with its restored private key.
                    var protect = Save(CertificateExportFormat.Pfx, copy);
                    WaitFor(() => window.ActivePage.Title == "Protect The Exported PFX");
                    foreach (var box in Children(window.ActivePage).OfType<PasswordBox>())
                        box.Password = "new password";
                    Click(window.ActivePage, "_Continue");
                    Complete(protect);
                    var repackaged = new X509Certificate2Collection();
                    try
                    {
                        repackaged.Import(copy, "new password", X509KeyStorageFlags.EphemeralKeySet);
                        Assert(repackaged.Count == 1 && repackaged[0].HasPrivateKey &&
                            repackaged[0].RawData.SequenceEqual(certificate.RawData),
                            "The exported PFX contains the wrong identity.");
                        CertificateUtilities.TestPrivateKey(repackaged[0]);
                    }
                    finally { foreach (var member in repackaged) member.Dispose(); }
                }

                // Check source protection and cancellation before writing an unencrypted key.
                Complete(Save(CertificateExportFormat.Pkcs8Pem, input));
                Assert(File.ReadAllBytes(input).SequenceEqual(original), "An export overwrote its source PFX.");
                File.WriteAllText(destination, "existing");
                Complete(Save(CertificateExportFormat.Pkcs8Pem, destination, false));
                Assert(File.ReadAllText(destination) == "existing", "Cancelling key export replaced its destination.");

                // Replacing a readable file must publish the key with the same private ACL as a new export.
                var acl = File.GetAccessControl(destination);
                acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null),
                    FileSystemRights.Read, AccessControlType.Allow));
                File.SetAccessControl(destination, acl);
                var existingAcl = File.GetAccessControl(destination)
                    .GetSecurityDescriptorSddlForm(AccessControlSections.Access);
                using (File.Open(destination, FileMode.Open, FileAccess.Read, FileShare.Read))
                    Complete(Save(CertificateExportFormat.Pkcs8Pem, destination));
                Assert(File.ReadAllText(destination) == "existing" && File.GetAccessControl(destination)
                    .GetSecurityDescriptorSddlForm(AccessControlSections.Access) == existingAcl,
                    "A failed private-key export changed the destination or its permissions.");
                Complete(Save(CertificateExportFormat.Pkcs8Pem, destination));
                using var identity = WindowsIdentity.GetCurrent();
                acl = File.GetAccessControl(destination);
                var rules = acl.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>();
                Assert(acl.AreAccessRulesProtected && rules.Single().IdentityReference.Equals(identity.User),
                    "Private-key replacement retained other readers.");

                // Public-only rows and mixed selections expose only certificate formats.
                grid.SelectedItem = grid.Items.Cast<InventoryCertificate>().Single(row => !row.HasPrivateKey);
                foreach (var multiple in new[] { false, true })
                {
                    if (multiple) grid.SelectAll();
                    var operation = (Task)Call(manager, "Export");
                    WaitFor(() => window.ActivePage is FilePicker);
                    var picker = (FilePicker)window.ActivePage;
                    Assert(picker.Filter.Split('|').Length == 6, "A public or mixed selection offered private keys.");
                    picker.DialogResult = false;
                    Complete(operation);
                }
            }
            finally { File.Delete(destination); File.Delete(copy); File.Delete(input); }
        }
    }
}
