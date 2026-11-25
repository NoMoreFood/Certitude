//
// Copyright (c) Bryan Berns.
// Licensed under GPLv3. See LICENSE.md.
//

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;

namespace Certitude
{
    internal enum CertificateExportFormat
    {
        Der = 1, Pem, Pkcs7, Pfx, Pkcs8Pem, Pkcs8Der, TraditionalPem, TraditionalDer
    }

    internal sealed class CertificateFile : IDisposable
    {
        private readonly X509Certificate2Collection certificates = new();
        public List<InventoryCertificate> Rows { get; }
        public string PfxPath { get; }

        public CertificateFile(byte[] encoded, string password, CancellationToken token, OidNames names,
            string pfxPath = null)
        {
            // Keep exportable handles only for an opened PFX. Import previews use ephemeral, non-exportable keys.
            PfxPath = pfxPath;
            token.ThrowIfCancellationRequested();
            try
            {
                var flags = X509KeyStorageFlags.EphemeralKeySet;
                if (pfxPath != null) flags |= X509KeyStorageFlags.Exportable;
                certificates.Import(encoded, password, flags);
                Rows = CertificateUtilities.DescribeAll(certificates, token, names);
            }
            catch { Dispose(); throw; }
        }

        public void Dispose()
        {
            foreach (var certificate in certificates) certificate.Dispose();
            certificates.Clear();
        }

        public X509Certificate2 KeyCertificate(InventoryCertificate row) =>
            PfxPath != null && row?.HasPrivateKey == true ? certificates.Cast<X509Certificate2>()
                .FirstOrDefault(cert => cert.HasPrivateKey && cert.RawData.SequenceEqual(row.Encoded)) : null;

        public static string TraditionalFormat(X509Certificate2 certificate)
        {
            // Offer formats only for key types the framework can open, including the certificate's usage restrictions.
            using var rsa = certificate?.GetRSAPrivateKey();
            if (rsa is RSACng) return "PKCS #1 RSA";
            using var ec = certificate?.GetECDsaPrivateKey();
            return ec is ECDsaCng ? "SEC1 EC" : null;
        }

        public static void WritePrivateKey(X509Certificate2 certificate, CertificateExportFormat format,
            string path, CancellationToken token)
        {
            // Windows imports ephemeral PFX keys through CNG with encrypted export permission.
            token.ThrowIfCancellationRequested();
            using var rsa = certificate.GetRSAPrivateKey();
            using var ec = certificate.GetECDsaPrivateKey();
            var key = (rsa as RSACng)?.Key ?? (ec as ECDsaCng)?.Key;
            if (key == null || !key.IsEphemeral || (key.ExportPolicy & CngExportPolicies.AllowExport) == 0)
                throw new NotSupportedException("Select an exportable RSA or ECDSA key from an open PFX.");
            key.SetProperty(new CngProperty("Export Policy", BitConverter.GetBytes((int)(key.ExportPolicy |
                CngExportPolicies.AllowPlaintextExport)), CngPropertyOptions.None));

            // CNG includes the RSA or EC private key structure inside the PKCS #8 privateKey OCTET STRING.
            var pkcs8 = key.Export(CngKeyBlobFormat.Pkcs8PrivateBlob);
            byte[] traditional = null, pem = null;
            try
            {
                var label = "PRIVATE KEY";
                if (format is CertificateExportFormat.TraditionalPem or CertificateExportFormat.TraditionalDer)
                {
                    traditional = ComparisonDer.Parse(pkcs8).Children(0x30)[2].Content;
                    label = rsa != null ? "RSA PRIVATE KEY" : "EC PRIVATE KEY";
                }
                if (format is CertificateExportFormat.Pkcs8Pem or CertificateExportFormat.TraditionalPem)
                    pem = EncodePem(label, traditional ?? pkcs8);
                token.ThrowIfCancellationRequested();
                CertificateUtilities.WriteAtomic(path, pem ?? traditional ?? pkcs8, privateKey: true);
            }
            finally
            {
                Array.Clear(pkcs8, 0, pkcs8.Length);
                if (traditional != null) Array.Clear(traditional, 0, traditional.Length);
                if (pem != null) Array.Clear(pem, 0, pem.Length);
            }
        }

        private static byte[] EncodePem(string label, byte[] der)
        {
            // Encode 48 bytes per 64-character PEM line without creating immutable strings of private key material.
            var header = Encoding.ASCII.GetBytes("-----BEGIN " + label + "-----\r\n");
            var footer = Encoding.ASCII.GetBytes("-----END " + label + "-----\r\n");
            var result = new byte[header.Length + 4 * ((der.Length + 2) / 3) + 2 * ((der.Length + 47) / 48) +
                footer.Length];
            header.CopyTo(result, 0);
            var position = header.Length;
            var line = new char[64];
            try
            {
                for (var offset = 0; offset < der.Length; offset += 48)
                {
                    var count = Convert.ToBase64CharArray(der, offset, Math.Min(48, der.Length - offset), line, 0);
                    position += Encoding.ASCII.GetBytes(line, 0, count, result, position);
                    result[position++] = (byte)'\r';
                    result[position++] = (byte)'\n';
                }
                footer.CopyTo(result, position);
                return result;
            }
            finally { Array.Clear(line, 0, line.Length); }
        }
    }
}
