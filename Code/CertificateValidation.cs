//
// Copyright (c) Bryan Berns.
// Licensed under GPLv3. See LICENSE.md.
//

using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;

namespace Certitude
{
    internal sealed class CrlResult
    {
        public string Source { get; set; }
        public byte[] Encoded { get; set; }
        public TimeReport Details { get; set; }
        public bool? SignatureValid { get; set; }
        public bool ScopeMatches { get; set; }
        public bool IssuerMatches { get; set; }
        public bool Current { get; set; }
        public bool Listed { get; set; }
        public bool IsDelta { get; set; }
        public string Issuer { get; set; }
        public DateTime? ThisUpdate { get; set; }
        public DateTime? NextUpdate { get; set; }
        public int EntryCount { get; set; }
        public string Number { get; set; }
        public override string ToString() => (IsDelta ? "Delta · " : "Base · ") + Source;
    }

    internal sealed class ValidationResult
    {
        public string Summary { get; set; }
        public TimeReport Report { get; set; }
        public string Revocation { get; set; }
        public X509ChainStatusFlags ChainErrors { get; set; }
        public List<CrlResult> Crls { get; } = new List<CrlResult>();
    }

    internal static class CertificateValidation
    {
        public static byte[] ReadCertificate(string path)
        {
            // Require one public certificate before returning normalized DER bytes.
            var bytes = Convert.FromBase64String(CaAdministration.ReadBase64(path));
            if (X509Certificate2.GetCertContentType(bytes) != X509ContentType.Cert)
                throw new ArgumentException("Select a single public certificate in DER or PEM format.");
            using (var certificate = new X509Certificate2(bytes)) return certificate.RawData;
        }

        public static ValidationResult Validate(byte[] encoded, string[] issuers, string[] crls, bool offline,
            bool retrieve, bool entireChain, int timeoutSeconds, CancellationToken token, IProgress<string> progress,
            OidNames names = null)
        {
            // Validate retrieval limits and choose OID resolution appropriate to the network mode.
            if (timeoutSeconds is < 1 or > 120)
                throw new ArgumentException("Set the retrieval timeout to 1–120 seconds.");
            token.ThrowIfCancellationRequested();
            names = offline ? names ?? OidNames.Windows : names?.Refresh() ?? OidNames.Local;
            token.ThrowIfCancellationRequested();

            // Create an isolated store for supplied issuers and CRLs used by this validation.
            var result = new ValidationResult();
            var extra = new X509Certificate2Collection();
            var inputs = new List<KeyValuePair<string, byte[]>>();
            var notes = new StringBuilder();
            using (var certificate = new X509Certificate2(encoded))
            using (var store = CertOpenStore(new IntPtr(2), 0, IntPtr.Zero, 0, IntPtr.Zero))
            {
                if (store.IsInvalid) throw NativeError();
                try
                {
                    // Load only public issuer certificates or chains into the validation context.
                    foreach (var path in issuers)
                    {
                        token.ThrowIfCancellationRequested();
                        var bytes = Convert.FromBase64String(CaAdministration.ReadBase64(path, token: token));
                        var kind = X509Certificate2.GetCertContentType(bytes);
                        if (kind is not (X509ContentType.Cert or X509ContentType.Pkcs7))
                            throw new ArgumentException("Issuer files must contain public certificates or a PKCS #7 chain.");
                        extra.Import(bytes);
                    }
                    // Populate the temporary Windows store with supplied issuers and CRLs.
                    foreach (var issuer in extra)
                        if (!CertAddCertificateContextToStore(store, issuer.Handle, 4, IntPtr.Zero)) throw NativeError();
                    foreach (var path in crls)
                    {
                        token.ThrowIfCancellationRequested();
                        AddCrl(store, inputs, path, Convert.FromBase64String(CaAdministration.ReadBase64(path, 100, token)));
                    }

                    // Collect the certificate distribution points for reporting and optional retrieval.
                    var urls = new Queue<string>(Urls(certificate.Handle, 2).Concat(Urls(certificate.Handle, 6)));
                    notes.AppendLine("Certificate CRL distribution points:");
                    foreach (var url in urls) notes.AppendLine("  " + url);
                    if (urls.Count == 0) notes.AppendLine("  No URL distribution points in this certificate.");
                    var seen = new HashSet<string>(StringComparer.Ordinal);
                    if (retrieve)
                    {
                        // Follow base and delta CRL locations while avoiding duplicate URL requests.
                        for (var i = 0; i < inputs.Count; i++)
                            foreach (var url in DeltaUrls(certificate.Handle, inputs[i].Value)) urls.Enqueue(url);
                        while (urls.Count > 0)
                        {
                            token.ThrowIfCancellationRequested();
                            var url = urls.Dequeue();
                            if (!seen.Add(url)) continue;
                            progress?.Report((offline ? "Reading cached CRL: " : "Retrieving CRL: ") + url);
                            try
                            {
                                // Retain each retrieved CRL and discover any further delta locations it advertises.
                                foreach (var bytes in RetrieveCrls(url, offline, timeoutSeconds))
                                {
                                    AddCrl(store, inputs, url, bytes);
                                    foreach (var delta in DeltaUrls(certificate.Handle, bytes)) urls.Enqueue(delta);
                                }
                            }
                            catch (Exception error) { notes.AppendLine(url + "\r\n  " + CaAdministration.Error(error)); }
                        }
                    }
                    // Build the Windows chain using the configured network policy and supplied material.
                    token.ThrowIfCancellationRequested();
                    progress?.Report("Checking the certificate chain and revocation status…");
                    using (var native = BuildChain(certificate, store, offline, timeoutSeconds))
                    using (var chain = new X509Chain(native.DangerousGetHandle()))
                    {
                        // Capture chain errors and identify the certificate and validation settings.
                        token.ThrowIfCancellationRequested();
                        result.ChainErrors = chain.ChainStatus.Aggregate(X509ChainStatusFlags.NoError,
                            (flags, status) => flags | status.Status);
                        var text = new TimeReport();
                        text.AppendLine("Certificate: " + certificate.Subject);
                        text.AppendLine("Issuer: " + certificate.Issuer);
                        text.AppendLine("Serial: " + certificate.SerialNumber);
                        text.AppendLine("SHA-256: " + Hash(certificate.RawData));
                        text.Append("Checked: ").AppendTime(DateTime.UtcNow).AppendLine();
                        text.AppendLine("OID Resolution: " + names.Status);
                        text.AppendLine("Mode: " + (offline ? "Offline / local files and Windows cache" : "Online"));
                        text.AppendLine("Revocation scope: " +
                            (entireChain ? "Chain, excluding the root" : "Selected certificate"));
                        text.AppendLine();

                        // Require a returned chain and explain the limits of revocation evidence.
                        var context = Read<ChainArray>(native.DangerousGetHandle());
                        if (context.Count == 0) throw new InvalidOperationException("Windows returned an empty chain.");
                        result.Revocation = "Not checked";
                        text.AppendLine("Windows uses its trust stores, supplied certificates/CRLs and cache; " +
                            "online mode may use OCSP.");
                        text.AppendLine("A missing, expired or inaccessible CRL is not proof " +
                            "that a certificate is not revoked.");
                        text.AppendLine();

                        // Inspect supplied and retrieved CRLs against available issuer certificates.
                        var candidates = extra.Cast<X509Certificate2>().Concat(
                            chain.ChainElements.Cast<X509ChainElement>().Select(element => element.Certificate)).ToArray();
                        foreach (var input in inputs)
                        {
                            token.ThrowIfCancellationRequested();
                            result.Crls.Add(InspectCrl(input.Value, input.Key, certificate, candidates, names));
                        }
                        // Walk every returned chain and report each element trust status.
                        text.AppendLine("WINDOWS CHAIN RESULTS");
                        for (var chainIndex = 0; chainIndex < context.Count; chainIndex++)
                        {
                            var simple = Read<ChainArray>(Marshal.ReadIntPtr(context.Items, chainIndex * IntPtr.Size));
                            for (var i = 0; i < simple.Count; i++)
                            {
                                token.ThrowIfCancellationRequested();
                                var element = Read<ChainElement>(Marshal.ReadIntPtr(simple.Items, i * IntPtr.Size));
                                using (var item = new X509Certificate2(element.Certificate))
                                    text.AppendLine(item.Subject + "\r\n  " + (X509ChainStatusFlags)element.Trust.Errors);

                                // Limit revocation checks to the requested scope, excluding a chain root.
                                var selected = chainIndex == 0 && i == 0;
                                var root = i == simple.Count - 1 && (element.Trust.Information & 8) != 0;
                                if ((!entireChain && !selected) || (entireChain && root))
                                {
                                    text.AppendLine("  Revocation: not checked (outside the selected scope).");
                                    continue;
                                }
                                // Check revocation with the next chain element as the candidate issuer.
                                var issuer = i + 1 < simple.Count ? Read<ChainElement>(
                                    Marshal.ReadIntPtr(simple.Items, (i + 1) * IntPtr.Size)).Certificate : IntPtr.Zero;
                                var check = CheckRevocation(element.Certificate, issuer,
                                    store, offline, timeoutSeconds);
                                if (selected) result.Revocation = check.State;
                                result.ChainErrors |= check.Errors;
                                text.AppendLine("  Revocation: " + check.State +
                                    $" (0x{check.Code:X8}; reason {check.Reason})");
                                if (check.Code != 0) text.AppendLine("  " + new Win32Exception((int)check.Code).Message);
                                if (check.Crls.Count == 0)
                                    text.AppendLine("  No CRL context returned (Windows may have used OCSP).");

                                // Include CRLs actually used by Windows without duplicating earlier inspections.
                                foreach (var bytes in check.Crls)
                                {
                                    text.AppendLine("  CRL used by Windows: SHA-256 " + Hash(bytes));
                                    if (selected && !result.Crls.Any(crl => crl.Encoded.SequenceEqual(bytes)))
                                        result.Crls.Add(InspectCrl(bytes, "Windows revocation provider",
                                            certificate, candidates, names));
                                }
                            }
                        }
                        // Combine the trust summary, retrieval notes, and individual CRL findings.
                        result.Summary = "Revocation: " + result.Revocation + ". Chain: " +
                            (result.ChainErrors == 0 ? "valid" : result.ChainErrors.ToString()) + ".";
                        text.AppendLine();
                        text.AppendLine(notes.ToString());
                        foreach (var crl in result.Crls) text.AppendLine(crl.Details);
                        text.AppendLine("CRL entry checks describe individual lists. Windows determines " +
                            "the combined base/delta revocation result and chain trust.");
                        text.AppendLine("No entry in one CRL alone does not establish validity.");
                        result.Report = new TimeReport(result.Summary + "\r\n\r\n").Append(text);
                    }
                    return result;
                }
                finally { foreach (var issuer in extra) issuer.Dispose(); }
            }
        }

        private sealed class RevocationCheck
        {
            public string State;
            public uint Code, Reason;
            public X509ChainStatusFlags Errors;
            public readonly List<byte[]> Crls = new List<byte[]>();
        }

        private static RevocationCheck CheckRevocation(IntPtr certificate, IntPtr issuer, SafeStore store,
            bool offline, int timeoutSeconds)
        {
            // Prepare native store and CRL-result buffers for the revocation provider.
            using (var stores = new NativeBuffer(IntPtr.Size))
            using (var crlInfo = new NativeBuffer(Marshal.SizeOf<RevocationCrlInfo>()))
            {
                Marshal.WriteIntPtr(stores.Pointer, store.DangerousGetHandle());
                Marshal.StructureToPtr(new RevocationCrlInfo { Size = Marshal.SizeOf<RevocationCrlInfo>() },
                    crlInfo.Pointer, false);
                var options = new RevocationParameters
                {
                    Size = Marshal.SizeOf<RevocationParameters>(), Issuer = issuer, StoreCount = 1,
                    Stores = stores.Pointer, CrlStore = store.DangerousGetHandle(), Timeout = timeoutSeconds * 1000,
                    CrlInfo = crlInfo.Pointer
                };
                var status = new RevocationStatus { Size = Marshal.SizeOf<RevocationStatus>() };
                try
                {
                    // Translate the provider outcome into revoked, not revoked, or unknown status.
                    var success = CertVerifyRevocation(0x10001, 1, 1, new[] { certificate }, offline ? 6 : 4,
                        ref options, ref status);
                    var result = new RevocationCheck { Code = status.Error, Reason = status.Reason };
                    if (!success && result.Code == 0) result.Code = unchecked((uint)Marshal.GetLastWin32Error());
                    result.State = success ? "Not revoked" :
                        result.Code == 0x80092010 ? "Revoked" : "Unknown / unavailable";
                    if (!success) result.Errors = result.Code == 0x80092010 ? X509ChainStatusFlags.Revoked :
                        X509ChainStatusFlags.RevocationStatusUnknown;
                    if (result.Code == 0x80092013) result.Errors |= X509ChainStatusFlags.OfflineRevocation;

                    // Copy returned base and delta CRLs before releasing their native contexts.
                    var info = Read<RevocationCrlInfo>(crlInfo.Pointer);
                    foreach (var pointer in new[] { info.BaseCrl, info.DeltaCrl })
                        if (pointer != IntPtr.Zero) result.Crls.Add(Encoded(pointer));
                    return result;
                }
                finally
                {
                    // Release every CRL context supplied by the revocation provider.
                    var info = Read<RevocationCrlInfo>(crlInfo.Pointer);
                    if (info.BaseCrl != IntPtr.Zero) CertFreeCRLContext(info.BaseCrl);
                    if (info.DeltaCrl != IntPtr.Zero) CertFreeCRLContext(info.DeltaCrl);
                }
            }
        }

        private static SafeChain BuildChain(X509Certificate2 certificate, SafeStore store,
            bool offline, int timeoutSeconds)
        {
            var options = new ChainParameters { Size = Marshal.SizeOf<ChainParameters>(), Timeout = timeoutSeconds * 1000 };

            // Revocation is checked separately with hCrlStore; chain building ignores CRLs in hAdditionalStore.
            var flags = offline ? 0x104u : 0x100u;
            if (!CertGetCertificateChain(IntPtr.Zero, certificate.Handle, IntPtr.Zero, store, ref options,
                flags, IntPtr.Zero, out var chain))
            {
                var error = NativeError();
                chain?.Dispose();
                throw error;
            }
            return chain;
        }

        private static void AddCrl(SafeStore store, List<KeyValuePair<string, byte[]>> inputs,
            string source, byte[] bytes)
        {
            // Add a CRL to the temporary store and retain its source for diagnostics.
            if (!CertAddEncodedCRLToStore(store, 1, bytes, bytes.Length, 4, IntPtr.Zero)) throw NativeError();
            inputs.Add(new KeyValuePair<string, byte[]>(source, bytes));
        }

        internal static CrlResult InspectCrl(byte[] bytes, string source, X509Certificate2 certificate,
            IEnumerable<X509Certificate2> issuers, OidNames names = null)
        {
            // Decode the CRL context and identify its issuer, extensions, and base or delta type.
            names ??= OidNames.Windows;
            using (var crl = CertCreateCRLContext(1, bytes, bytes.Length))
            {
                if (crl.IsInvalid) throw NativeError();
                var context = Read<EncodedContext>(crl.DangerousGetHandle());
                if (context.Size != bytes.Length) throw new CryptographicException("Select a single encoded CRL.");
                var info = Read<CrlInfo>(context.Info);
                var extensions = Extensions(info.ExtensionCount, info.Extensions).ToArray();
                var issuer = new X500DistinguishedName(Bytes(info.Issuer));
                var number = extensions.FirstOrDefault(extension => extension.Oid.Value == "2.5.29.20");
                var numberText = "";
                if (number != null)
                {
                    // Render the nonnegative CRL number itself rather than Windows' localized field label.
                    var data = number.RawData;
                    if (data.Length < 3 || data[0] != 2 || data[1] >= 128 || data[1] != data.Length - 2 ||
                        (data[2] & 128) != 0) throw new CryptographicException("Invalid CRL number.");
                    numberText = new BigInteger(data.Skip(2).Reverse().Concat(new byte[1]).ToArray())
                        .ToString(CultureInfo.InvariantCulture);
                }
                var result = new CrlResult
                {
                    Source = source, Encoded = bytes, IsDelta = extensions.Any(e => e.Oid.Value == "2.5.29.27"),
                    Issuer = issuer.Name, EntryCount = info.EntryCount,
                    ThisUpdate = info.ThisUpdate == 0 ? null : DateTime.FromFileTimeUtc(info.ThisUpdate),
                    NextUpdate = info.NextUpdate == 0 ? null : DateTime.FromFileTimeUtc(info.NextUpdate),
                    Number = numberText
                };

                // Report CRL identity, validity window, entry count, and current freshness.
                var text = new TimeReport("CRL: " + source + "\r\n");
                text.AppendLine("  SHA-256: " + Hash(bytes));
                text.AppendLine("  Issuer: " + issuer.Name);
                text.AppendLine("  Type: " + (result.IsDelta ? "Delta (requires a compatible base CRL)" : "Base"));
                text.AppendLine("  Signature algorithm: " + names.Describe(Marshal.PtrToStringAnsi(info.Signature.Oid), 4));
                text.Append("  This update: ").AppendTime(result.ThisUpdate).AppendLine();
                text.Append("  Next update: ").AppendTime(result.NextUpdate).AppendLine();
                text.AppendLine("  Revoked entries: " + info.EntryCount.ToString("N0", CultureInfo.InvariantCulture));
                var now = DateTime.UtcNow.ToFileTimeUtc();
                result.Current = info.ThisUpdate > 0 && info.ThisUpdate <= now && info.NextUpdate > now;
                text.AppendLine("  Freshness: " +
                    (result.Current ? "Current" : "Expired, not yet valid, or no next update"));
                if (certificate != null)
                {
                    // Check whether the CRL issuer and distribution-point scope fit the certificate.
                    result.IssuerMatches = SameName(issuer.RawData, certificate.IssuerName.RawData);
                    result.ScopeMatches = CertIsValidCRLForCertificate(certificate.Handle,
                        crl.DangerousGetHandle(), 0, IntPtr.Zero);
                    text.AppendLine("  Direct issuer match: " + result.IssuerMatches);
                    text.AppendLine("  Distribution-point scope check: " + result.ScopeMatches);

                    // Verify the CRL signature using available certificates with a matching issuer name.
                    var signers = issuers.Where(item => SameName(item.SubjectName.RawData, issuer.RawData)).ToArray();
                    var signer = signers.FirstOrDefault(item => CryptVerifyCertificateSignatureEx(IntPtr.Zero, 1, 3,
                        crl.DangerousGetHandle(), 2, item.Handle, 0, IntPtr.Zero));
                    result.SignatureValid = signers.Length == 0 ? (bool?)null : signer != null;
                    text.AppendLine("  Signature: " + (result.SignatureValid == true ? "Verified" :
                        result.SignatureValid == false ? "INVALID" : "Unknown — CRL signer certificate not available"));
                    if (signer != null)
                    {
                        // Report whether the verified signer permits CRL signing.
                        var usage = signer.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
                        text.AppendLine("  Signer: " + signer.Subject + " (" + signer.Thumbprint + ")");
                        text.AppendLine("  Signer CRL-sign usage: " + (usage == null ? "Unrestricted" :
                            ((usage.KeyUsages & X509KeyUsageFlags.CrlSign) != 0 ? "Allowed" : "NOT allowed")));
                    }
                    // Locate the certificate serial in this particular CRL.
                    if (!CertFindCertificateInCRL(certificate.Handle, crl.DangerousGetHandle(), 0,
                        IntPtr.Zero, out var entry)) throw NativeError();
                    result.Listed = entry != IntPtr.Zero;
                    text.AppendLine("  Certificate entry: " + (result.Listed ? "FOUND" : "Not present in this CRL"));
                    if (result.Listed)
                    {
                        // Show the matching entry revocation date and any entry-specific extensions.
                        var item = Read<CrlEntry>(entry);
                        text.Append("  Entry revocation date: ").AppendTime(FileTime(item.RevocationDate)).AppendLine();
                        foreach (var extension in Extensions(item.ExtensionCount, item.Extensions))
                            text.Append("  Entry " + names.Describe(extension.Oid.Value, 6) + ": ")
                                .Append(() => names.FormatExtension(extension).Trim()).AppendLine();
                    }
                }
                // Append decoded CRL extensions to the inspection report.
                foreach (var extension in extensions)
                    text.Append("  " + names.Describe(extension.Oid.Value, 6) +
                        (extension.Critical ? " (Critical)" : "") + ":\r\n")
                        .Append(() => names.FormatExtension(extension).Trim()).AppendLine();
                result.Details = text;
                return result;
            }
        }

        internal static string[] Urls(IntPtr context, int kind)
        {
            // Measure the native URL result and treat absent distribution points as an empty list.
            var size = 0;
            if (!CryptGetObjectUrl(new IntPtr(kind), context, 2, IntPtr.Zero, ref size,
                IntPtr.Zero, IntPtr.Zero, IntPtr.Zero))
            {
                var error = Marshal.GetLastWin32Error();
                if (error == unchecked((int)0x80092004)) return Array.Empty<string>();
                throw new Win32Exception(error);
            }
            // Retrieve URL pointers into a managed array before freeing the native buffer.
            using (var buffer = new NativeBuffer(size))
            {
                if (!CryptGetObjectUrl(new IntPtr(kind), context, 2, buffer.Pointer, ref size,
                    IntPtr.Zero, IntPtr.Zero, IntPtr.Zero)) throw NativeError();
                var array = Read<PointerArray>(buffer.Pointer);
                return Enumerable.Range(0, array.Count).Select(i =>
                    Marshal.PtrToStringUni(Marshal.ReadIntPtr(array.Items, i * IntPtr.Size))).ToArray();
            }
        }

        internal static TimeReport CrlMetadata(byte[] bytes)
        {
            // Read compact CRL size and update metadata for server statistics.
            using (var crl = CertCreateCRLContext(1, bytes, bytes.Length))
            {
                if (crl.IsInvalid) throw NativeError();
                var context = Read<EncodedContext>(crl.DangerousGetHandle());
                var info = Read<CrlInfo>(context.Info);
                return new TimeReport(CaServerStatistics.Size(bytes.Length) + $" / {info.EntryCount:N0} Entries\r\n")
                    .Append("This Update: ").AppendTime(FileTime(info.ThisUpdate)).AppendLine()
                    .Append("Next Update: ").AppendTime(FileTime(info.NextUpdate));
            }
        }

        private static string[] DeltaUrls(IntPtr certificate, byte[] bytes)
        {
            // Pair the certificate and base CRL when asking Windows for delta locations.
            using (var crl = CertCreateCRLContext(1, bytes, bytes.Length))
            using (var pair = new NativeBuffer(IntPtr.Size * 2))
            {
                if (crl.IsInvalid) throw NativeError();
                Marshal.WriteIntPtr(pair.Pointer, certificate);
                Marshal.WriteIntPtr(pair.Pointer, IntPtr.Size, crl.DangerousGetHandle());
                return Urls(pair.Pointer, 7);
            }
        }

        internal static List<byte[]> RetrieveCrls(string url, bool offline, int timeoutSeconds)
        {
            var options = new RetrievalOptions { Size = Marshal.SizeOf<RetrievalOptions>(), MaximumBytes = 100 * 1024 * 1024 };

            // MULTIPLE_OBJECTS returns a store, including LDAP responses containing multiple CRLs.
            if (!CryptRetrieveObjectByUrl(url, new IntPtr(2), offline ? 3u : 13u, timeoutSeconds * 1000,
                out var store, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref options))
            {
                var error = NativeError();
                store?.Dispose();
                throw error;
            }
            using (store)
            {
                // Copy every CRL from the retrieval store before disposing its native resources.
                var result = new List<byte[]>();
                var current = IntPtr.Zero;
                try
                {
                    while ((current = CertEnumCRLsInStore(store, current)) != IntPtr.Zero) result.Add(Encoded(current));
                }
                finally { if (current != IntPtr.Zero) CertFreeCRLContext(current); }
                if (result.Count == 0) throw new InvalidOperationException("The location did not return a CRL.");
                return result;
            }
        }

        private static IEnumerable<X509Extension> Extensions(int count, IntPtr pointer)
        {
            // Project native extension entries into managed values for decoding.
            for (var i = 0; i < count; i++)
            {
                var item = Read<Extension>(IntPtr.Add(pointer, i * Marshal.SizeOf<Extension>()));
                yield return new X509Extension(Marshal.PtrToStringAnsi(item.Oid), Bytes(item.Value), item.Critical != 0);
            }
        }

        private static T Read<T>(IntPtr pointer) => Marshal.PtrToStructure<T>(pointer);
        private static Win32Exception NativeError() => new Win32Exception(Marshal.GetLastWin32Error());
        private static DateTime? FileTime(long fileTime) => fileTime == 0 ? null : DateTime.FromFileTimeUtc(fileTime);

        private static bool SameName(byte[] first, byte[] second)
        {
            // Compare encoded distinguished names with Windows certificate name semantics.
            using (var buffer = new NativeBuffer(first.Length + second.Length))
            {
                var left = new Blob { Data = buffer.Pointer, Size = first.Length };
                var right = new Blob { Data = IntPtr.Add(buffer.Pointer, first.Length), Size = second.Length };
                Marshal.Copy(first, 0, left.Data, first.Length);
                Marshal.Copy(second, 0, right.Data, second.Length);
                return CertCompareCertificateName(1, ref left, ref right);
            }
        }
        private static byte[] Bytes(Blob blob)
        {
            // Copy a native blob into managed storage without retaining its pointer.
            var result = new byte[blob.Size];
            if (result.Length > 0) Marshal.Copy(blob.Data, result, 0, result.Length);
            return result;
        }

        private static byte[] Encoded(IntPtr pointer)
        {
            // Extract an encoded context payload independently of its native lifetime.
            var context = Read<EncodedContext>(pointer);
            return Bytes(new Blob { Data = context.Encoded, Size = context.Size });
        }

        private static string Hash(byte[] bytes)
        {
            using (var sha = SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-", "");
        }

        // Layouts follow wincrypt.h. The chain structs only declare the prefixes read here.
        [StructLayout(LayoutKind.Sequential)]
        private struct Blob
        {
            public int Size; public IntPtr Data;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct Algorithm
        {
            public IntPtr Oid; public Blob Parameters;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct EncodedContext
        {
            public int Encoding; public IntPtr Encoded; public int Size; public IntPtr Info, Store;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct CrlInfo
        {
            public int Version; public Algorithm Signature; public Blob Issuer; public long ThisUpdate, NextUpdate; public int EntryCount; public IntPtr Entries; public int ExtensionCount; public IntPtr Extensions;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct CrlEntry
        {
            public Blob Serial; public long RevocationDate; public int ExtensionCount; public IntPtr Extensions;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct Extension
        {
            public IntPtr Oid; public int Critical; public Blob Value;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct PointerArray
        {
            public int Count; public IntPtr Items;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct UsageMatch
        {
            public int Type; public PointerArray Usage;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct ChainParameters
        {
            public int Size; public UsageMatch Usage, Issuance; public int Timeout, CheckFreshness, Freshness; public IntPtr CacheResync, StrongSign; public int StrongSignFlags;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct TrustStatus
        {
            public uint Errors, Information;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct ChainArray
        {
            public int Size; public TrustStatus Trust; public int Count; public IntPtr Items;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct ChainElement
        {
            public int Size; public IntPtr Certificate; public TrustStatus Trust; public IntPtr Revocation;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct RevocationParameters
        {
            public int Size; public IntPtr Issuer; public int StoreCount; public IntPtr Stores, CrlStore, Time; public int Timeout, CheckFreshness, Freshness; public IntPtr CurrentTime, CrlInfo, CacheResync, Chain;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct RevocationStatus
        {
            public int Size, Index; public uint Error, Reason; public int HasFreshness, Freshness;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct RevocationCrlInfo
        {
            public int Size; public IntPtr BaseCrl, DeltaCrl, Entry; public int DeltaEntry;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct RetrievalOptions
        {
            public int Size; public IntPtr LastSync; public int MaximumBytes; public IntPtr PreFetch, Flush, Response, FilePrefix, CacheResync; public int ProxyCache, HttpStatus;
        }

        private sealed class NativeBuffer : IDisposable
        {
            public IntPtr Pointer { get; }
            public NativeBuffer(int size) => Pointer = Marshal.AllocHGlobal(size);
            public void Dispose() => Marshal.FreeHGlobal(Pointer);
        }

        private sealed class SafeStore : SafeHandleZeroOrMinusOneIsInvalid
        {
            public SafeStore() : base(true) { }
            protected override bool ReleaseHandle() => CertCloseStore(handle, 0);
        }

        private sealed class SafeCrl : SafeHandleZeroOrMinusOneIsInvalid
        {
            public SafeCrl() : base(true) { }
            protected override bool ReleaseHandle() => CertFreeCRLContext(handle);
        }

        private sealed class SafeChain : SafeHandleZeroOrMinusOneIsInvalid
        {
            public SafeChain() : base(true) { }
            protected override bool ReleaseHandle() { CertFreeCertificateChain(handle); return true; }
        }

        [DllImport("crypt32.dll", SetLastError = true)]
        private static extern SafeStore CertOpenStore(IntPtr provider, int encoding, IntPtr cryptProvider,
            int flags, IntPtr parameter);
        [DllImport("crypt32.dll")]
        private static extern bool CertCloseStore(IntPtr store, int flags);
        [DllImport("crypt32.dll", SetLastError = true)]
        private static extern bool CertAddCertificateContextToStore(SafeStore store, IntPtr certificate,
            int disposition, IntPtr context);
        [DllImport("crypt32.dll", SetLastError = true)]
        private static extern bool CertAddEncodedCRLToStore(SafeStore store, int encoding, byte[] bytes, int length,
            int disposition, IntPtr context);
        [DllImport("crypt32.dll", SetLastError = true)]
        private static extern SafeCrl CertCreateCRLContext(int encoding, byte[] bytes, int length);
        [DllImport("crypt32.dll")]
        private static extern bool CertFreeCRLContext(IntPtr context);
        [DllImport("crypt32.dll")]
        private static extern bool CertCompareCertificateName(int encoding, ref Blob first, ref Blob second);
        [DllImport("crypt32.dll", SetLastError = true)]
        private static extern IntPtr CertEnumCRLsInStore(SafeStore store, IntPtr previous);
        [DllImport("crypt32.dll", SetLastError = true)]
        private static extern bool CertGetCertificateChain(IntPtr engine, IntPtr certificate, IntPtr time,
            SafeStore store, ref ChainParameters options, uint flags, IntPtr reserved, out SafeChain chain);
        [DllImport("crypt32.dll")]
        private static extern void CertFreeCertificateChain(IntPtr chain);
        [DllImport("crypt32.dll", SetLastError = true)]
        private static extern bool CertVerifyRevocation(int encoding, int type, int count, IntPtr[] certificates,
            int flags, ref RevocationParameters options, ref RevocationStatus status);
        [DllImport("crypt32.dll", SetLastError = true)]
        private static extern bool CertIsValidCRLForCertificate(IntPtr certificate, IntPtr crl, int flags,
            IntPtr reserved);
        [DllImport("crypt32.dll", SetLastError = true)]
        private static extern bool CertFindCertificateInCRL(IntPtr certificate, IntPtr crl, int flags,
            IntPtr reserved, out IntPtr entry);
        [DllImport("crypt32.dll", SetLastError = true)]
        private static extern bool CryptVerifyCertificateSignatureEx(IntPtr provider, int encoding, int subjectType,
            IntPtr subject, int issuerType, IntPtr issuer, int flags, IntPtr extra);
        [DllImport("cryptnet.dll", SetLastError = true)]
        private static extern bool CryptGetObjectUrl(IntPtr oid, IntPtr context, int flags, IntPtr array,
            ref int size, IntPtr info, IntPtr infoSize, IntPtr reserved);
        [DllImport("cryptnet.dll", EntryPoint = "CryptRetrieveObjectByUrlW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CryptRetrieveObjectByUrl(string url, IntPtr oid, uint flags, int timeout,
            out SafeStore store, IntPtr async, IntPtr credentials, IntPtr verify, ref RetrievalOptions options);
    }
}
