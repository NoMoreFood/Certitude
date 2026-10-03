//
// Copyright (c) Bryan Berns.
// Licensed under GPLv3. See LICENSE.md.
//

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.DirectoryServices.Protocols;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Certitude
{
    internal sealed class PublishedStore
    {
        public string Id { get; }
        public string Name { get; }
        public string Container { get; }
        public string Attribute { get; }
        public string ObjectClass { get; }
        public string Effect { get; }
        public bool FixedObject => Id == "NTAuthCA";
        public bool IsCrl => ObjectClass == "cRLDistributionPoint";
        public string ItemName => IsCrl ? "CRL" : "Certificate";
        public bool ExistingOnly => Id == "Enrollment" || IsCrl;
        public bool RequiredValue => !ExistingOnly && Id != "CrossCA";
        public override string ToString() => Name;

        public PublishedStore(string id, string name, string container,
            string attribute, string objectClass, string effect)
        {
            // Describe the directory location and effect of this publication store.
            Id = id; Name = name; Container = container;
            Attribute = attribute; ObjectClass = objectClass; Effect = effect;
        }
    }

    internal sealed class PublishedObject
    {
        public Guid Id { get; set; }
        public string Name { get; set; }
        public string DistinguishedName { get; set; }
        public bool IsAuthority { get; set; }
    }

    internal sealed class PublishedArtifact
    {
        public PublishedStore Store { get; set; }
        public PublishedObject Object { get; set; }
        public byte[] Value { get; set; }
        public int Direction { get; set; } = -1;
        public InventoryCertificate Certificate { get; set; }
        public CrlResult Crl { get; set; }
        public string Error { get; set; } = "";
        public string Fingerprint { get; set; }
        public string Subject => Certificate?.Subject ?? Crl?.Issuer ?? "Unreadable " + Store.ItemName + " Value";
        public string Issuer => Certificate?.Issuer ?? Crl?.Issuer ?? "";
        public string Thumbprint => Certificate?.Thumbprint ?? Fingerprint;
        public DateTime? Expires => Certificate?.NotAfter ?? Crl?.NextUpdate;
        public DateTime? Updated => Crl?.ThisUpdate;
        public int? Entries => Crl?.EntryCount;
        public string Number => Crl?.Number ?? "";
        public string Status => Certificate?.Validity ?? (Crl == null ? "Unreadable" :
            Crl.ThisUpdate == null ? "No This Update" : Crl.ThisUpdate > DateTime.UtcNow ? "Not Yet Valid" :
            Crl.NextUpdate == null ? "No Next Update" :
            Crl.NextUpdate <= DateTime.UtcNow ? "Expired" : "Current (Time Only)");
        public bool Readable => Certificate != null || Crl != null;
        public byte[] Encoded => Certificate?.Encoded ?? Crl?.Encoded ?? Value;
        public string Details => Certificate != null ? CertificateUtilities.Details(Certificate) :
            Crl != null ? Crl.Details + "\r\nSignature And Certificate Revocation Status Not Checked In This View." :
            Error + "\r\nValue SHA-256: " + Fingerprint;
        public string PairSide => Direction switch { 0 => "Forward", 1 => "Reverse", _ => "" };
        public string Key => Object.Id + "/" + Fingerprint + "/" + Direction;
    }

    internal sealed class PublishedSnapshot
    {
        public List<PublishedObject> Objects { get; } = new List<PublishedObject>();
        public List<PublishedArtifact> Artifacts { get; } = new List<PublishedArtifact>();
        public string OidStatus { get; set; } = "";
    }

    internal sealed class PublicationPlan
    {
        public PublishedStore Store { get; set; }
        public PublishedObject Object { get; set; }
        public PublishedArtifact Artifact { get; set; }
        public PublishedArtifact Previous { get; set; }
        public string Server { get; set; }
        public string Review => "Domain Controller: " + Server + "\r\nStore: " + Store.Name +
            "\r\nDirectory Object: " + Object.DistinguishedName + "\r\n" +
            (Object.Id == Guid.Empty ? "Create A New Publication Object" : Previous != null ?
                "Replace The Existing Base CRL\r\nCurrent SHA-256: " + Previous.Fingerprint :
                "Add To The Existing Publication Object") +
            "\r\n\r\n" + Store.Effect + "\r\n\r\n" + Artifact.Details;
    }

    internal sealed class PublishedDirectory
    {
        public static readonly PublishedStore[] Stores =
        {
            new PublishedStore("NTAuthCA", "NTAuth Certificates", "", "cACertificate", "certificationAuthority",
                "Changes which CAs the forest accepts for certificate-based authentication."),
            new PublishedStore("RootCA", "Trusted Root CAs", "Certification Authorities", "cACertificate",
                "certificationAuthority", "Changes the trusted root CA certificates distributed through Active Directory."),
            new PublishedStore("SubCA", "Intermediate CAs / AIA", "AIA", "cACertificate", "certificationAuthority",
                "Changes CA certificates available to clients building certificate chains through LDAP AIA locations."),
            new PublishedStore("CrossCA", "Cross-Certificates / AIA", "AIA", "crossCertificatePair",
                "certificationAuthority", "Changes cross-certificates used to build certification paths. " +
                "New certificates are published as the forward side of a certificate pair."),
            new PublishedStore("KRA", "Key Recovery Agents", "KRA", "userCertificate", "msPKI-PrivateKeyRecoveryAgent",
                "Changes published key recovery agent certificates. Configure CA key recovery separately."),
            new PublishedStore("Enrollment", "Enrollment Services", "Enrollment Services", "cACertificate",
                "pKIEnrollmentService", "Changes the certificates advertised by an existing enrollment service. " +
                "CA configuration and published templates stay unchanged."),
            new PublishedStore("BaseCRL", "Base CRLs", "", "certificateRevocationList", "cRLDistributionPoint",
                "Changes base revocation lists available to clients through this AD publication location."),
            new PublishedStore("DeltaCRL", "Delta CRLs", "", "deltaRevocationList", "cRLDistributionPoint",
                "Changes delta revocation lists. Clients also need the matching base CRL."),
            new PublishedStore("ARL", "Authority Revocation Lists", "", "authorityRevocationList",
                "cRLDistributionPoint", "Changes revocation lists for CA certificates at this AD publication location.")
        };
        public string Server { get; }
        public string ConfigurationName { get; }
        private readonly OidDirectory oidDirectory;
        internal OidNames Names => OidNames.Load(oidDirectory);
        internal string ServicesName => "CN=Public Key Services,CN=Services," + ConfigurationName;

        private PublishedDirectory(string server, string configuration, OidDirectory directory)
        {
            // Keep publication and OID reads bound to the same controller and forest.
            oidDirectory = directory;
            Server = server;
            ConfigurationName = configuration;
        }

        public static PublishedDirectory Connect(string target = "")
        {
            // Resolve the requested forest before creating a publication connection.
            var directory = OidDirectory.Connect(target);
            return new PublishedDirectory(directory.Server, directory.ConfigurationName, directory);
        }

        internal LdapConnection Open()
        {
            // Use the current Windows identity with signed and sealed LDAP operations.
            var connection = new LdapConnection(new LdapDirectoryIdentifier(Server),
                CredentialCache.DefaultNetworkCredentials, AuthType.Negotiate) { Timeout = TimeSpan.FromSeconds(30) };
            connection.SessionOptions.ProtocolVersion = 3;
            connection.SessionOptions.Signing = true;
            connection.SessionOptions.Sealing = true;
            connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
            return connection;
        }

        internal string ParentName(PublishedStore store) => store.FixedObject || store.IsCrl ? ServicesName :
            "CN=" + store.Container + "," + ServicesName;

        private string TargetName(PublishedStore store, string name)
        {
            // Retain full CRL object paths because separate CA containers can contain identical common names.
            if (!store.IsCrl) return "CN=" + EscapeName(name) + "," + ParentName(store);
            if (string.IsNullOrWhiteSpace(name) || !name.EndsWith(
                "," + ServicesName, StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("Select an existing CRL publication object in this forest.");
            return name;
        }

        private static bool Matches(PublishedStore store, SearchResultEntry entry) =>
            entry.Attributes["objectClass"].GetValues(typeof(string)).Cast<string>().Any(value =>
                value.Equals(store.ObjectClass, StringComparison.OrdinalIgnoreCase) ||
                (store.IsCrl && value.Equals("certificationAuthority", StringComparison.OrdinalIgnoreCase)));

        internal static string EscapeName(string value)
        {
            // Validate a publication object name before using it in a distinguished name.
            var name = (value ?? "").Trim();
            if (name.Length == 0 || name.Length > 64 || name.Any(char.IsControl))
                throw new ArgumentException("Enter a publication object name of 1–64 characters.");

            // Escape characters that have structural meaning inside a directory common name.
            var escaped = new StringBuilder();
            for (var i = 0; i < name.Length; i++)
            {
                if (",+\"\\<>;=".Contains(name[i]) || (i == 0 && name[i] == '#')) escaped.Append('\\');
                escaped.Append(name[i]);
            }
            return escaped.ToString();
        }

        private static SearchResultEntry Entry(LdapConnection connection, string name, params string[] attributes)
        {
            // Read one publication object and represent a missing object as an absent result.
            try
            {
                var response = (SearchResponse)connection.SendRequest(
                    new SearchRequest(name, "(objectClass=*)", SearchScope.Base, attributes));
                return response.Entries.Count == 0 ? null : response.Entries[0];
            }
            catch (DirectoryOperationException error) when (error.Response?.ResultCode == ResultCode.NoSuchObject)
            { return null; }
        }

        private static PublishedObject DescribeObject(SearchResultEntry entry) => new PublishedObject
        {
            Id = new Guid((byte[])entry.Attributes["objectGUID"][0]),
            Name = (string)entry.Attributes["cn"].GetValues(typeof(string))[0],
            DistinguishedName = entry.DistinguishedName,
            IsAuthority = entry.Attributes["objectClass"].GetValues(typeof(string)).Cast<string>()
                .Contains("certificationAuthority", StringComparer.OrdinalIgnoreCase)
        };

        private static byte[][] Values(LdapConnection connection, SearchResultEntry entry, string attribute)
        {
            // Track object identity across ranged reads of a multivalued publication attribute.
            var values = new List<byte[]>();
            var id = new Guid((byte[])entry.Attributes["objectGUID"][0]);
            var next = 0;
            while (true)
            {
                // Identify the returned range while detecting replacement or incomplete results.
                if (new Guid((byte[])entry.Attributes["objectGUID"][0]) != id)
                    throw new InvalidOperationException("The publication object changed while reading. Refresh again.");
                var name = entry.Attributes.AttributeNames.Cast<string>().FirstOrDefault(value =>
                    value.StartsWith(attribute + ";range=", StringComparison.OrdinalIgnoreCase)) ??
                    (entry.Attributes.Contains(attribute) ? attribute : null);
                if (name == null)
                {
                    if (next != 0)
                        throw new InvalidOperationException("The directory returned an incomplete publication list.");
                    return values.ToArray();
                }
                // Accumulate values and request the next range until the full attribute is read.
                values.AddRange(entry.Attributes[name].GetValues(typeof(byte[])).Cast<byte[]>());
                if (name.Equals(attribute, StringComparison.OrdinalIgnoreCase) || name.EndsWith("-*"))
                    return values.ToArray();
                var end = name.Substring(name.LastIndexOf('-') + 1);
                if (!int.TryParse(end, NumberStyles.None, CultureInfo.InvariantCulture, out var last) || last < next)
                    throw new InvalidOperationException("The directory returned an invalid publication range.");
                next = checked(last + 1);
                entry = Entry(connection, entry.DistinguishedName, "objectGUID", attribute + ";range=" + next + "-*");
                if (entry == null)
                    throw new InvalidOperationException("The publication object was removed. Refresh again.");
            }
        }

        internal static PublishedArtifact[] Describe(PublishedStore store, PublishedObject target, byte[] value,
            OidNames names = null)
        {
            // Ignore the required-attribute placeholder and fingerprint real publication values.
            if (store.RequiredValue && value.Length == 1 && value[0] == 0)
                return Array.Empty<PublishedArtifact>();
            string fingerprint;
            using (var hash = SHA256.Create())
                fingerprint = BitConverter.ToString(hash.ComputeHash(value)).Replace("-", "");
            PublishedArtifact Row(byte[] encoded, int direction)
            {
                // Describe an artifact while retaining its source value even if decoding fails.
                var row = new PublishedArtifact { Store = store, Object = target, Value = value,
                    Direction = direction, Fingerprint = fingerprint };
                try
                {
                    // Use the native CRL decoder for revocation lists while retaining unreadable directory bytes.
                    if (store.IsCrl)
                    {
                        row.Crl = CertificateValidation.InspectCrl(
                            encoded, target.DistinguishedName, null, null, names);
                        return row;
                    }
                    using var certificate = new X509Certificate2(encoded);
                    if (!certificate.RawData.SequenceEqual(encoded))
                        throw new CryptographicException("Invalid certificate data.");
                    row.Certificate = CertificateUtilities.Describe(certificate, names);
                }
                catch (Exception error) when (error is CryptographicException or Win32Exception or ArgumentException)
                { row.Error = CaAdministration.Error(error); }
                return row;
            }
            // Expand cross-certificate pairs into separate forward and reverse rows.
            if (store.Id != "CrossCA") return new[] { Row(value, -1) };
            try
            {
                return DecodePair(value).Select((encoded, side) => encoded == null ? null : Row(encoded, side))
                    .Where(row => row != null).ToArray();
            }
            catch (ArgumentException error)
            {
                // Keep malformed pair data visible so it can still be inspected or removed.
                return new[] { new PublishedArtifact { Store = store, Object = target, Value = value,
                    Fingerprint = fingerprint, Error = error.Message } };
            }
        }

        public PublishedSnapshot Read(PublishedStore store)
        {
            // Prepare a paged search including nested CDP and CA objects for revocation lists.
            using var connection = Open();
            var names = Names;
            var snapshot = new PublishedSnapshot { OidStatus = names.Status };
            var filter = store.IsCrl ? "(|(objectClass=cRLDistributionPoint)(objectClass=certificationAuthority))" :
                "(objectClass=" + store.ObjectClass + ")";
            if (store.FixedObject) filter = "(&" + filter + "(cn=NTAuthCertificates))";
            var request = new SearchRequest(ParentName(store), filter,
                store.IsCrl ? SearchScope.Subtree : SearchScope.OneLevel,
                "cn", "objectGUID", "objectClass", store.Attribute + ";range=0-499");
            var pages = new PageResultRequestControl(500);
            request.Controls.Add(pages);
            do
            {
                // Read each page, including all ranged publication values for every object.
                SearchResponse response;
                try { response = (SearchResponse)connection.SendRequest(request); }
                catch (DirectoryOperationException error) when (error.Response?.ResultCode == ResultCode.NoSuchObject)
                { return snapshot; }
                foreach (SearchResultEntry entry in response.Entries)
                {
                    var target = DescribeObject(entry);
                    snapshot.Objects.Add(target);
                    foreach (var value in Values(connection, entry, store.Attribute))
                        snapshot.Artifacts.AddRange(Describe(store, target, value, names));
                }
                pages.Cookie = response.Controls.OfType<PageResultResponseControl>().Single().Cookie;
            } while (pages.Cookie.Length > 0);

            // Sort the completed snapshot for stable object selection and artifact browsing.
            snapshot.Objects.Sort((a, b) => StringComparer.OrdinalIgnoreCase.Compare(
                store.IsCrl ? a.DistinguishedName : a.Name, store.IsCrl ? b.DistinguishedName : b.Name));
            snapshot.Artifacts.Sort((a, b) => StringComparer.OrdinalIgnoreCase.Compare(a.Subject, b.Subject));
            return snapshot;
        }

        internal static InventoryCertificate ValidateCertificate(PublishedStore store, byte[] encoded, OidNames names = null)
        {
            // Require exactly one encoded certificate before checking store-specific requirements.
            if (encoded == null || X509Certificate2.GetCertContentType(encoded) != X509ContentType.Cert)
                throw new ArgumentException("Select a single public certificate in DER or PEM format.");
            using var certificate = new X509Certificate2(encoded);
            if (!certificate.RawData.SequenceEqual(encoded))
                throw new ArgumentException("Select a single public certificate in DER or PEM format.");

            // Enforce CA constraints or key recovery usage according to the destination store.
            var metadata = CertificateUtilities.Describe(certificate, names);
            if (store.Id != "KRA" && !metadata.IsCa)
                throw new ArgumentException("This store requires a CA certificate with CA basic constraints.");
            if (store.Id == "KRA" && !certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>()
                .Any(extension => extension.EnhancedKeyUsages.Cast<Oid>()
                    .Any(oid => oid.Value == "1.3.6.1.4.1.311.21.6")))
                throw new ArgumentException("Select a certificate with the Key Recovery Agent enhanced key usage.");
            return metadata;
        }

        internal static PublishedArtifact ValidateArtifact(PublishedStore store, byte[] encoded, OidNames names = null)
        {
            // Reject malformed inputs and CRLs placed in the wrong base or delta publication attribute.
            if (!store.IsCrl) return new PublishedArtifact
                { Store = store, Certificate = ValidateCertificate(store, encoded, names) };
            var crl = CertificateValidation.InspectCrl(encoded, store.Name, null, null, names);
            if (crl.IsDelta != (store.Id == "DeltaCRL"))
                throw new ArgumentException(store.Id == "DeltaCRL" ? "Select a delta CRL." : "Select a base CRL.");
            return new PublishedArtifact { Store = store, Crl = crl };
        }

        public PublicationPlan Prepare(PublishedStore store, string objectName, byte[] encoded)
        {
            // Validate the artifact and resolve the intended publication object.
            var artifact = ValidateArtifact(store, encoded, Names);
            objectName = store.FixedObject ? "NTAuthCertificates" : (objectName ?? "").Trim();
            var name = TargetName(store, objectName);
            using var connection = Open();
            var entry = Entry(connection, name, "cn", "objectGUID", "objectClass", store.Attribute);

            // Check whether the destination can be created or must already have the expected class.
            if (entry == null && store.ExistingOnly)
                throw new InvalidOperationException("Select an existing publication object.");
            if (entry != null && !Matches(store, entry))
                throw new InvalidOperationException("The selected object is not a publication object for this store.");
            var plan = new PublicationPlan { Store = store, Artifact = artifact, Server = Server,
                Object = entry == null ? new PublishedObject { Name = objectName, DistinguishedName = name } :
                    DescribeObject(entry) };

            // Retain the reviewed base CRL because its directory attribute accepts only one value.
            if (store.Id == "BaseCRL" && entry != null)
            {
                var previous = Values(connection, entry, store.Attribute).SingleOrDefault();
                if (previous != null) plan.Previous = Describe(store, plan.Object, previous, Names).Single();
            }
            return plan;
        }

        private SearchResultEntry Current(LdapConnection connection, PublishedStore store, PublishedObject expected)
        {
            // Recheck store membership and object identity immediately before a directory change.
            var name = TargetName(store, store.IsCrl ? expected.DistinguishedName : expected.Name);
            if (!name.Equals(expected.DistinguishedName, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("The publication object does not belong to the selected store.");
            var entry = Entry(connection, name, "cn", "objectGUID", "objectClass", store.Attribute);
            if ((entry == null) != (expected.Id == Guid.Empty) || (entry != null &&
                (DescribeObject(entry).Id != expected.Id || !Matches(store, entry))))
                throw new InvalidOperationException("The publication object changed. Refresh and review again.");
            return entry;
        }

        public void Publish(PublicationPlan plan)
        {
            // Validate the reviewed plan against the current controller and artifact contents.
            if (plan.Server != Server)
                throw new ArgumentException("The publication plan belongs to another domain controller.");
            ValidateArtifact(plan.Store, plan.Artifact.Encoded);
            using var connection = Open();
            var entry = Current(connection, plan.Store, plan.Object);
            var value = plan.Store.Id == "CrossCA" ?
                EncodePair(plan.Artifact.Encoded, null) : plan.Artifact.Encoded;
            if (entry != null)
            {
                // Reject duplicates on an existing publication object before adding the value.
                var values = Values(connection, entry, plan.Store.Attribute);
                var duplicate = plan.Store.Id == "CrossCA" ?
                    values.SelectMany(bytes => Describe(plan.Store, plan.Object, bytes))
                        .Any(row => row.Encoded.SequenceEqual(plan.Artifact.Encoded)) :
                    values.Any(bytes => bytes.SequenceEqual(value));
                if (duplicate) throw new InvalidOperationException("This value is already published on this object.");

                // Replace a single-valued base CRL only while the reviewed value is still current.
                if (plan.Store.Id == "BaseCRL")
                {
                    if (plan.Previous == null ? values.Length != 0 :
                        values.Length != 1 || !values[0].SequenceEqual(plan.Previous.Value))
                        throw new InvalidOperationException("The base CRL changed. Refresh and review again.");
                    var replacement = new ModifyRequest(plan.Object.DistinguishedName);
                    if (plan.Previous != null)
                        replacement.Modifications.Add(Change(
                            plan.Store.Attribute, DirectoryAttributeOperation.Delete, plan.Previous.Value));
                    replacement.Modifications.Add(Change(
                        plan.Store.Attribute, DirectoryAttributeOperation.Add, value));
                    connection.SendRequest(replacement);
                    return;
                }

                // Add the real artifact and remove an obsolete empty-value placeholder together.
                var update = new ModifyRequest(plan.Object.DistinguishedName,
                    DirectoryAttributeOperation.Add, plan.Store.Attribute, value);
                if (values.Any(bytes => bytes.Length == 1 && bytes[0] == 0))
                    update.Modifications.Add(Change(
                        plan.Store.Attribute, DirectoryAttributeOperation.Delete, new byte[1]));
                connection.SendRequest(update);
                return;
            }
            // Create a missing publication container only for stores that permit new objects.
            if (plan.Store.ExistingOnly) throw new InvalidOperationException("Select an existing publication object.");
            var parent = ParentName(plan.Store);
            if (!plan.Store.FixedObject && Entry(connection, parent, "objectGUID") == null)
            {
                var container = new AddRequest(parent, "container");
                container.Attributes.Add(new DirectoryAttribute("cn", plan.Store.Container));
                try { connection.SendRequest(container); }
                catch (DirectoryOperationException error) when
                    (error.Response?.ResultCode == ResultCode.EntryAlreadyExists) { }
            }
            // Build the new publication object with its name and certificate attribute.
            var request = new AddRequest(plan.Object.DistinguishedName, plan.Store.ObjectClass);
            request.Attributes.Add(new DirectoryAttribute("cn", plan.Object.Name));
            request.Attributes.Add(new DirectoryAttribute(plan.Store.Attribute, value));
            if (plan.Store.ObjectClass == "certificationAuthority")
            {
                // Windows publication objects use a zero byte for required attributes without a published value.
                request.Attributes.Add(new DirectoryAttribute("certificateRevocationList", new byte[1]));
                request.Attributes.Add(new DirectoryAttribute("authorityRevocationList", new byte[1]));
                if (plan.Store.Id == "CrossCA")
                    request.Attributes.Add(new DirectoryAttribute("cACertificate", new byte[1]));
            }
            connection.SendRequest(request);
        }

        public void Remove(PublishedArtifact row)
        {
            // Revalidate the publication object and exact stored value before removing it.
            using var connection = Open();
            var entry = Current(connection, row.Store, row.Object);
            if (entry == null)
                throw new InvalidOperationException("The publication object was removed. Refresh again.");
            var values = Values(connection, entry, row.Store.Attribute);
            if (!values.Any(value => value.SequenceEqual(row.Value)))
                throw new InvalidOperationException("The published value changed. Refresh and review again.");

            // Remove the selected value while keeping required attributes populated.
            var request = new ModifyRequest(row.Object.DistinguishedName, DirectoryAttributeOperation.Delete,
                row.Store.Attribute, row.Value);
            var required = row.Store.RequiredValue || (DescribeObject(entry).IsAuthority &&
                row.Store.IsCrl && row.Store.Id != "DeltaCRL");
            if (required && values.Length == 1)
                request.Modifications.Add(Change(row.Store.Attribute, DirectoryAttributeOperation.Add, new byte[1]));
            if (row.Store.Id == "CrossCA" && row.Direction >= 0)
            {
                // Preserve the unselected side when removing one certificate from a pair.
                var pair = DecodePair(row.Value);
                pair[row.Direction] = null;
                if (pair.Any(value => value != null))
                {
                    var remaining = EncodePair(pair[0], pair[1]);
                    if (!values.Any(value => value.SequenceEqual(remaining)))
                    {
                        request.Modifications.Add(Change(
                            row.Store.Attribute, DirectoryAttributeOperation.Add, remaining));
                    }
                }
            }
            connection.SendRequest(request);
        }

        private static DirectoryAttributeModification Change(
            string name, DirectoryAttributeOperation operation, byte[] value)
        {
            // Package a binary attribute value for an LDAP modification request.
            var change = new DirectoryAttributeModification { Name = name, Operation = operation };
            change.Add(value);
            return change;
        }

        internal static byte[] EncodePair(byte[] forward, byte[] reverse)
        {
            // Require at least one certificate before constructing a DER pair.
            if (forward == null && reverse == null) throw new ArgumentException("A certificate pair cannot be empty.");
            byte[] Encode(byte tag, byte[] data)
            {
                // Encode a tag and canonical length prefix around each DER payload.
                var length = new List<byte>();
                for (var size = data.Length; size > 0; size >>= 8) length.Insert(0, (byte)(size & 255));
                var prefix = data.Length < 128 ? new[] { tag, (byte)data.Length } :
                    new[] { tag, (byte)(128 | length.Count) }.Concat(length).ToArray();
                return prefix.Concat(data).ToArray();
            }
            // Wrap the optional forward and reverse certificates in a pair sequence.
            return Encode(0x30, (forward == null ? Array.Empty<byte>() : Encode(0xa0, forward))
                .Concat(reverse == null ? Array.Empty<byte>() : Encode(0xa1, reverse)).ToArray());
        }

        internal static byte[][] DecodePair(byte[] value)
        {
            // Track the current DER position while extracting certificate pair members.
            var offset = 0;
            byte[] Read(byte tag, byte[] bytes)
            {
                // Require the expected tag and decode its bounded DER length.
                if (offset + 2 > bytes.Length || bytes[offset++] != tag)
                    throw new ArgumentException("Invalid cross-certificate pair.");
                var length = (int)bytes[offset++];
                if ((length & 128) != 0)
                {
                    var count = length & 127;
                    if (count == 0 || count > 4 || offset + count > bytes.Length || bytes[offset] == 0)
                        throw new ArgumentException("Invalid cross-certificate pair length.");
                    long size = 0;
                    for (var i = 0; i < count; i++) size = (size << 8) | bytes[offset++];
                    if (size < 128 || size > bytes.Length - offset)
                        throw new ArgumentException("Invalid cross-certificate pair length.");
                    length = (int)size;
                }
                // Copy a nonempty member payload and advance past it.
                if (length == 0 || length > bytes.Length - offset)
                    throw new ArgumentException("Invalid cross-certificate pair length.");
                var result = bytes.Skip(offset).Take(length).ToArray();
                offset += length;
                return result;
            }
            // Validate the outer sequence and consume only supported pair directions.
            var content = Read(0x30, value);
            if (offset != value.Length) throw new ArgumentException("Trailing cross-certificate pair data.");
            offset = 0;
            var pair = new byte[2][];
            if (content[offset] == 0xa0) pair[0] = Read(0xa0, content);
            if (offset < content.Length && content[offset] == 0xa1) pair[1] = Read(0xa1, content);
            if (offset != content.Length || pair.All(part => part == null))
                throw new ArgumentException("Invalid cross-certificate pair members.");
            return pair;
        }
    }
}
