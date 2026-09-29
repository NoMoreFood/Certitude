//
// Copyright (c) Bryan Berns.
// Licensed under GPLv3. See LICENSE.md.
//

using System;
using System.Collections.Generic;
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
        public bool ExistingOnly => Id == "Enrollment";
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
    }

    internal sealed class PublishedCertificate
    {
        public PublishedStore Store { get; set; }
        public PublishedObject Object { get; set; }
        public byte[] Value { get; set; }
        public int Direction { get; set; } = -1;
        public InventoryCertificate Certificate { get; set; }
        public string Error { get; set; } = "";
        public string Fingerprint { get; set; }
        public string Subject => Certificate?.Subject ?? "Unreadable Certificate Value";
        public string Issuer => Certificate?.Issuer ?? "";
        public string Thumbprint => Certificate?.Thumbprint ?? Fingerprint;
        public DateTime? Expires => Certificate?.NotAfter;
        public string Status => Certificate?.Validity ?? "Unreadable";
        public string PairSide => Direction == 0 ? "Forward" : Direction == 1 ? "Reverse" : "";
        public string Key => Object.Id + "/" + Fingerprint + "/" + Direction;
    }

    internal sealed class PublishedSnapshot
    {
        public List<PublishedObject> Objects { get; } = new List<PublishedObject>();
        public List<PublishedCertificate> Certificates { get; } = new List<PublishedCertificate>();
        public string OidStatus { get; set; } = "";
    }

    internal sealed class PublicationPlan
    {
        public PublishedStore Store { get; set; }
        public PublishedObject Object { get; set; }
        public InventoryCertificate Certificate { get; set; }
        public string Server { get; set; }
        public string Review => "Domain Controller: " + Server + "\r\nStore: " + Store.Name +
            "\r\nDirectory Object: " + Object.DistinguishedName + "\r\n" +
            (Object.Id == Guid.Empty ? "Create A New Publication Object" : "Add To The Existing Publication Object") +
            "\r\n\r\n" + Store.Effect + "\r\n\r\n" + CertificateUtilities.Details(Certificate);
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
                "CA configuration and published templates stay unchanged.")
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

        internal string ParentName(PublishedStore store) => store.FixedObject ? ServicesName :
            "CN=" + store.Container + "," + ServicesName;

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
            DistinguishedName = entry.DistinguishedName
        };

        private static byte[][] Values(LdapConnection connection, SearchResultEntry entry, string attribute)
        {
            // Track object identity across ranged reads of a multivalued certificate attribute.
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
                        throw new InvalidOperationException("The directory returned an incomplete certificate list.");
                    return values.ToArray();
                }
                // Accumulate values and request the next range until the full attribute is read.
                values.AddRange(entry.Attributes[name].GetValues(typeof(byte[])).Cast<byte[]>());
                if (name.Equals(attribute, StringComparison.OrdinalIgnoreCase) || name.EndsWith("-*"))
                    return values.ToArray();
                var end = name.Substring(name.LastIndexOf('-') + 1);
                if (!int.TryParse(end, NumberStyles.None, CultureInfo.InvariantCulture, out var last) || last < next)
                    throw new InvalidOperationException("The directory returned an invalid certificate range.");
                next = checked(last + 1);
                entry = Entry(connection, entry.DistinguishedName, "objectGUID", attribute + ";range=" + next + "-*");
                if (entry == null)
                    throw new InvalidOperationException("The publication object was removed. Refresh again.");
            }
        }

        internal static PublishedCertificate[] Describe(PublishedStore store, PublishedObject target, byte[] value,
            OidNames names = null)
        {
            // Ignore the required-attribute placeholder and fingerprint real publication values.
            if (value.Length == 1 && value[0] == 0) return Array.Empty<PublishedCertificate>();
            string fingerprint;
            using (var hash = SHA256.Create())
                fingerprint = BitConverter.ToString(hash.ComputeHash(value)).Replace("-", "");
            PublishedCertificate Row(byte[] encoded, int direction)
            {
                // Describe a certificate while retaining its source value even if decoding fails.
                var row = new PublishedCertificate { Store = store, Object = target, Value = value,
                    Direction = direction, Fingerprint = fingerprint };
                try
                {
                    using var certificate = new X509Certificate2(encoded);
                    if (!certificate.RawData.SequenceEqual(encoded))
                        throw new CryptographicException("Invalid certificate data.");
                    row.Certificate = CertificateUtilities.Describe(certificate, names);
                }
                catch (CryptographicException error) { row.Error = CaAdministration.Error(error); }
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
                return new[] { new PublishedCertificate { Store = store, Object = target, Value = value,
                    Fingerprint = fingerprint, Error = error.Message } };
            }
        }

        public PublishedSnapshot Read(PublishedStore store)
        {
            // Prepare a paged search of the selected forest publication store.
            using var connection = Open();
            var names = Names;
            var snapshot = new PublishedSnapshot { OidStatus = names.Status };
            var filter = "(objectClass=" + store.ObjectClass + ")";
            if (store.FixedObject) filter = "(&" + filter + "(cn=NTAuthCertificates))";
            var request = new SearchRequest(ParentName(store), filter, SearchScope.OneLevel,
                "cn", "objectGUID", store.Attribute + ";range=0-499");
            var pages = new PageResultRequestControl(500);
            request.Controls.Add(pages);
            do
            {
                // Read each page, including all ranged certificate values for every object.
                SearchResponse response;
                try { response = (SearchResponse)connection.SendRequest(request); }
                catch (DirectoryOperationException error) when (error.Response?.ResultCode == ResultCode.NoSuchObject)
                { return snapshot; }
                foreach (SearchResultEntry entry in response.Entries)
                {
                    var target = DescribeObject(entry);
                    snapshot.Objects.Add(target);
                    foreach (var value in Values(connection, entry, store.Attribute))
                        snapshot.Certificates.AddRange(Describe(store, target, value, names));
                }
                pages.Cookie = response.Controls.OfType<PageResultResponseControl>().Single().Cookie;
            } while (pages.Cookie.Length > 0);

            // Sort the completed snapshot for stable object selection and certificate browsing.
            snapshot.Objects.Sort((a, b) => StringComparer.OrdinalIgnoreCase.Compare(a.Name, b.Name));
            snapshot.Certificates.Sort((a, b) => StringComparer.OrdinalIgnoreCase.Compare(a.Subject, b.Subject));
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

        public PublicationPlan Prepare(PublishedStore store, string objectName, byte[] encoded)
        {
            // Validate the certificate and resolve the intended publication object.
            var certificate = ValidateCertificate(store, encoded, Names);
            objectName = store.FixedObject ? "NTAuthCertificates" : (objectName ?? "").Trim();
            var name = "CN=" + EscapeName(objectName) + "," + ParentName(store);
            using var connection = Open();
            var entry = Entry(connection, name, "cn", "objectGUID", "objectClass", store.Attribute);

            // Check whether the destination can be created or must already have the expected class.
            if (entry == null && store.ExistingOnly)
                throw new InvalidOperationException("Select an existing enrollment service publication object.");
            if (entry != null && !entry.Attributes["objectClass"].GetValues(typeof(string)).Cast<string>()
                .Contains(store.ObjectClass, StringComparer.OrdinalIgnoreCase))
                throw new InvalidOperationException("The selected object is not a publication object for this store.");
            return new PublicationPlan { Store = store, Certificate = certificate, Server = Server,
                Object = entry == null ? new PublishedObject { Name = objectName, DistinguishedName = name } :
                    DescribeObject(entry) };
        }

        private SearchResultEntry Current(LdapConnection connection, PublishedStore store, PublishedObject expected)
        {
            // Recheck store membership and object identity immediately before a directory change.
            var name = "CN=" + EscapeName(expected.Name) + "," + ParentName(store);
            if (!name.Equals(expected.DistinguishedName, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("The publication object does not belong to the selected store.");
            var entry = Entry(connection, name, "cn", "objectGUID", "objectClass", store.Attribute);
            if ((entry == null) != (expected.Id == Guid.Empty) || (entry != null &&
                (DescribeObject(entry).Id != expected.Id || !entry.Attributes["objectClass"].GetValues(typeof(string))
                    .Cast<string>().Contains(store.ObjectClass, StringComparer.OrdinalIgnoreCase))))
                throw new InvalidOperationException("The publication object changed. Refresh and review again.");
            return entry;
        }

        public void Publish(PublicationPlan plan)
        {
            // Validate the reviewed plan against the current controller and certificate contents.
            if (plan.Server != Server)
                throw new ArgumentException("The publication plan belongs to another domain controller.");
            ValidateCertificate(plan.Store, plan.Certificate.Encoded);
            using var connection = Open();
            var entry = Current(connection, plan.Store, plan.Object);
            var value = plan.Store.Id == "CrossCA" ?
                EncodePair(plan.Certificate.Encoded, null) : plan.Certificate.Encoded;
            if (entry != null)
            {
                // Reject duplicates on an existing publication object before adding the value.
                var values = Values(connection, entry, plan.Store.Attribute);
                var certificates = values.SelectMany(bytes => Describe(plan.Store, plan.Object, bytes));
                if (certificates.Any(row => row.Certificate?.Encoded.SequenceEqual(plan.Certificate.Encoded) == true))
                    throw new InvalidOperationException("This certificate is already published on this object.");

                // Add the real certificate and remove an obsolete empty-value placeholder together.
                var update = new ModifyRequest(plan.Object.DistinguishedName,
                    DirectoryAttributeOperation.Add, plan.Store.Attribute, value);
                if (values.Any(bytes => bytes.Length == 1 && bytes[0] == 0))
                    update.Modifications.Add(Change(
                        plan.Store.Attribute, DirectoryAttributeOperation.Delete, new byte[1]));
                connection.SendRequest(update);
                return;
            }
            // Create a missing publication container only for stores that permit new objects.
            if (plan.Store.ExistingOnly) throw new InvalidOperationException("Select an existing enrollment service.");
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

        public void Remove(PublishedCertificate row)
        {
            // Revalidate the publication object and exact stored value before removing it.
            using var connection = Open();
            var entry = Current(connection, row.Store, row.Object);
            if (entry == null)
                throw new InvalidOperationException("The publication object was removed. Refresh again.");
            var values = Values(connection, entry, row.Store.Attribute);
            if (!values.Any(value => value.SequenceEqual(row.Value)))
                throw new InvalidOperationException("The published certificate changed. Refresh and review again.");

            // Remove the selected value while keeping required attributes populated.
            var request = new ModifyRequest(row.Object.DistinguishedName, DirectoryAttributeOperation.Delete,
                row.Store.Attribute, row.Value);
            if (row.Store.RequiredValue && values.Length == 1)
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
