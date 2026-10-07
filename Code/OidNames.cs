//
// Copyright (c) Bryan Berns.
// Licensed under GPLv3. See LICENSE.md.
//

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Globalization;
using System.Linq;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Certitude
{
    internal sealed class TemplateIdentity
    {
        public string Name { get; }
        public string DisplayName { get; }
        public string Oid { get; }
        public string Label { get; }

        public TemplateIdentity(string name, string displayName, string oid)
        {
            // Keep the template identities together and build a label without duplicate names.
            Name = name;
            DisplayName = displayName;
            Oid = oid;
            Label = DisplayName + (Name == DisplayName || Name.Length == 0 ? "" : " · " + Name) +
                (Oid.Length == 0 || Oid == DisplayName ? "" : " (" + Oid + ")");
        }
    }

    internal sealed class OidNames
    {
        private readonly Dictionary<string, Dictionary<uint, HashSet<string>>> names =
            new Dictionary<string, Dictionary<uint, HashSet<string>>>(StringComparer.Ordinal);
        private readonly ConcurrentDictionary<string, string> resolved = new ConcurrentDictionary<string, string>();
        private readonly Dictionary<string, TemplateIdentity> templates =
            new Dictionary<string, TemplateIdentity>(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, TemplateIdentity> templateCache =
            new ConcurrentDictionary<string, TemplateIdentity>(StringComparer.OrdinalIgnoreCase);
        private static readonly ConcurrentDictionary<string, string> windowsNames =
            new ConcurrentDictionary<string, string>(StringComparer.Ordinal);
        private static readonly ConcurrentDictionary<string, Lazy<OidNames>> catalogs =
            new ConcurrentDictionary<string, Lazy<OidNames>>(StringComparer.OrdinalIgnoreCase);
        private DateTime expires;
        private Func<OidNames> refresh;
        public static OidNames Local => Load();
        public static OidNames Windows { get; } = new OidNames();
        public string Status { get; private set; } = "Windows OID Names";
        public string Warning { get; private set; } = "";

        public static void Invalidate()
        {
            // Discard cached names after directory or local OID registrations change.
            catalogs.Clear();
            windowsNames.Clear();
            Windows.resolved.Clear();
            Windows.templateCache.Clear();
        }

        public OidNames Refresh() => refresh?.Invoke() ?? this;

        private static OidNames Cached(string key, Func<OidNames> read)
        {
            // Cache successful directory reads longer while allowing failed lookups to retry soon.
            Lazy<OidNames> Create() => new Lazy<OidNames>(() =>
            {
                var result = read();
                result.expires = DateTime.UtcNow.AddSeconds(result.Warning.Length == 0 ? 300 : 30);
                result.refresh = () => Cached(key, read);
                return result;
            });

            // Replace expired catalogs atomically so concurrent callers share one refresh.
            while (true)
            {
                var cached = catalogs.GetOrAdd(key, _ => Create());
                if (!cached.IsValueCreated || cached.Value.expires > DateTime.UtcNow) return cached.Value;
                var replacement = Create();
                if (catalogs.TryUpdate(key, replacement, cached)) return replacement.Value;
            }
        }

        [DllImport("crypt32.dll", CharSet = CharSet.Ansi, ExactSpelling = true)]
        private static extern IntPtr CryptFindOIDInfo(int keyType, string key, uint group);

        [DllImport("crypt32.dll", CharSet = CharSet.Unicode, EntryPoint = "CryptFindOIDInfo", ExactSpelling = true)]
        private static extern IntPtr FindNamedOid(int keyType, string key, uint group);

        [StructLayout(LayoutKind.Sequential)]
        private struct NativeOidInfo
        {
            public int Size;
            public IntPtr Oid;
            public IntPtr Name;
        }

        private static string WindowsName(string value, uint group) => windowsNames.GetOrAdd(group + ":" + value, _ =>
        {
            // Bulk directory reads below replace CryptoAPI's implicit per-OID LDAP lookups.
            var found = CryptFindOIDInfo(1, value, group | 0x80000000);
            return found == IntPtr.Zero ? value :
                Marshal.PtrToStringUni(Marshal.PtrToStructure<NativeOidInfo>(found).Name) ?? value;
        });

        private static string Text(SearchResult result, string name) =>
            result.Properties[name].Count == 0 ? "" : Convert.ToString(result.Properties[name][0]);

        private static DirectorySearcher Search(DirectoryEntry root, string filter, params string[] properties) =>
            new DirectorySearcher(root, filter, properties, SearchScope.Subtree)
            {
                PageSize = 1000, ClientTimeout = TimeSpan.FromSeconds(10),
                ServerTimeLimit = TimeSpan.FromSeconds(10), ReferralChasing = ReferralChasingOption.None
            };

        private static string Escape(string value) => value.Replace("\\", "\\5c").Replace("*", "\\2a")
            .Replace("(", "\\28").Replace(")", "\\29").Replace("\0", "\\00");

        private static OidDirectory DirectoryFor(string configuration)
        {
            // Try the current forest first when resolving the selected CA directory.
            OidDirectory directory = null;
            try { directory = OidDirectory.Connect(); }
            catch (Exception) { if (string.IsNullOrEmpty(configuration)) throw; }
            if (string.IsNullOrEmpty(configuration)) return directory;
            var parts = configuration.Split(new[] { '\\' }, 2);
            if (directory != null)
            {
                try
                {
                    // Reuse the current forest only when its enrollment entry matches this CA.
                    using var root = directory.Open("CN=Enrollment Services,CN=Public Key Services,CN=Services," +
                        directory.ConfigurationName);
                    using var search = Search(root, "(&(objectClass=pKIEnrollmentService)(cn=" + Escape(parts[1]) + "))",
                        "dNSHostName");
                    using var results = search.FindAll();
                    if (results.Cast<SearchResult>().Any(result =>
                        string.Equals(Text(result, "dNSHostName"), parts[0], StringComparison.OrdinalIgnoreCase) ||
                        (parts[0].IndexOf('.') < 0 && string.Equals(Text(result, "dNSHostName").Split('.')[0],
                            parts[0], StringComparison.OrdinalIgnoreCase)))) return directory;
                }
                catch (Exception) { }
            }
            // The CA can be a member server; bind LDAP to its domain, never to the CA host itself.
            var domain = CaDirectory.JoinedDomain(parts[0]);
            if (domain.Length == 0) throw new InvalidOperationException("The CA is not joined to a domain.");
            return OidDirectory.Connect(domain);
        }

        public static OidNames Load(string configuration = "") => Cached("CA:" + configuration,
            () => Read(() => DirectoryFor(configuration)));

        public static OidNames Load(OidDirectory directory) => Cached("Directory:" + directory.Server + ":" +
            directory.ConfigurationName, () => Read(() => directory));

        private static OidNames Read(Func<OidDirectory> connect)
        {
            // Fall back to Windows names with a visible warning when the directory is unavailable.
            var result = new OidNames();
            var issues = new List<string>();
            OidDirectory directory;
            try { directory = connect(); }
            catch (Exception error)
            {
                result.Warning = "Directory OID Names Unavailable · " + CaAdministration.Error(error);
                result.Status = result.Warning;
                return result;
            }
            // Load enterprise OID names in one search while preserving their usage groups.
            try
            {
                using var root = directory.Open(directory.ContainerName);
                using var search = Search(root, "(objectClass=msPKI-Enterprise-Oid)",
                    "msPKI-Cert-Template-OID", "displayName", "flags");
                using var rows = search.FindAll();
                foreach (SearchResult row in rows)
                {
                    // Associate each directory name with its policy or template category.
                    var oid = Text(row, "msPKI-Cert-Template-OID");
                    var name = Text(row, "displayName");
                    if (oid.Length == 0 || name.Length == 0) continue;
                    var flags = Text(row, "flags");
                    result.AddName(oid, name, flags == "1" ? 9U : flags == "2" ? 8U : flags == "3" ? 7U : 0U);
                    if (flags == "1") result.templates[oid] = new TemplateIdentity("", name, oid);
                }
            }
            catch (Exception error) { issues.Add("Policy OIDs: " + CaAdministration.Error(error)); }

            // Read template objects to resolve both database names and numeric template OIDs.
            try
            {
                using var root = directory.Open(directory.TemplatesName);
                using var search = Search(root, "(objectClass=pKICertificateTemplate)",
                    "cn", "displayName", "msPKI-Cert-Template-OID");
                using var rows = search.FindAll();
                foreach (SearchResult row in rows)
                {
                    // Index each template by name and OID, preferring its own display name.
                    var name = Text(row, "cn");
                    if (name.Length == 0) continue;
                    var display = Text(row, "displayName");
                    var template = new TemplateIdentity(name, display.Length == 0 ? name : display,
                        Text(row, "msPKI-Cert-Template-OID"));
                    result.templates[name] = template;
                    if (template.Oid.Length == 0) continue;
                    result.templates[template.Oid] = template;
                    result.AddName(template.Oid, template.DisplayName, 9);
                    result.names[template.Oid][9] = new HashSet<string> { template.DisplayName };
                }
            }
            catch (Exception error) { issues.Add("Templates: " + CaAdministration.Error(error)); }

            // Report partial directory failures without discarding names already loaded.
            result.Warning = string.Join(" · ", issues);
            result.Status = "OID Directory · " + directory.Server +
                (result.Warning.Length == 0 ? "" : " · " + result.Warning);
            return result;
        }

        public string Name(string oid, uint group = 0)
        {
            // Cache resolved labels by OID group, with Windows names as the fallback.
            if (string.IsNullOrEmpty(oid)) return "";
            return resolved.GetOrAdd(group + ":" + oid, _ =>
            {
                if (!names.TryGetValue(oid, out var groups)) return WindowsName(oid, group);
                IEnumerable<string> values = group == 0 ? groups.Values.SelectMany(items => items) :
                    groups.TryGetValue(group, out var exact) ? exact :
                    groups.TryGetValue(0, out var general) ? general : Enumerable.Empty<string>();
                var result = string.Join(" / ", values.Distinct().OrderBy(value => value, StringComparer.Ordinal));
                return result.Length == 0 ? WindowsName(oid, group) : result;
            });
        }

        private void AddName(string oid, string name, uint group)
        {
            // Retain distinct names per OID category instead of overwriting alternate labels.
            if (!names.TryGetValue(oid, out var groups)) names[oid] = groups = new Dictionary<uint, HashSet<string>>();
            if (!groups.TryGetValue(group, out var values)) groups[group] = values = new HashSet<string>();
            values.Add(name);
        }

        public string Describe(string oid, uint group = 0)
        {
            // Show a friendly name while retaining the numeric OID for identification.
            if (string.IsNullOrEmpty(oid)) return "";
            var name = Name(oid, group);
            return name == oid ? name : name + " (" + oid + ")";
        }

        public TemplateIdentity Template(string value)
        {
            // Use directory template identities or cache a fallback for unknown values.
            value ??= "";
            if (templates.TryGetValue(value, out var template)) return template;
            return templateCache.GetOrAdd(value, key =>
            {
                var numeric = key.Length > 0 && key.IndexOf('.') > 0 && key.All(c => c == '.' || c >= '0' && c <= '9');
                return new TemplateIdentity(numeric ? "" : key, numeric ? Name(key, 9) : key, numeric ? key : "");
            });
        }

        public string[] TemplateRestrictions(string value)
        {
            // Include locally registered template OIDs when expanding an exact search.
            var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { value };
            var localName = FindNamedOid(2, value, 0x80000009);
            if (localName != IntPtr.Zero)
                result.Add(Marshal.PtrToStringAnsi(Marshal.PtrToStructure<NativeOidInfo>(localName).Oid));

            // Add directory name and OID aliases that match the supplied template identity.
            foreach (var template in templates.Values.Distinct())
            {
                if (!new[] { template.Name, template.Oid, template.DisplayName }.Contains(
                    value, StringComparer.OrdinalIgnoreCase)) continue;
                result.Add(template.Name);
                result.Add(template.Oid);
            }
            // Remove empty aliases before they become CA query restrictions.
            result.Remove("");
            result.Remove(null);
            return result.ToArray();
        }

        public string FormatExtension(X509Extension extension)
        {
            // Choose an extension-specific decoder where generic formatting loses OID names.
            var oid = extension.Oid.Value;
            var bytes = extension.RawData;
            try
            {
                // Render dates embedded in certificates and CRLs in the same zone as their other timestamps.
                if (oid is "2.5.29.16" or "2.5.29.24")
                {
                    var position = 0;
                    var tag = ReadElement(bytes, ref position, bytes.Length, out var end);
                    string Date(int start, int finish)
                    {
                        if (!DateTime.TryParseExact(Encoding.ASCII.GetString(bytes, start, finish - start),
                            new[] { "yyyyMMddHHmmss'Z'", "yyyyMMddHHmmss.FFFFFFF'Z'" }, CultureInfo.InvariantCulture,
                            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var date))
                            throw new CryptographicException("Invalid extension date.");
                        return TimeDisplay.Stamp(date);
                    }
                    if (end != bytes.Length) throw new CryptographicException("Invalid date extension.");
                    if (oid == "2.5.29.24" && tag == 24) return Date(position, end);
                    if (oid != "2.5.29.16" || tag != 48)
                        throw new CryptographicException("Invalid date extension.");
                    var dates = new List<string>();
                    while (position < end)
                    {
                        tag = ReadElement(bytes, ref position, end, out var finish);
                        if (tag is not (128 or 129)) throw new CryptographicException("Invalid private-key date.");
                        dates.Add((tag == 128 ? "Not Before: " : "Not After: ") + Date(position, finish));
                        position = finish;
                    }
                    return string.Join(Environment.NewLine, dates);
                }
                if (oid == "1.3.6.1.4.1.311.20.2")
                {
                    // Decode the legacy template name and resolve it against the template catalog.
                    var position = 0;
                    var tag = ReadElement(bytes, ref position, bytes.Length, out var end);
                    if (tag != 30 || end != bytes.Length || (end - position) % 2 != 0)
                        throw new CryptographicException("Invalid template name extension.");
                    return Template(Encoding.BigEndianUnicode.GetString(bytes, position, end - position)).Label;
                }
                if (oid == "1.3.6.1.4.1.311.21.7")
                {
                    // Read the template identifier before its optional version numbers.
                    var position = 0;
                    if (ReadElement(bytes, ref position, bytes.Length, out var end) != 48 || end != bytes.Length ||
                        ReadElement(bytes, ref position, end, out var oidEnd) != 6)
                        throw new CryptographicException("Invalid template identifier extension.");
                    var text = new StringBuilder(Template(DecodeOid(bytes, position, oidEnd)).Label);
                    position = oidEnd;

                    // Append the template versions while validating their DER integer encodings.
                    foreach (var label in new[] { "Major Version", "Minor Version" })
                    {
                        if (position == end) break;
                        if (ReadElement(bytes, ref position, end, out var numberEnd) != 2 || position == numberEnd ||
                            (bytes[position] & 0x80) != 0) throw new CryptographicException("Invalid template version.");
                        var number = BigInteger.Zero;
                        for (; position < numberEnd; position++) number = number * 256 + bytes[position];
                        text.AppendLine().Append(label + ": " + number.ToString(CultureInfo.InvariantCulture));
                    }
                    if (position != end) throw new CryptographicException("Invalid template extension.");
                    return text.ToString();
                }
                // Resolve usage and policy identifiers in their appropriate OID groups.
                if (oid == "2.5.29.37")
                    return string.Join(Environment.NewLine, new X509EnhancedKeyUsageExtension(extension,
                        extension.Critical).EnhancedKeyUsages.Cast<Oid>().Select(usage => Describe(usage.Value, 7)));
                if (oid == "2.5.29.32" || oid == "1.3.6.1.4.1.311.21.10" || oid == "2.5.29.33")
                    return FormatPolicies(bytes, oid == "1.3.6.1.4.1.311.21.10" ? 7U : 8U, oid == "2.5.29.33");

                // Supplement Windows formatting with identifiers embedded in other extensions.
                var formatted = extension.Format(true);
                var registeredIdDepth = oid == "2.5.29.17" || oid == "2.5.29.18" || oid == "2.5.29.29" ? 1 :
                    oid == "1.3.6.1.5.5.7.1.1" || oid == "1.3.6.1.5.5.7.1.11" ? 2 : 0;
                var embedded = Identifiers(bytes, registeredIdDepth);
                return formatted + (embedded.Length == 0 ? "" : Environment.NewLine + "Object Identifiers:" +
                    Environment.NewLine + embedded);
            }
            catch (CryptographicException)
            {
                // Preserve undecodable extension data so the details remain inspectable.
                return "Unable To Decode Extension · DER (Base64): " + Convert.ToBase64String(bytes);
            }
        }

        private string FormatPolicies(byte[] bytes, uint group, bool mappings)
        {
            // Require a complete policy sequence before decoding its entries.
            var position = 0;
            if (ReadElement(bytes, ref position, bytes.Length, out var end) != 48 || end != bytes.Length || position == end)
                throw new CryptographicException("Invalid policy extension.");
            var text = new StringBuilder();
            while (position < end)
            {
                // Resolve the leading identifier for each policy or mapping entry.
                if (ReadElement(bytes, ref position, end, out var policyEnd) != 48 ||
                    ReadElement(bytes, ref position, policyEnd, out var oidEnd) != 6)
                    throw new CryptographicException("Invalid policy identifier.");
                var name = Describe(DecodeOid(bytes, position, oidEnd), group);
                position = oidEnd;
                if (mappings)
                {
                    // Render a mapping as its issuer and subject policy pair.
                    if (ReadElement(bytes, ref position, policyEnd, out oidEnd) != 6 || oidEnd != policyEnd)
                        throw new CryptographicException("Invalid policy mapping.");
                    text.AppendLine("Issuer Policy: " + name + " → Subject Policy: " +
                        Describe(DecodeOid(bytes, position, oidEnd), group));
                    position = oidEnd;
                    continue;
                }
                // Validate an optional qualifier sequence after the policy identifier.
                text.AppendLine("Policy: " + name);
                if (position == policyEnd) continue;
                if (ReadElement(bytes, ref position, policyEnd, out var qualifiersEnd) != 48 ||
                    qualifiersEnd != policyEnd || position == qualifiersEnd)
                    throw new CryptographicException("Invalid policy qualifiers.");
                while (position < qualifiersEnd)
                {
                    // Decode each qualifier name and value without losing their association.
                    if (ReadElement(bytes, ref position, qualifiersEnd, out var qualifierEnd) != 48 ||
                        ReadElement(bytes, ref position, qualifierEnd, out oidEnd) != 6)
                        throw new CryptographicException("Invalid policy qualifier.");
                    var qualifier = Describe(DecodeOid(bytes, position, oidEnd));
                    position = oidEnd;
                    var value = FormatQualifier(bytes, ref position, qualifierEnd, 0);
                    if (position != qualifierEnd) throw new CryptographicException("Invalid policy qualifier value.");
                    text.AppendLine("  " + qualifier + ": " + value);
                }
            }
            return text.ToString().TrimEnd();
        }

        private string FormatQualifier(byte[] bytes, ref int position, int end, int depth)
        {
            // Bound recursive decoding and isolate the current qualifier value.
            if (depth > 32) throw new CryptographicException("Policy qualifier nesting is too deep.");
            var start = position;
            var tag = ReadElement(bytes, ref position, end, out var valueEnd);
            var offset = position;
            position = valueEnd;
            var length = valueEnd - offset;

            // Render known qualifier primitives as readable names, text, or numbers.
            if (tag == 6) return Describe(DecodeOid(bytes, offset, valueEnd));
            if (tag == 12) return Encoding.UTF8.GetString(bytes, offset, length);
            if (tag == 19 || tag == 22 || tag == 26) return Encoding.ASCII.GetString(bytes, offset, length);
            if (tag == 30 && length % 2 == 0) return Encoding.BigEndianUnicode.GetString(bytes, offset, length);
            if (tag == 2 && length > 0)
            {
                var number = (bytes[offset] & 128) == 0 ? BigInteger.Zero : -BigInteger.One;
                while (offset < valueEnd) number = number * 256 + bytes[offset++];
                return number.ToString(CultureInfo.InvariantCulture);
            }
            if (tag == 48)
            {
                // Render nested qualifier sequences while preserving their grouping.
                var parts = new List<string>();
                while (offset < valueEnd) parts.Add(FormatQualifier(bytes, ref offset, valueEnd, depth + 1));
                return "(" + string.Join("; ", parts) + ")";
            }
            return "DER (Base64): " + Convert.ToBase64String(bytes, start, valueEnd - start);
        }

        public string Identifiers(byte[] encoded, int registeredIdDepth = 0)
        {
            // Collect distinct embedded OIDs and ignore data that cannot be parsed safely.
            var values = new List<string>();
            try { ReadOids(encoded, 0, encoded.Length, 0, values, registeredIdDepth); }
            catch (CryptographicException) { return ""; }
            return string.Join(Environment.NewLine, values.Distinct().Select(value => Describe(value)));
        }

        internal static string[] DnsNames(byte[] encoded)
        {
            // Decode individual DNS identities independently of localized extension formatting.
            var position = 0;
            if (ReadElement(encoded, ref position, encoded.Length, out var end) != 48 || end != encoded.Length)
                throw new CryptographicException("Invalid subject alternative names.");
            var names = new List<string>();
            while (position < end)
            {
                var tag = ReadElement(encoded, ref position, end, out var finish);
                if (tag == 130)
                {
                    // DNS entries are nonempty IA5 strings; other GeneralName types are skipped.
                    if (position == finish) throw new CryptographicException("Empty DNS name.");
                    for (var i = position; i < finish; i++)
                        if (encoded[i] < 33 || encoded[i] > 126)
                            throw new CryptographicException("Invalid DNS name.");
                    names.Add(Encoding.ASCII.GetString(encoded, position, finish - position));
                }
                position = finish;
            }
            return names.ToArray();
        }

        private static int ReadElement(byte[] bytes, ref int position, int end, out int valueEnd)
        {
            // Read the DER tag, including any extended tag-number bytes.
            if (position >= end) throw new CryptographicException("Truncated DER tag.");
            var tag = bytes[position++];
            if ((tag & 31) == 31)
            {
                do
                {
                    if (position >= end) throw new CryptographicException("Truncated DER tag.");
                } while ((bytes[position++] & 128) != 0);
            }
            // Decode short or long lengths while rejecting truncation and overflow.
            if (position >= end) throw new CryptographicException("Truncated DER length.");
            var length = (int)bytes[position++];
            if ((length & 128) != 0)
            {
                var count = length & 127;
                if (count == 0 || count > 4 || count > end - position)
                    throw new CryptographicException("Invalid DER length.");
                length = 0;
                for (var i = 0; i < count; i++)
                {
                    if (length > (int.MaxValue - bytes[position]) / 256)
                        throw new CryptographicException("Invalid DER length.");
                    length = length * 256 + bytes[position++];
                }
            }
            // Return only element boundaries that fit inside the enclosing DER value.
            if (length > end - position) throw new CryptographicException("Truncated DER value.");
            valueEnd = position + length;
            return tag;
        }

        private static void ReadOids(byte[] bytes, int position, int end, int depth, List<string> result, int registeredIdDepth)
        {
            // Walk constructed DER values with a nesting limit to discover embedded OIDs.
            if (depth > 32) throw new CryptographicException("DER nesting is too deep.");
            while (position < end)
            {
                var tag = ReadElement(bytes, ref position, end, out var valueEnd);
                if (tag == 6 || registeredIdDepth > 0 && depth == registeredIdDepth && tag == 136)
                    result.Add(DecodeOid(bytes, position, valueEnd));
                else if ((tag & 32) != 0) ReadOids(bytes, position, valueEnd, depth + 1, result, registeredIdDepth);
                position = valueEnd;
            }
        }

        private static string DecodeOid(byte[] bytes, int position, int end)
        {
            // Reject an empty identifier before decoding its numeric arcs.
            if (position == end) throw new CryptographicException("Empty OID.");
            var text = new StringBuilder();
            while (position < end)
            {
                // Read one base-128 arc without assuming it fits in a fixed-width integer.
                var arc = BigInteger.Zero;
                if (bytes[position] == 128) throw new CryptographicException("Invalid OID arc.");
                byte value;
                do
                {
                    if (position == end) throw new CryptographicException("Truncated OID.");
                    value = bytes[position++];
                    arc = arc * 128 + (value & 127);
                } while ((value & 128) != 0);

                // Split the first encoded arc into the two leading OID components.
                if (text.Length == 0)
                {
                    var first = arc < 40 ? 0 : arc < 80 ? 1 : 2;
                    text.Append(first);
                    arc -= first * 40;
                }
                text.Append('.').Append(arc.ToString(CultureInfo.InvariantCulture));
            }
            return text.ToString();
        }
    }
}
