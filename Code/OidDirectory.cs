//
// Copyright (c) Bryan Berns.
// Licensed under GPLv3. See LICENSE.md.
//

using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Globalization;
using System.Linq;

namespace Certitude
{
    internal sealed class DirectoryOid
    {
        public Guid Id { get; set; }
        public string Name { get; set; }
        public string Value { get; set; }
        public int Flags { get; set; }
        public string DistinguishedName { get; set; }
        public string GroupLink { get; set; }
        public string[] LocalizedNames { get; set; } = Array.Empty<string>();
        public string[] PolicyStatements { get; set; } = Array.Empty<string>();
        public string[] Templates { get; set; } = Array.Empty<string>();
        public bool Protected { get; set; }
        public string Kind => Flags == 1 ? "Certificate Template" : Flags == 2 ? "Issuance Policy" :
            Flags == 3 ? "Application Policy" : "Other / Forest OID";
        public int TemplateCount => Templates.Length;
        public string RemovalBlock => Protected || (Flags != 2 && Flags != 3) ? "This OID Is Read Only." :
            !string.IsNullOrEmpty(GroupLink) ? "This Policy Is Linked To An AD Group." :
            Templates.Length > 0 ? "This OID Is Referenced By Certificate Templates." : "";
        public bool CanRemove => RemovalBlock.Length == 0;
    }

    internal sealed class OidDirectory
    {
        internal static readonly string[] TemplateAttributes = { "msPKI-Cert-Template-OID",
            "msPKI-Certificate-Policy", "msPKI-Certificate-Application-Policy", "pKIExtendedKeyUsage",
            "msPKI-RA-Policies", "msPKI-RA-Application-Policies" };
        private static readonly string[] OidAttributes = { "objectGUID", "cn", "displayName", "flags",
            "distinguishedName", "msPKI-Cert-Template-OID", "msDS-OIDToGroupLink", "isCriticalSystemObject",
            "systemFlags", "msPKI-OIDLocalizedName", "msPKI-OID-CPS" };
        public string Server { get; }
        public string ConfigurationName { get; }
        public string ContainerName => "CN=OID,CN=Public Key Services,CN=Services," + ConfigurationName;
        internal string TemplatesName => "CN=Certificate Templates,CN=Public Key Services,CN=Services," +
            ConfigurationName;

        private OidDirectory(string server, string configuration)
        {
            // Retain the resolved controller and forest partition for subsequent directory operations.
            Server = server;
            ConfigurationName = configuration;
        }

        public static OidDirectory Connect(string target = "")
        {
            // Validate the target as a DNS name before constructing an LDAP binding.
            target = (target ?? "").Trim();
            if (target.Length > 0 && Uri.CheckHostName(target) != UriHostNameType.Dns)
                throw new ArgumentException("Enter a domain or domain controller DNS name, without an LDAP path.");

            // Resolve a controller and configuration partition from the target directory.
            using var root = new DirectoryEntry("LDAP://" + (target.Length == 0 ? "" : target + "/") + "RootDSE");
            var server = Convert.ToString(root.Properties["dnsHostName"].Value);
            var configuration = Convert.ToString(root.Properties["configurationNamingContext"].Value);
            if (string.IsNullOrEmpty(server) || string.IsNullOrEmpty(configuration))
                throw new InvalidOperationException("The target did not provide an Active Directory forest.");
            return new OidDirectory(server, configuration);
        }

        internal DirectoryEntry Open(string name) => new DirectoryEntry("LDAP://" + Server + "/" + name);

        private static DirectorySearcher Search(DirectoryEntry root, string filter, string[] attributes) =>
            new DirectorySearcher(root, filter, attributes, SearchScope.Subtree)
            {
                PageSize = 1000, ClientTimeout = TimeSpan.FromSeconds(30),
                ServerTimeLimit = TimeSpan.FromSeconds(30), ReferralChasing = ReferralChasingOption.None
            };

        private static string Text(SearchResult result, string name) =>
            result.Properties[name].Count == 0 ? "" : Convert.ToString(result.Properties[name][0]);

        // Project directory attributes into the policy metadata and removal safeguards shown in the UI.
        private static DirectoryOid ReadOid(SearchResult result) => new DirectoryOid
        {
            Id = new Guid((byte[])result.Properties["objectGUID"][0]),
            Name = string.IsNullOrEmpty(Text(result, "displayName")) ? Text(result, "cn") : Text(result, "displayName"),
            Value = Text(result, "msPKI-Cert-Template-OID"),
            Flags = int.TryParse(Text(result, "flags"), out var flags) ? flags : 0,
            DistinguishedName = Text(result, "distinguishedName"), GroupLink = Text(result, "msDS-OIDToGroupLink"),
            LocalizedNames = result.Properties["msPKI-OIDLocalizedName"].Cast<string>().ToArray(),
            PolicyStatements = result.Properties["msPKI-OID-CPS"].Cast<string>().ToArray(),
            Protected = string.Equals(Text(result, "isCriticalSystemObject"), "True",
                StringComparison.OrdinalIgnoreCase) ||
                (long.TryParse(Text(result, "systemFlags"), out var systemFlags) && (systemFlags & 0x80000000L) != 0)
        };

        public DirectoryOid[] Read()
        {
            // Load forest OID registrations before finding their template references.
            using var container = Open(ContainerName);
            using var search = Search(container, "(objectClass=msPKI-Enterprise-Oid)", OidAttributes);
            using var results = search.FindAll();
            var rows = results.Cast<SearchResult>().Select(ReadOid).ToArray();

            // Read every template attribute that can refer to a policy or template OID.
            var references = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);
            using var templates = Open(TemplatesName);
            using var templateSearch = Search(templates, "(objectClass=pKICertificateTemplate)",
                TemplateAttributes.Concat(new[] { "cn", "displayName" }).ToArray());
            using var templateResults = templateSearch.FindAll();
            foreach (SearchResult result in templateResults)
            {
                // Record readable template names and the attributes that reference each OID.
                var name = Text(result, "cn");
                var display = Text(result, "displayName");
                if (display.Length > 0 && display != name) name = display + " (" + name + ")";
                foreach (var attribute in TemplateAttributes)
                    foreach (string oid in result.Properties[attribute])
                    {
                        if (!references.TryGetValue(oid, out var names))
                            references[oid] = names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                        names.Add(name + " · " + attribute);
                    }
            }
            // Attach reference lists and return registrations in display order.
            foreach (var row in rows)
                if (references.TryGetValue(row.Value, out var names))
                    row.Templates = names.OrderBy(name => name, StringComparer.OrdinalIgnoreCase).ToArray();
            return rows.OrderBy(row => row.Name, StringComparer.OrdinalIgnoreCase).ThenBy(row => row.Value).ToArray();
        }

        internal static string ValidateValue(string value)
        {
            // Validate numeric OID arcs before using the value in directory operations.
            value = (value ?? "").Trim();
            var arcs = value.Split('.');
            if (arcs.Length < 2 || arcs.Any(arc => arc.Length == 0 || arc.Any(c => c < '0' || c > '9') ||
                (arc.Length > 1 && arc[0] == '0')) || (arcs[0] != "0" && arcs[0] != "1" && arcs[0] != "2") ||
                (arcs[0] != "2" && (arcs[1].Length > 2 || int.Parse(arcs[1], CultureInfo.InvariantCulture) > 39)))
                throw new ArgumentException("Enter a numeric OID such as 1.3.6.1.4.1.55555.1, without leading zeros. " +
                    "The first number must be 0, 1 or 2; the second must be at most 39 when the first is 0 or 1.");
            return value;
        }

        public Guid Add(string name, string value, int flags)
        {
            // Require a valid OID, display name, and supported custom policy type.
            value = ValidateValue(value);
            name = (name ?? "").Trim();
            if (name.Length == 0 || name.Length > 256 || name.Any(char.IsControl) || (flags != 2 && flags != 3))
                throw new ArgumentException("Enter a display name of 1–256 characters and select an application or " +
                    "issuance policy.");

            // Reject duplicate forest registrations before creating a new directory object.
            using var container = Open(ContainerName);
            using var search = Search(container,
                "(&(objectClass=msPKI-Enterprise-Oid)(msPKI-Cert-Template-OID=" + value + "))", new[] { "cn" });
            if (search.FindOne() != null)
                throw new InvalidOperationException("This OID already exists in the forest. Refresh to review it.");

            // Persist the custom policy and invalidate cached OID labels.
            using var entry = container.Children.Add("CN=" + Guid.NewGuid().ToString("N"), "msPKI-Enterprise-Oid");
            entry.Properties["displayName"].Value = name;
            entry.Properties["msPKI-Cert-Template-OID"].Value = value;
            entry.Properties["flags"].Value = flags;
            entry.CommitChanges();
            OidNames.Invalidate();
            return entry.Guid;
        }

        public void Remove(DirectoryOid expected)
        {
            // Recheck identity and removal restrictions against current directory contents.
            if (expected == null) throw new ArgumentException("Select an OID to remove.");
            var current = Read().SingleOrDefault(row => row.Id == expected.Id);
            if (current == null || current.Value != expected.Value || current.Flags != expected.Flags ||
                current.Name != expected.Name)
                throw new InvalidOperationException(
                    "The selected OID changed or was removed. Refresh and review it again.");
            if (!current.CanRemove) throw new InvalidOperationException(current.RemovalBlock);

            // Verify the bound object before removing it and invalidating cached names.
            using var entry = Open(current.DistinguishedName);
            if (entry.Guid != current.Id)
                throw new InvalidOperationException("The selected OID changed. Refresh and review it again.");
            using var parent = entry.Parent;
            parent.Children.Remove(entry);
            OidNames.Invalidate();
        }
    }
}
