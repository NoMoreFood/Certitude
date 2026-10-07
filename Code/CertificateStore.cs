//
// Copyright (c) Bryan Berns.
// Licensed under GPLv3. See LICENSE.md.
//

using Microsoft.Win32;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.DirectoryServices;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Certitude
{
    internal static class CaDirectory
    {
        internal const string AllAuthorities = "All CAs";

        internal static string[] Configurations(IEnumerable<string> configurations)
        {
            // Normalize usable CA connection names before building the selection list.
            var values = configurations.Where(value => !string.IsNullOrWhiteSpace(value)).Select(value => value.Trim())
                .Where(value => value.IndexOf('\\') > 0 && !value.EndsWith("\\") &&
                    value.IndexOfAny(new[] { '\r', '\n', '"' }) < 0)
                .Distinct(StringComparer.OrdinalIgnoreCase).ToArray();

            // Prefer a fully qualified host name when discovery also returns its short alias.
            return values.Where(value =>
            {
                var parts = value.Split('\\');
                return parts.Length != 2 || parts[0].Contains(".") || !values.Any(other =>
                    other.StartsWith(parts[0] + ".", StringComparison.OrdinalIgnoreCase) &&
                    other.EndsWith("\\" + parts[1], StringComparison.OrdinalIgnoreCase));
            }).OrderBy(value => value, StringComparer.OrdinalIgnoreCase).ToArray();
        }

        [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int NetGetJoinInformation(string server, out IntPtr name, out int status);
        [DllImport("Netapi32.dll")]
        private static extern int NetApiBufferFree(IntPtr buffer);

        internal static string JoinedDomain(string server)
        {
            // Read the server domain and release the native join-information buffer.
            var error = NetGetJoinInformation(server, out var name, out var status);
            try
            {
                if (error != 0) throw new Win32Exception(error);
                return status == 3 ? Marshal.PtrToStringUni(name) ?? "" : "";
            }
            finally { if (name != IntPtr.Zero) NetApiBufferFree(name); }
        }

        public static List<string> Discover()
        {
            // Skip directory discovery when this computer is not joined to a domain.
            var error = NetGetJoinInformation(null, out var name, out var status);
            try
            {
                if (error != 0) throw new System.ComponentModel.Win32Exception(error);
                if (status != 3) return new List<string>();
            }
            finally { if (name != IntPtr.Zero) NetApiBufferFree(name); }

            // Find published enterprise CAs in the forest configuration partition.
            using (var root = new DirectoryEntry("LDAP://RootDSE"))
            {
                var context = Convert.ToString(root.Properties["configurationNamingContext"].Value);
                using (var directory = new DirectoryEntry(
                    "LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services," + context))
                using (var search = new DirectorySearcher(directory, "(objectClass=pKIEnrollmentService)",
                    new[] { "cn", "dNSHostName" }, SearchScope.OneLevel)
                    { PageSize = 1000, ClientTimeout = TimeSpan.FromSeconds(10), ServerTimeLimit = TimeSpan.FromSeconds(10) })
                using (var results = search.FindAll())
                    return results.Cast<SearchResult>()
                        .Where(result => result.Properties["cn"].Count > 0 && result.Properties["dNSHostName"].Count > 0)
                        .Select(result => result.Properties["dNSHostName"][0] + "\\" + result.Properties["cn"][0])
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .OrderBy(value => value, StringComparer.OrdinalIgnoreCase).ToList();
            }
        }
    }

    public sealed class CertificateRow
    {
        public string Configuration { get; set; }
        public int RequestId { get; set; }
        public string CommonName { get; set; }
        public string[] DnsNames { get; set; }
        public string Requester { get; set; }
        public string Template { get; set; }
        internal TemplateIdentity ResolvedTemplate { get; set; }
        public string TemplateDisplayName => ResolvedTemplate?.DisplayName ?? Template;
        public string TemplateName => ResolvedTemplate?.Name ?? Template;
        public string TemplateOid => ResolvedTemplate?.Oid ?? "";
        public string TemplateLabel => ResolvedTemplate?.Label ?? Template;
        public string SerialNumber { get; set; }
        public DateTime? NotBefore { get; set; }
        public DateTime? NotAfter { get; set; }
        public int Disposition { get; set; }
        public int? RevocationReason { get; set; }
        public string Status => Disposition == 20 && NotAfter < DateTime.UtcNow ? "Expired" : State(Disposition);

        public static string State(int value)
        {
            // Translate native request dispositions into labels used across the interface.
            return value switch
            {
                8 => "Processing", 9 => "Pending", 12 => "Foreign certificate", 15 => "CA certificate",
                16 => "CA chain", 17 => "Recovery agent", 20 => "Issued", 21 => "Revoked", 30 => "Failed",
                31 => "Denied", _ => value.ToString(CultureInfo.InvariantCulture)
            };
        }
    }

    public enum SearchMatch
    {
        Contains, StartsWith, Exact
    }

    public sealed class QuerySpec
    {
        public int? Disposition { get; set; } = 20;
        public string[] Fields { get; set; } = new[] { "CommonName" };
        public string Field
        {
            get => Fields?.Length == 1 ? Fields[0] : null;
            set => Fields = value == "All" ? CertificateStore.SearchFields.ToArray() : new[] { value };
        }
        public bool ShouldSerializeField() => false;
        public string Value { get; set; } = "";
        public SearchMatch Match { get; set; } = SearchMatch.Exact;
        public DateTime? ExpiresFrom { get; set; }
        public DateTime? ExpiresBefore { get; set; }
        public int PageSize { get; set; } = 1000;

        public int? ExactId => Field == "RequestID" && Match == SearchMatch.Exact && Value.Length > 0 ?
            (int?)int.Parse(Value) : null;
        internal bool UsesIndexedFields => Match == SearchMatch.Exact && Value.Length > 0 && Fields.Length > 1 &&
            Fields.All(name => name is "CommonName" or "RequesterName" or "CertificateTemplate" or
                "SerialNumber" or "RequestID" or "Configuration");
        public bool UsesClientSearch => Value.Length > 0 && !UsesIndexedFields &&
            (Fields.Length != 1 || Field is "Configuration" or "Status" or "SubjectAlternativeName" ||
                Match != SearchMatch.Exact);

        internal bool SameFilter(QuerySpec other) => other != null && Disposition == other.Disposition &&
            Fields.Length == other.Fields.Length && Fields.All(other.Fields.Contains) &&
            Value == other.Value && Match == other.Match &&
            ExpiresFrom == other.ExpiresFrom && ExpiresBefore == other.ExpiresBefore;

        public void Validate()
        {
            // Reject unsupported filters and invalid bounds before opening a CA query.
            if (PageSize is < 1 or > 25000) throw new ArgumentException("Page size must be 1–25,000.");
            if (Fields == null || Fields.Length == 0 || Fields.Length > CertificateStore.SearchFields.Length ||
                Fields.Any(field => !CertificateStore.SearchFields.Contains(field)) ||
                Fields.Distinct().Count() != Fields.Length)
                throw new ArgumentException("Select one or more search fields.");
            if (!Enum.IsDefined(typeof(SearchMatch), Match)) throw new ArgumentException("Unknown search match mode.");
            if (Field == "RequestID" && Match == SearchMatch.Exact && Value.Length > 0 &&
                (!int.TryParse(Value, out var id) || id < 1))
                throw new ArgumentException("Enter a positive request ID.");
            if (ExpiresFrom.HasValue && ExpiresBefore.HasValue && ExpiresFrom >= ExpiresBefore)
                throw new ArgumentException("The expiry end date must be after the start date.");
        }

        public bool Matches(CertificateRow row)
        {
            // Apply disposition and exact expiry bounds before evaluating search text.
            if (Disposition.HasValue && row.Disposition != Disposition) return false;
            if (ExpiresFrom.HasValue && (!row.NotAfter.HasValue || row.NotAfter < ExpiresFrom)) return false;
            if (ExpiresBefore.HasValue && (!row.NotAfter.HasValue || row.NotAfter >= ExpiresBefore)) return false;
            if (Value.Length == 0) return true;
            if (ExactId.HasValue) return row.RequestId == ExactId.Value;

            // Match any selected field, including the resolved identities of templates.
            foreach (var field in Fields)
            {
                var matches = field switch
                {
                    "CommonName" => MatchesText(row.CommonName),
                    "SubjectAlternativeName" => row.DnsNames?.Any(MatchesText) == true,
                    "RequesterName" => MatchesText(row.Requester),
                    "CertificateTemplate" => MatchesTemplate(row),
                    "SerialNumber" => MatchesText(row.SerialNumber),
                    "RequestID" => MatchesText(row.RequestId.ToString(CultureInfo.InvariantCulture)),
                    "Configuration" => MatchesText(row.Configuration),
                    "Status" => MatchesText(row.Status),
                    _ => false
                };
                if (matches) return true;
            }
            return false;
        }

        internal bool MatchesTemplate(CertificateRow row) => MatchesText(row.Template) ||
            MatchesText(row.TemplateName) || MatchesText(row.TemplateDisplayName) || MatchesText(row.TemplateOid);

        internal bool MatchesText(string actual)
        {
            // Apply the chosen text match consistently without case sensitivity.
            if (actual == null) return false;
            if (Match == SearchMatch.Contains) return actual.IndexOf(Value, StringComparison.OrdinalIgnoreCase) >= 0;
            if (Match == SearchMatch.StartsWith) return actual.StartsWith(Value, StringComparison.OrdinalIgnoreCase);
            return string.Equals(actual, Value, StringComparison.OrdinalIgnoreCase);
        }
    }

    public sealed class CertificatePage
    {
        public List<CertificateRow> Rows { get; } = new List<CertificateRow>();
        public bool HasMore { get; set; }
    }

    public sealed class DetailValue
    {
        private string name;
        private string value;
        public string Name { get => name?.Replace("(UTC)", "(" + TimeDisplay.Current.Zone + ")"); set => name = value; }
        public DateTime? Time { get; set; }
        internal TimeReport Report { get; set; }
        public string Value
        {
            get => Time.HasValue ? TimeDisplay.Stamp(Time) : Report?.ToString() ?? value;
            set => this.value = value;
        }
    }

    public sealed class CertificateDetails
    {
        public string Configuration { get; set; }
        public List<DetailValue> Values { get; } = new List<DetailValue>();
        public byte[] Certificate { get; set; }
        internal OidNames Oids { get; set; }
    }

    public class CertificateStore
    {
        public static readonly string[] SearchFields =
        {
            "CommonName", "SubjectAlternativeName", "RequesterName", "CertificateTemplate", "SerialNumber",
            "RequestID", "Configuration", "Status"
        };
        private static readonly string[] Columns =
        {
            "RequestID", "CommonName", "RequesterName", "CertificateTemplate", "SerialNumber",
            "NotBefore", "NotAfter", "Request.Disposition", "Request.RevokedReason"
        };
        private static readonly ConcurrentDictionary<string, SemaphoreSlim> scanGates =
            new ConcurrentDictionary<string, SemaphoreSlim>(StringComparer.OrdinalIgnoreCase);

        public virtual string Configuration { get; }
        internal virtual bool IsAllAuthorities => false;
        internal virtual string SearchStatus => LoadedOids?.Status ?? "OID Names Not Loaded";
        private OidNames oidNames;
        internal OidNames Oids => oidNames = OidNames.Load(Configuration);
        internal OidNames LoadedOids => oidNames;

        public CertificateStore(string configuration)
        {
            // Require a usable server and CA name before retaining the connection target.
            if (string.IsNullOrWhiteSpace(configuration) || configuration.IndexOf('\\') < 1 ||
                configuration.EndsWith("\\") || configuration.IndexOfAny(new[] { '\r', '\n', '"' }) >= 0)
                throw new ArgumentException("Enter the CA as SERVER\\CA name.");
            Configuration = configuration;
        }

        public static string LocalConfiguration()
        {
            // Read the active local CA so startup can connect without manual selection.
            using (var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services\CertSvc\Configuration"))
            {
                var name = key?.GetValue("Active") as string;
                return string.IsNullOrEmpty(name) ? "" : Environment.MachineName + "\\" + name;
            }
        }

        internal virtual CertificateStore ForRow(CertificateRow row)
        {
            // Prevent a record from being acted on through the wrong CA connection.
            if (!string.IsNullOrEmpty(row.Configuration) &&
                !row.Configuration.Equals(Configuration, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("The record belongs to another certificate authority.");
            return this;
        }

        internal virtual string Apply(IReadOnlyList<CertificateRow> rows, string action, int reason,
            DateTime? effective, string attributes, CancellationToken token, Action<int> progress)
        {
            // Validate every record destination before submitting the requested operation.
            foreach (var row in rows) ForRow(row);
            token.ThrowIfCancellationRequested();
            return CaAdministration.Apply(Configuration, rows, action, reason, effective, attributes, token, progress);
        }

        internal virtual CertificatePage ReadBrowserPage(QuerySpec query, CertificateRow before,
            CancellationToken token) => ReadPage(query, before?.RequestId, token);

        public CertificatePage ReadPage(QuerySpec query, int? before, CancellationToken token)
            => ReadPage(query, before, token, null);

        private CertificatePage ReadPage(QuerySpec query, int? before, CancellationToken token, string[] fields)
        {
            // Validate the query before selecting the paging strategy.
            query.Validate();
            token.ThrowIfCancellationRequested();
            var page = new CertificatePage();
            if (query.UsesIndexedFields)
            {
                // Merge indexed field pages while retaining global newest-first order and distinct request IDs.
                var records = new Dictionary<int, CertificateRow>();
                foreach (var branch in ExactFieldQueries(query))
                {
                    var result = ReadPage(branch, before, token, fields);
                    page.HasMore |= result.HasMore;
                    foreach (var row in result.Rows) records[row.RequestId] = row;
                }
                page.HasMore |= records.Count > query.PageSize;
                page.Rows.AddRange(records.Values.OrderByDescending(row => row.RequestId).Take(query.PageSize));
                return page;
            }
            if (query.Match == SearchMatch.Exact && query.Value.Length > 0 &&
                (query.Field == "CommonName" || query.Field == "SerialNumber"))
            {
                // Let the CA use the selective field index instead of forcing a scan in RequestID order.
                var newest = new SortedSet<CertificateRow>(Comparer<CertificateRow>.Create(
                    (left, right) => CompareNewest(right, left)));
                foreach (var row in ReadRows(query, before, token, false, fields))
                {
                    newest.Add(row);
                    if (newest.Count > query.PageSize + 1) newest.Remove(newest.Min);
                }
                // Use the extra matching row to determine whether another page is available.
                page.Rows.AddRange(newest.Reverse().Take(query.PageSize));
                page.HasMore = newest.Count > query.PageSize;
                return page;
            }
            // Stop the ordered stream after collecting one page and detecting overflow.
            foreach (var row in ReadRows(query, before, token, true, fields))
            {
                if (page.Rows.Count == query.PageSize)
                {
                    page.HasMore = true;
                    break;
                }
                page.Rows.Add(row);
            }
            return page;
        }

        private IEnumerable<QuerySpec> ExactFieldQueries(QuerySpec query)
        {
            // A matching CA name covers every candidate, so additional OR branches cannot add records.
            var fields = query.Fields.Contains("Configuration") && query.MatchesText(Configuration) ?
                new[] { "Configuration" } : query.Fields;
            foreach (var field in fields)
            {
                // Text matching of IDs and serials cannot accept the native API's broader input conversions.
                if (field == "RequestID" && (!int.TryParse(query.Value, NumberStyles.None,
                    CultureInfo.InvariantCulture, out var id) || id < 1 ||
                    id.ToString(CultureInfo.InvariantCulture) != query.Value)) continue;
                if (field == "SerialNumber" && (query.Value.Length % 2 != 0 ||
                    query.Value.Any(value => !Uri.IsHexDigit(value)))) continue;
                yield return new QuerySpec
                {
                    Fields = new[] { field }, Value = query.Value, Match = SearchMatch.Exact,
                    Disposition = query.Disposition, ExpiresFrom = query.ExpiresFrom,
                    ExpiresBefore = query.ExpiresBefore, PageSize = query.PageSize
                };
            }
        }

        private IEnumerable<CertificateRow> ReadFieldPages(QuerySpec query, int? before,
            CancellationToken token, string[] fields)
        {
            // Page selective indexes without forcing them to scan the CA in request-ID order.
            while (true)
            {
                var page = ReadPage(query, before, token, fields);
                foreach (var row in page.Rows) yield return row;
                if (!page.HasMore) yield break;
                before = page.Rows.Last().RequestId;
            }
        }

        internal static int CompareNewest(CertificateRow left, CertificateRow right)
        {
            // Break equal request IDs by CA name to keep combined paging deterministic.
            var order = right.RequestId.CompareTo(left.RequestId);
            return order != 0 ? order : StringComparer.OrdinalIgnoreCase.Compare(
                left.Configuration, right.Configuration);
        }

        internal static CertificateRow[] SortRows(IEnumerable<CertificateRow> rows, string field,
            ListSortDirection direction, CancellationToken token)
        {
            // Freeze the current time so expiry-based status comparisons remain stable.
            token.ThrowIfCancellationRequested();
            var now = DateTime.UtcNow;
            var text = StringComparer.OrdinalIgnoreCase;
            string Status(CertificateRow row) => row.Disposition == 20 && row.NotAfter < now ?
                "Expired" : CertificateRow.State(row.Disposition);

            // Select a comparison that respects the displayed field and its value type.
            Comparison<CertificateRow> compare = field switch
            {
                nameof(CertificateRow.Configuration) => (left, right) => text.Compare(left.Configuration, right.Configuration),
                nameof(CertificateRow.RequestId) => (left, right) => left.RequestId.CompareTo(right.RequestId),
                nameof(CertificateRow.CommonName) => (left, right) => text.Compare(left.CommonName, right.CommonName),
                nameof(CertificateRow.Requester) => (left, right) => text.Compare(left.Requester, right.Requester),
                nameof(CertificateRow.Template) => (left, right) => text.Compare(left.TemplateDisplayName, right.TemplateDisplayName),
                nameof(CertificateRow.SerialNumber) => (left, right) => text.Compare(left.SerialNumber, right.SerialNumber),
                nameof(CertificateRow.Status) => (left, right) => text.Compare(Status(left), Status(right)),
                nameof(CertificateRow.NotBefore) => (left, right) => Nullable.Compare(left.NotBefore, right.NotBefore),
                nameof(CertificateRow.NotAfter) => (left, right) => Nullable.Compare(left.NotAfter, right.NotAfter),
                _ => throw new ArgumentException("Unknown sort column.")
            };
            // Sort a snapshot with a stable tie-breaker and honor cancellation around the work.
            var sorted = rows.ToArray();
            token.ThrowIfCancellationRequested();
            Array.Sort(sorted, (left, right) =>
            {
                var order = direction == ListSortDirection.Descending ? compare(right, left) : compare(left, right);
                return order != 0 ? order : CompareNewest(left, right);
            });
            token.ThrowIfCancellationRequested();
            return sorted;
        }

        public virtual IEnumerable<CertificateRow> ReadRows(QuerySpec query, int? before,
            CancellationToken token, bool ordered = true, string[] fields = null)
        {
            // Reject impossible cursor ranges before preparing the matching row streams.
            query.Validate();
            token.ThrowIfCancellationRequested();
            if (query.UsesIndexedFields)
            {
                // Stream each indexed branch directly for exports and client sorting, or merge ordered pages.
                var branches = ExactFieldQueries(query).ToArray();
                if (!ordered)
                {
                    var seen = new HashSet<int>();
                    foreach (var branch in branches)
                        foreach (var row in ReadRows(branch, before, token, false, fields))
                            if (seen.Add(row.RequestId)) yield return row;
                    yield break;
                }
                var fieldStreams = branches.Select(branch =>
                    ReadFieldPages(branch, before, token, fields).GetEnumerator()).ToArray();
                try
                {
                    var active = fieldStreams.Select(stream => stream.MoveNext()).ToArray();
                    while (true)
                    {
                        token.ThrowIfCancellationRequested();
                        var next = -1;
                        for (var i = 0; i < fieldStreams.Length; i++)
                            if (active[i] && (next < 0 ||
                                fieldStreams[i].Current.RequestId > fieldStreams[next].Current.RequestId)) next = i;
                        if (next < 0) yield break;
                        var row = fieldStreams[next].Current;
                        yield return row;
                        for (var i = 0; i < fieldStreams.Length; i++)
                            if (active[i] && fieldStreams[i].Current.RequestId == row.RequestId)
                                active[i] = fieldStreams[i].MoveNext();
                    }
                }
                finally { foreach (var stream in fieldStreams) stream.Dispose(); }
            }
            if (query.ExactId.HasValue && before.HasValue && query.ExactId.Value >= before.Value) yield break;
            if (query.Field == "Configuration" && query.Value.Length > 0 && !query.MatchesText(Configuration)) yield break;

            // Check the status index before an ordered query can scan every issued certificate for an empty view.
            if (query.Disposition is 9 or 30 or 31 &&
                !HasRows("Request.Disposition", query.Disposition.Value, token)) yield break;

            // Load directory names before the query only when template labels participate in filtering.
            var names = query.Value.Length > 0 && query.Fields.Contains("CertificateTemplate") ?
                Oids : null;
            token.ThrowIfCancellationRequested();

            // Include output and filter dependencies while always retaining IDs for ordering and scan bounds.
            var resultColumns = Columns;
            var resolveTemplates = true;
            if (fields != null)
            {
                var selected = fields.Select(ExportField.Find).ToArray();
                var required = new HashSet<string>(selected.SelectMany(field => field.Columns)) { "RequestID" };
                if (query.Disposition.HasValue) required.Add("Request.Disposition");
                if (query.ExpiresFrom.HasValue || query.ExpiresBefore.HasValue) required.Add("NotAfter");
                if (query.Value.Length > 0)
                {
                    required.UnionWith(query.Fields.Where(field =>
                        field is not ("Configuration" or "Status" or "SubjectAlternativeName")));
                    if (query.Fields.Contains("Status"))
                        required.UnionWith(new[] { "NotAfter", "Request.Disposition" });
                }
                resultColumns = Columns.Where(required.Contains).ToArray();
                resolveTemplates = names != null || selected.Any(field =>
                    field.Name.StartsWith("Template", StringComparison.Ordinal));
            }

            // Parallelize client-side scans unless the CA name alone already matches every candidate.
            if (query.UsesClientSearch && query.Field != "Configuration" &&
                (!query.Fields.Contains("Configuration") || !query.MatchesText(Configuration)))
            {
                foreach (var row in ReadScanRows(query, before, token, names, resultColumns, resolveTemplates))
                    yield return row;
                yield break;
            }

            // Expand exact template searches to their indexed name and OID representations.
            var restrictions = query.Field == "CertificateTemplate" && query.Match == SearchMatch.Exact &&
                query.Value.Length > 0 ? names.TemplateRestrictions(query.Value) : new[] { (string)null };

            // Rule out absent indexed values before opening an ordered requester or template stream.
            if (ordered && query.Match == SearchMatch.Exact && query.Value.Length > 0 &&
                query.Field is "RequesterName" or "CertificateTemplate" &&
                !restrictions.Any(value => HasRows(query.Field, value ?? query.Value, token))) yield break;
            var streams = restrictions.Select(value => ReadRowsCore(query, before, token, ordered, names,
                value, resultColumns, resolveTemplates).GetEnumerator()).ToArray();
            try
            {
                // Stream directly when no merge of ordered template results is necessary.
                if (!ordered || streams.Length == 1)
                {
                    foreach (var stream in streams)
                        while (stream.MoveNext()) yield return stream.Current;
                    yield break;
                }
                // Merge indexed template-name/OID queries without materializing the matching CA records.
                var active = streams.Select(stream => stream.MoveNext()).ToArray();
                while (true)
                {
                    token.ThrowIfCancellationRequested();
                    var next = -1;
                    for (var i = 0; i < streams.Length; i++)
                        if (active[i] && (next < 0 || streams[i].Current.RequestId > streams[next].Current.RequestId))
                            next = i;
                    if (next < 0) yield break;

                    // Emit each request once even when several template restrictions match it.
                    var row = streams[next].Current;
                    yield return row;
                    for (var i = 0; i < streams.Length; i++)
                        if (active[i] && streams[i].Current.RequestId == row.RequestId) active[i] = streams[i].MoveNext();
                }
            }
            finally { foreach (var stream in streams) stream.Dispose(); }
        }

        private bool HasRows(string field, object value, CancellationToken token)
        {
            // Select only a request ID and let the CA choose its field index without an ordering constraint.
            token.ThrowIfCancellationRequested();
            using var view = ComScope<ICertView>.Create("CertificateAuthority.View");
            view.Value.OpenConnection(Configuration);
            view.Value.SetResultColumnCount(1);
            view.Value.SetResultColumn(view.Value.GetColumnIndex(0, "RequestID"));
            Restrict(view.Value, field, 1, value);

            // Read one candidate without retrieving certificate metadata or caching an empty result.
            token.ThrowIfCancellationRequested();
            using var rows = new ComScope<ICertViewRow>(view.Value.OpenView());
            var found = rows.Value.Next() >= 0;
            token.ThrowIfCancellationRequested();
            return found;
        }

        internal virtual IEnumerable<CertificateRow> ReadRowsForSort(QuerySpec query, CancellationToken token)
        {
            // Preserve selective field and date indexes when collecting the complete matching set.
            query.Validate();
            token.ThrowIfCancellationRequested();
            if (IsAllAuthorities || query.Value.Length > 0 ||
                query.ExpiresFrom.HasValue || query.ExpiresBefore.HasValue)
                return ReadRows(query, null, token, false);
            if (query.Disposition.HasValue && !HasRows("Request.Disposition", query.Disposition.Value, token))
                return Enumerable.Empty<CertificateRow>();

            // Broad snapshots can collect primary-key ranges concurrently because the final sort defines order.
            return ReadScanRows(query, null, token, null, Columns, true, false);
        }

        private IEnumerable<CertificateRow> ReadScanRows(QuerySpec query, int? before,
            CancellationToken token, OidNames names, string[] resultColumns,
            bool resolveTemplates, bool ordered = true)
        {
            // Limit one expensive scan per CA so concurrent callers cannot multiply its four readers.
            var gate = scanGates.GetOrAdd(Configuration, _ => new SemaphoreSlim(1, 1));
            gate.Wait(token);
            try
            {
                // Keep quick pages on one reader and record the last candidate, including rejected rows.
                var budget = Math.Max(4096, query.PageSize + 1);
                var scanned = 0;
                var cursor = 0;
                var first = 0;
                var matched = 0;
                foreach (var row in ReadRowsCore(query, before, token, true, names, null,
                    resultColumns, resolveTemplates, 1, budget, id =>
                {
                    if (scanned == 0) first = id;
                    scanned++;
                    cursor = id;
                }))
                {
                    matched++;
                    yield return row;
                }
                if (scanned < budget || cursor <= 1) yield break;

                // Keep page scans near their cursor; unordered snapshots can drain larger ranges concurrently.
                const int readers = 4;
                var width = ordered ? Math.Min(262144, Math.Max(16384, (first - (long)cursor + 1) *
                    Math.Max(1, query.PageSize + 1 - matched) / Math.Max(1, matched) / readers)) :
                    (cursor - 1L + readers - 1) / readers;
                while (cursor > 1)
                {
                    using (var request = CancellationTokenSource.CreateLinkedTokenSource(token))
                    {
                        var buffers = Enumerable.Range(0, ordered ? readers : 1)
                            .Select(_ => new BlockingCollection<CertificateRow>(256)).ToArray();
                        var remaining = readers;
                        var workers = Enumerable.Range(0, readers).Select(partition => Task.Factory.StartNew(() =>
                        {
                            var upper = (int)Math.Max(1, cursor - partition * width);
                            var lower = (int)Math.Max(1, cursor - (partition + 1) * width);
                            try
                            {
                                // Each worker owns its COM objects and stops before entering the next range.
                                if (upper <= lower) return;
                                foreach (var row in ReadRowsCore(query, upper, request.Token, true, names,
                                    null, resultColumns, resolveTemplates, lower))
                                    buffers[ordered ? partition : 0].Add(row, request.Token);
                            }
                            catch (OperationCanceledException) when (request.IsCancellationRequested) { }
                            catch
                            {
                                request.Cancel();
                                throw;
                            }
                            finally
                            {
                                if (ordered || Interlocked.Decrement(ref remaining) == 0)
                                    buffers[ordered ? partition : 0].CompleteAdding();
                            }
                        }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default)).ToArray();
                        try
                        {
                            // Ordered pages consume adjacent ranges in sequence; snapshots consume any ready row.
                            foreach (var buffer in buffers)
                                foreach (var row in buffer.GetConsumingEnumerable(request.Token)) yield return row;
                            token.ThrowIfCancellationRequested();
                        }
                        finally
                        {
                            // Early page completion and faults must stop and join every producer before returning.
                            request.Cancel();
                            try { Task.WhenAll(workers).GetAwaiter().GetResult(); }
                            finally { foreach (var buffer in buffers) buffer.Dispose(); }
                        }
                    }
                    cursor = (int)Math.Max(1, cursor - width * readers);
                }
            }
            finally { gate.Release(); }
        }

        private IEnumerable<CertificateRow> ReadRowsCore(QuerySpec query, int? before, CancellationToken token,
            bool ordered, OidNames names, string templateRestriction, string[] resultColumns,
            bool resolveTemplates, int minimumId = 1,
            int maximumRows = int.MaxValue, Action<int> scanned = null)
        {
            // Open a narrow metadata view to avoid fetching certificate blobs while browsing.
            token.ThrowIfCancellationRequested();
            using (var scope = ComScope<ICertView>.Create("CertificateAuthority.View"))
            {
                var view = scope.Value;
                view.OpenConnection(Configuration);
                view.SetResultColumnCount(resultColumns.Length);
                foreach (var name in resultColumns) view.SetResultColumn(view.GetColumnIndex(0, name));

                // A sorted column can have only one restriction. The cursor is the sole RequestID bound.
                if (query.ExactId.HasValue) Restrict(view, "RequestID", 1, query.ExactId.Value);
                else Restrict(view, "RequestID", before.HasValue ? 2 : 16, before ?? 0, ordered ? 2 : 0);
                if (query.Disposition.HasValue) Restrict(view, "Request.Disposition", 1, query.Disposition.Value);
                if (query.Value.Length > 0 && !query.UsesClientSearch && !query.ExactId.HasValue)
                    Restrict(view, query.Field, 1, templateRestriction ?? query.Value);

                // CA date restrictions have minute precision; apply the exact UTC bounds to returned rows below.
                if (query.ExpiresFrom.HasValue)
                    Restrict(view, "NotAfter", 8, new DateTime(query.ExpiresFrom.Value.Ticks /
                        TimeSpan.TicksPerMinute * TimeSpan.TicksPerMinute, DateTimeKind.Utc));
                if (query.ExpiresBefore.HasValue && query.ExpiresBefore.Value.Ticks <=
                    DateTime.MaxValue.Ticks - TimeSpan.TicksPerMinute)
                    Restrict(view, "NotAfter", 2, new DateTime((query.ExpiresBefore.Value.Ticks +
                        TimeSpan.TicksPerMinute - 1) / TimeSpan.TicksPerMinute * TimeSpan.TicksPerMinute, DateTimeKind.Utc));

                // Prepare column lookup state once for the streamed result set.
                token.ThrowIfCancellationRequested();
                using (var rows = new ComScope<ICertViewRow>(view.OpenView()))
                {
                    var ordinals = new Dictionary<int, int>();
                    var searchColumn = query.UsesClientSearch ? Array.IndexOf(Columns, query.Field) : -1;
                    var searchSans = query.Value.Length > 0 && query.Fields.Contains("SubjectAlternativeName");
                    for (var read = 0; read < maximumRows; read++)
                    {
                        // Read one request at a time while keeping cancellation responsive.
                        token.ThrowIfCancellationRequested();
                        if (rows.Value.Next() < 0) yield break;
                        var row = new CertificateRow { Configuration = Configuration };
                        var rejected = false;
                        using (var columns = new ComScope<ICertViewColumn>(rows.Value.EnumCertViewColumn()))
                        {
                            int index;
                            while ((index = columns.Value.Next()) >= 0)
                            {
                                // Cache native column mappings instead of resolving names for every row.
                                if (!ordinals.TryGetValue(index, out var ordinal))
                                {
                                    var name = columns.Value.GetName();
                                    ordinal = Array.FindIndex(Columns, c => string.Equals(NormalizeColumn(c),
                                        NormalizeColumn(name), StringComparison.OrdinalIgnoreCase));
                                    ordinals[index] = ordinal;
                                }
                                // Enforce partition bounds before rejecting any selected search field.
                                if (ordinal < 0) continue;
                                var value = columns.Value.GetValue(1);
                                if (ordinal == 0)
                                {
                                    row.RequestId = Convert.ToInt32(value, CultureInfo.InvariantCulture);
                                    if (row.RequestId < 1)
                                        throw new InvalidOperationException("The CA returned no request ID for a row.");
                                    if (row.RequestId < minimumId) yield break;
                                    scanned?.Invoke(row.RequestId);
                                }
                                // Resolve template metadata alongside the raw value for display and filtering.
                                if (ordinal == 3)
                                {
                                    row.Template = Convert.ToString(value, CultureInfo.InvariantCulture);
                                    row.ResolvedTemplate = names?.Template(row.Template);
                                }
                                // Stop reading a row as soon as its selected search field fails to match.
                                if (ordinal == searchColumn && !(ordinal == 3 ? query.MatchesTemplate(row) :
                                    query.MatchesText(Convert.ToString(value, CultureInfo.InvariantCulture))))
                                {
                                    rejected = true;
                                    break;
                                }
                                // Convert the remaining native values into the lightweight browser row.
                                switch (ordinal)
                                {
                                    case 1: row.CommonName = Convert.ToString(value, CultureInfo.InvariantCulture); break;
                                    case 2: row.Requester = Convert.ToString(value, CultureInfo.InvariantCulture); break;
                                    case 4: row.SerialNumber = Convert.ToString(value, CultureInfo.InvariantCulture); break;
                                    case 5: row.NotBefore = UtcDate(value); break;
                                    case 6: row.NotAfter = UtcDate(value); break;
                                    case 7: row.Disposition = Convert.ToInt32(value, CultureInfo.InvariantCulture); break;
                                    case 8: row.RevocationReason = value == null || value == DBNull.Value ? null :
                                        (int?)Convert.ToInt32(value, CultureInfo.InvariantCulture); break;
                                }
                            }
                        }
                        // Enforce exact client-side bounds before exposing a complete matching record.
                        token.ThrowIfCancellationRequested();
                        if (row.RequestId < 1)
                            throw new InvalidOperationException("The CA returned no request ID for a row.");
                        if (rejected) continue;

                        // Read the SAN extension only when DNS names participate in a nonempty search.
                        if (searchSans) row.DnsNames = ReadDnsNames(rows.Value, token);
                        if (!query.Matches(row)) continue;

                        // Resolve display labels only for matching rows when the search does not need them.
                        if (resolveTemplates)
                        {
                            names ??= Oids;
                            row.ResolvedTemplate ??= names.Template(row.Template);
                        }
                        token.ThrowIfCancellationRequested();
                        yield return row;
                    }
                }
            }
        }

        private static string[] ReadDnsNames(ICertViewRow row, CancellationToken token)
        {
            // Enumerate the current request's extensions without retrieving the certificate blob.
            token.ThrowIfCancellationRequested();
            using var extensions = new ComScope<ICertViewExtension>(row.EnumCertViewExtension(0));
            while (extensions.Value.Next() >= 0)
            {
                token.ThrowIfCancellationRequested();
                if (extensions.Value.GetName() != "2.5.29.17" || (extensions.Value.GetFlags() & 2) != 0) continue;

                // Malformed SAN data cannot match, while CA access failures still propagate to the caller.
                try
                {
                    var encoded = Format(extensions.Value.GetValue(3, 1));
                    return OidNames.DnsNames(Convert.FromBase64String(encoded));
                }
                catch (Exception error) when (error is FormatException or CryptographicException)
                { return Array.Empty<string>(); }
            }
            return Array.Empty<string>();
        }

        internal static void Restrict(ICertView view, string name, int seek, object value, int sort = 0)
        {
            view.SetRestriction(view.GetColumnIndex(0, name), seek, sort, ref value);
        }

        private static DateTime? UtcDate(object value) => value is DateTime date ?
            (DateTime?)DateTime.SpecifyKind(date, DateTimeKind.Utc) : null;

        private static string NormalizeColumn(string name) => name.StartsWith("Request.",
            StringComparison.OrdinalIgnoreCase) ? name.Substring(8) : name;

        public virtual byte[] ReadCertificate(int requestId, CancellationToken token)
        {
            // Retrieve only the certificate blob when viewing or exporting an individual certificate.
            token.ThrowIfCancellationRequested();
            using var view = ComScope<ICertView>.Create("CertificateAuthority.View");
            view.Value.OpenConnection(Configuration);
            view.Value.SetResultColumnCount(1);
            view.Value.SetResultColumn(view.Value.GetColumnIndex(0, "RawCertificate"));
            Restrict(view.Value, "RequestID", 1, requestId);

            // Distinguish a deleted request from an existing request without an issued certificate.
            token.ThrowIfCancellationRequested();
            using var rows = new ComScope<ICertViewRow>(view.Value.OpenView());
            if (rows.Value.Next() < 0) throw new InvalidOperationException("This request no longer exists.");
            token.ThrowIfCancellationRequested();
            using var columns = new ComScope<ICertViewColumn>(rows.Value.EnumCertViewColumn());
            var value = columns.Value.Next() < 0 ? null : columns.Value.GetValue(1);
            token.ThrowIfCancellationRequested();
            return value is string encoded && encoded.Length > 0 ? Convert.FromBase64String(encoded) : null;
        }

        public virtual CertificateDetails ReadDetails(int requestId, CancellationToken token)
        {
            // Capture OID names and CA identity for a consistent details report.
            token.ThrowIfCancellationRequested();
            var names = Oids;
            var details = new CertificateDetails { Configuration = Configuration, Oids = names };
            details.Values.Add(new DetailValue { Name = "Certificate Authority", Value = Configuration });
            token.ThrowIfCancellationRequested();

            // Select all database columns because the details view exposes the full request.
            using (var scope = ComScope<ICertView>.Create("CertificateAuthority.View"))
            {
                var view = scope.Value;
                view.OpenConnection(Configuration);
                var count = view.GetColumnCount(0);
                view.SetResultColumnCount(count);
                using (var schema = new ComScope<ICertViewColumn>(view.EnumCertViewColumn(0)))
                {
                    int index;
                    while ((index = schema.Value.Next()) >= 0) view.SetResultColumn(index);
                }
                // Limit the lookup to the chosen request and detect records that were deleted.
                Restrict(view, "RequestID", 1, requestId);
                using (var rows = new ComScope<ICertViewRow>(view.OpenView()))
                {
                    token.ThrowIfCancellationRequested();
                    if (rows.Value.Next() < 0) throw new InvalidOperationException("This request no longer exists.");

                    // Retain raw fields and certificate bytes while adding a readable template name.
                    using (var columns = new ComScope<ICertViewColumn>(rows.Value.EnumCertViewColumn()))
                    {
                        while (columns.Value.Next() >= 0)
                        {
                            token.ThrowIfCancellationRequested();
                            var name = columns.Value.GetName();
                            var value = columns.Value.GetValue(1);
                            if (name == "RawCertificate" && value is string encoded && encoded.Length > 0)
                                details.Certificate = Convert.FromBase64String(encoded);
                            details.Values.Add(new DetailValue { Name = name, Value = Format(value),
                                Time = value is DateTime date ? TimeDisplay.Utc(date) : (DateTime?)null });
                            if (NormalizeColumn(name) == "CertificateTemplate")
                                details.Values.Add(new DetailValue { Name = "Resolved Certificate Template",
                                    Value = names.Template(Format(value)).Label });
                        }
                    }
                    // Append enrollment attributes that are stored outside the main request columns.
                    using (var attributes = new ComScope<ICertViewAttribute>(rows.Value.EnumCertViewAttribute(0)))
                    {
                        while (attributes.Value.Next() >= 0)
                        {
                            token.ThrowIfCancellationRequested();
                            details.Values.Add(new DetailValue
                            {
                                Name = "Attribute: " + attributes.Value.GetName(), Value = attributes.Value.GetValue()
                            });
                        }
                    }
                    // Preserve each extension OID, flags, and raw data for inspection or diagnosis.
                    using (var extensions = new ComScope<ICertViewExtension>(rows.Value.EnumCertViewExtension(0)))
                    {
                        while (extensions.Value.Next() >= 0)
                        {
                            token.ThrowIfCancellationRequested();
                            var oid = extensions.Value.GetName();
                            var flags = extensions.Value.GetFlags();
                            var encoded = Format(extensions.Value.GetValue(3, 1));
                            var name = "Extension: " + names.Describe(oid, 6) + " (Flags " + flags + ")";
                            details.Values.Add(new DetailValue { Name = name + " · DER (Base64)", Value = encoded });

                            // Add a decoded extension when its stored data can be interpreted.
                            try
                            {
                                var extension = new System.Security.Cryptography.X509Certificates.X509Extension(
                                    oid, Convert.FromBase64String(encoded), (flags & 1) != 0);
                                details.Values.Add(new DetailValue { Name = name,
                                    Report = new TimeReport().Append(() => names.FormatExtension(extension)) });
                            }
                            catch (FormatException) { }
                        }
                    }
                }
            }
            // Include OID resolution context and identifiers embedded in the certificate.
            details.Values.Add(new DetailValue { Name = "OID Resolution", Value = names.Status });
            if (details.Certificate != null)
                details.Values.Add(new DetailValue { Name = "Certificate Object Identifiers",
                    Value = names.Identifiers(details.Certificate) });
            return details;
        }

        public long Export(QuerySpec query, string path, CancellationToken token, Action<long> progress,
            string[] fields = null, Func<CertificateRow, bool> matches = null, bool overwrite = true,
            string[] conditionFields = null)
        {
            // Choose export columns and reject accidental replacement of an existing file.
            var utc = TimeDisplay.Current.UseUtc;
            var zone = utc ? "UTC" : "Local";
            var selected = ExportField.Select(fields ?? (IsAllAuthorities ?
                new[] { "Configuration" }.Concat(ExportField.Defaults).ToArray() : null));

            // Keep full rows for opaque predicates; otherwise include only output and known filter dependencies.
            var required = matches != null && conditionFields == null ? null :
                selected.Select(field => field.Name).Concat(conditionFields ?? Array.Empty<string>()).ToArray();
            if (!overwrite && File.Exists(path))
                throw new IOException("The output file already exists. Use --force to replace it.");

            // Write beside the destination so a failed/cancelled export never replaces an existing file.
            var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            long count = 0;
            try
            {
                using (var writer = new StreamWriter(temporary, false, new UTF8Encoding(true), 65536))
                {
                    // Write the appropriate headers for GUI defaults or explicitly selected fields.
                    writer.WriteLine(fields == null ? (IsAllAuthorities ? "Certificate authority," : "") +
                        "Request ID,Common name,Requester,Template,Serial number," +
                        $"Valid from ({zone}),Expires ({zone}),Status" :
                        string.Join(",", selected.Select(field => Csv(field.Name))));

                    // Stream matching records with the most selective available query order.
                    var ordered = fields == null || query.Match != SearchMatch.Exact || query.Value.Length == 0 ||
                        query.Field != "CommonName" && query.Field != "SerialNumber";
                    foreach (var row in ReadRows(query, null, token, ordered, required))
                    {
                        // Apply remaining export conditions and serialize only the requested fields.
                        if (matches != null && !matches(row)) continue;
                        writer.WriteLine(string.Join(",", selected.Select(field =>
                        {
                            var value = field.Read(row);
                            if (value is not DateTime date) return Csv(Format(value));
                            return Csv(fields != null ? date.ToString("o", CultureInfo.InvariantCulture) :
                                TimeDisplay.Stamp(date, utc));
                        })));
                        if (++count % 1000 == 0) progress?.Invoke(count);
                    }
                }
                // Publish the completed export only after cancellation has been checked.
                token.ThrowIfCancellationRequested();
                if (overwrite && File.Exists(path)) File.Replace(temporary, path, null);
                else File.Move(temporary, path);
                return count;
            }
            finally
            {
                // Remove any temporary output left by a failed or cancelled export.
                if (File.Exists(temporary)) File.Delete(temporary);
            }
        }

        internal CaStatistics ReadStatistics(CancellationToken token, Action<long> progress) =>
            CaStatistics.Read(Configuration, token, progress, Oids);

        internal CaServerStatistics ReadServerStatistics(CancellationToken token) =>
            CaServerStatistics.Read(Configuration, token, Oids);

        public static string Format(object value)
        {
            // Render native values consistently for details and CSV output.
            if (value is DateTime date) return TimeDisplay.Format(date,
                TimeDisplay.Current.UseUtc ? "yyyy-MM-dd HH:mm:ss" : "yyyy-MM-dd HH:mm:ss zzz");
            if (value is byte[] bytes) return Convert.ToBase64String(bytes);
            if (value is string[] lines) return string.Join(Environment.NewLine, lines);
            return Convert.ToString(value, CultureInfo.InvariantCulture) ?? "";
        }

        public static string Csv(string value)
        {
            // Escape CSV cells and keep spreadsheet programs from evaluating formulas.
            value ??= "";
            if (value.Length > 0 && "=+-@\t\r\n".IndexOf(value[0]) >= 0) value = "'" + value;
            return "\"" + value.Replace("\"", "\"\"") + "\"";
        }
    }

    internal sealed class AllCertificateStore : CertificateStore
    {
        private readonly CertificateStore[] authorities;
        private readonly ConcurrentDictionary<string, string> unavailable =
            new ConcurrentDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private const string NoAuthorities = "No CAs could be queried. Connect to All CAs again to retry.";
        public override string Configuration => CaDirectory.AllAuthorities;
        internal override bool IsAllAuthorities => true;
        internal int AuthorityCount => authorities.Length;
        internal int UnavailableCount => unavailable.Count;
        internal string UnavailableMessage => unavailable.IsEmpty ? "" : "Could not query these CAs: " +
            string.Join(", ", unavailable.Keys.OrderBy(name => name, StringComparer.OrdinalIgnoreCase)) +
            ". New queries skip these CAs. Connect to All CAs again to retry.";
        internal string UnavailableDetails => string.Join(Environment.NewLine, unavailable
            .OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase).Select(pair => pair.Key + ": " + pair.Value));
        internal override string SearchStatus =>
            $"{authorities.Length - unavailable.Count:N0} Of {authorities.Length:N0} CAs · " +
            string.Join(" · ", authorities.Where(source => !unavailable.ContainsKey(source.Configuration))
                .Select(source => source.Configuration + ": " + source.SearchStatus));

        internal AllCertificateStore(IEnumerable<CertificateStore> sources) : this(sources
            .GroupBy(source => source.Configuration, StringComparer.OrdinalIgnoreCase).Select(group => group.First())
            .OrderBy(source => source.Configuration, StringComparer.OrdinalIgnoreCase).ToArray()) { }

        private AllCertificateStore(CertificateStore[] sources) : base(sources.Length > 0 ? sources[0].Configuration :
            throw new ArgumentException("No CAs are available. Use Find CAs or connect to a CA first."))
        {
            authorities = sources;
        }

        internal override CertificateStore ForRow(CertificateRow row) => authorities.FirstOrDefault(source =>
            source.Configuration.Equals(row.Configuration, StringComparison.OrdinalIgnoreCase)) ??
            throw new InvalidOperationException("The record's certificate authority is not connected.");

        public override CertificateDetails ReadDetails(int requestId, CancellationToken token) =>
            throw new InvalidOperationException("Select a record and its certificate authority to load details.");

        public override byte[] ReadCertificate(int requestId, CancellationToken token) =>
            throw new InvalidOperationException("Select a record and its certificate authority to load a certificate.");

        internal override CertificatePage ReadBrowserPage(QuerySpec query, CertificateRow before,
            CancellationToken token)
        {
            // Query each available CA concurrently for the requested browser page.
            query.Validate();
            token.ThrowIfCancellationRequested();
            var pages = Task.WhenAll(authorities.Where(source => !unavailable.ContainsKey(source.Configuration))
                .Select(source => Task.Factory.StartNew(() =>
            {
                try
                {
                    // Adjust equal-ID boundaries using the CA name to avoid skipping records.
                    var bound = before?.RequestId;
                    if (before != null && StringComparer.OrdinalIgnoreCase.Compare(
                        source.Configuration, before.Configuration) > 0)
                        bound = before.RequestId == int.MaxValue ? null : (int?)(before.RequestId + 1);

                    // Tag returned records with their origin for later details and actions.
                    var page = source.ReadPage(query, bound, token);
                    foreach (var row in page.Rows) row.Configuration = source.Configuration;
                    return page;
                }
                catch (OperationCanceledException) { throw; }
                catch (Exception error)
                {
                    // Remember unreachable CAs so subsequent queries can use the remaining servers.
                    token.ThrowIfCancellationRequested();
                    unavailable.TryAdd(source.Configuration, CaAdministration.Error(error));
                    return null;
                }
            }, token, TaskCreationOptions.LongRunning, TaskScheduler.Default)))
                .GetAwaiter().GetResult().Where(page => page != null).ToArray();

            // Merge successful pages into one globally ordered page and preserve overflow.
            token.ThrowIfCancellationRequested();
            if (pages.Length == 0) throw new InvalidOperationException(NoAuthorities);
            var rows = SortRows(pages.SelectMany(page => page.Rows), nameof(CertificateRow.RequestId),
                ListSortDirection.Descending, token);
            var result = new CertificatePage { HasMore = rows.Length > query.PageSize || pages.Any(page => page.HasMore) };
            result.Rows.AddRange(rows.Take(query.PageSize));
            return result;
        }

        public override IEnumerable<CertificateRow> ReadRows(QuerySpec query, int? before,
            CancellationToken token, bool ordered = true, string[] fields = null)
        {
            // Start a cancellable query using only CAs still available in this selection.
            query.Validate();
            token.ThrowIfCancellationRequested();
            var sources = authorities.Where(source => !unavailable.ContainsKey(source.Configuration)).ToArray();
            if (sources.Length == 0) throw new InvalidOperationException(NoAuthorities);
            using (var request = CancellationTokenSource.CreateLinkedTokenSource(token))
            {
                // Use per-CA queues for ordered merging or one shared queue for direct streaming.
                var buffers = Enumerable.Range(0, ordered ? sources.Length : 1)
                    .Select(_ => new BlockingCollection<CertificateRow>(256)).ToArray();
                var remaining = sources.Length;

                // Keep each COM enumerator on its own worker; bounded buffers limit read-ahead.
                var workers = sources.Select((source, index) => Task.Factory.StartNew(() =>
                {
                    var buffer = buffers[ordered ? index : 0];
                    var readAny = false;
                    try
                    {
                        // Feed records into bounded queues while retaining their originating CA.
                        foreach (var row in source.ReadRows(query, before, request.Token, ordered, fields))
                        {
                            row.Configuration = source.Configuration;
                            readAny = true;
                            buffer.Add(row, request.Token);
                        }
                    }
                    catch (OperationCanceledException) { request.Cancel(); }
                    catch (Exception error)
                    {
                        // Tolerate connection failures only before that CA has emitted any records.
                        if (request.IsCancellationRequested) return;
                        if (!readAny)
                        {
                            unavailable.TryAdd(source.Configuration, CaAdministration.Error(error));
                            return;
                        }
                        // A failure after rows were emitted must not turn an incomplete export into a success.
                        request.Cancel();
                        throw new InvalidOperationException(source.Configuration + ": " +
                            CaAdministration.Error(error), error);
                    }
                    finally
                    {
                        // Close the queue when its producer, or all shared producers, have finished.
                        if (ordered || Interlocked.Decrement(ref remaining) == 0) buffer.CompleteAdding();
                    }
                }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default)).ToArray();

                // Expose buffered worker results through disposable consumer enumerators.
                var streams = buffers.Select(buffer => buffer.GetConsumingEnumerable(request.Token).GetEnumerator())
                    .ToArray();
                try
                {
                    // Return unordered results immediately as any CA produces them.
                    if (!ordered)
                    {
                        while (streams[0].MoveNext()) yield return streams[0].Current;
                    }
                    else
                    {
                        // Merge the head of each CA stream to preserve global request ordering.
                        var active = streams.Select(stream => stream.MoveNext()).ToArray();
                        while (true)
                        {
                            request.Token.ThrowIfCancellationRequested();
                            var next = -1;
                            for (var i = 0; i < streams.Length; i++)
                                if (active[i] && (next < 0 ||
                                    CompareNewest(streams[i].Current, streams[next].Current) < 0)) next = i;
                            if (next < 0) break;
                            yield return streams[next].Current;
                            active[next] = streams[next].MoveNext();
                        }
                    }
                    // Distinguish an empty result from cancellation or total connection failure.
                    token.ThrowIfCancellationRequested();
                    if (unavailable.Count == authorities.Length) throw new InvalidOperationException(NoAuthorities);
                }
                finally
                {
                    // Stop producers and release all queues even when the caller ends enumeration early.
                    request.Cancel();
                    foreach (var stream in streams) stream.Dispose();
                    try { Task.WhenAll(workers).GetAwaiter().GetResult(); }
                    finally { foreach (var buffer in buffers) buffer.Dispose(); }
                }
            }
        }

        internal override string Apply(IReadOnlyList<CertificateRow> rows, string action, int reason,
            DateTime? effective, string attributes, CancellationToken token, Action<int> progress)
        {
            // Resolve every record to its CA before applying any grouped changes.
            var groups = rows.GroupBy(ForRow).ToArray();
            var report = new StringBuilder();
            var completed = 0;
            foreach (var group in groups)
            {
                if (token.IsCancellationRequested) break;
                var selected = group.ToArray();
                try
                {
                    // Apply each CA group while reporting progress across the whole selection.
                    report.AppendLine(group.Key.Apply(selected, action, reason, effective, attributes, token,
                        count => progress?.Invoke(completed + count)));
                }
                catch (OperationCanceledException) { break; }
                catch (Exception error)
                {
                    // Record a failed CA group and allow later groups to continue.
                    report.AppendLine(action + " on " + group.Key.Configuration + ": FAILED — " +
                        CaAdministration.Error(error) + "\r\nRequest IDs: " +
                        string.Join(", ", selected.Select(row => row.RequestId)));
                }
                // Advance overall progress only after the current CA group completes.
                if (token.IsCancellationRequested) break;
                completed += selected.Length;
                progress?.Invoke(completed);
            }
            // Make partial completion explicit when cancellation stops further changes.
            if (token.IsCancellationRequested)
                report.AppendLine("Cancelled. Completed CA changes remain applied; " +
                    "remaining records were not attempted.");
            return report.ToString();
        }
    }
}
