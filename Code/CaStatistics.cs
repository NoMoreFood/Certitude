//
// Copyright (c) Bryan Berns.
// Licensed under GPLv3. See LICENSE.md.
//

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Net.NetworkInformation;
using System.Security.Cryptography.X509Certificates;
using System.Threading;

namespace Certitude
{
    internal sealed class StatisticsRecord
    {
        public CertificateRow Certificate { get; set; }
        public DateTime? Submitted { get; set; }
        public DateTime? Resolved { get; set; }
        public int? RequestType { get; set; }
    }

    internal sealed class StatisticsGroup
    {
        public string Name { get; set; }
        public long Count { get; set; }
        public long Issued { get; set; }
        public long Revoked { get; set; }
        public long Expired { get; set; }
        public long DueSoon { get; set; }
        public double Percent { get; set; }
    }

    internal sealed class CaStatistics
    {
        public DateTime AsOf { get; private set; }
        public TimeSpan Elapsed { get; private set; }
        public long Total { get; private set; }
        public long Valid { get; private set; }
        public long Expired { get; private set; }
        public long Future { get; private set; }
        public long MissingValidity { get; private set; }
        public long[] Expiry { get; } = new long[5];
        public long[] Recent { get; } = new long[3];
        public int? FirstId { get; private set; }
        public int? LastId { get; private set; }
        public DateTime? FirstSubmission { get; private set; }
        public DateTime? LastSubmission { get; private set; }
        public DateTime? OldestPending { get; private set; }
        public long MissingSubmission { get; private set; }
        public long TimedResolutions { get; private set; }
        public double ResolutionSeconds { get; private set; }
        public double LongestResolutionSeconds { get; private set; }
        public long DatedCertificates { get; private set; }
        public double ValidityDays { get; private set; }
        public int TemplateCount { get; private set; }
        public int RequesterCount { get; private set; }
        public Dictionary<int, long> Dispositions { get; } = new Dictionary<int, long>();
        public StatisticsGroup[] Templates { get; private set; }
        public StatisticsGroup[] Requesters { get; private set; }
        private StatisticsGroup[] utcMonths;
        private StatisticsGroup[] localMonths;
        public StatisticsGroup[] Months => TimeDisplay.Current.UseUtc ? utcMonths : localMonths;
        public StatisticsGroup[] Types { get; private set; }
        public StatisticsGroup[] Reasons { get; private set; }
        public long Count(int disposition) => Dispositions.TryGetValue(disposition, out var value) ? value : 0;

        internal static CaStatistics Read(string configuration, CancellationToken token, Action<long> progress,
            OidNames names = null) => Aggregate(ReadRecords(configuration, token, names ?? OidNames.Load(configuration)),
                DateTime.UtcNow, token, progress);

        internal static CaStatistics Aggregate(IEnumerable<StatisticsRecord> records, DateTime now,
            CancellationToken token, Action<long> progress)
        {
            // Initialize aggregate counters and grouping tables for one consistent snapshot time.
            token.ThrowIfCancellationRequested();
            var watch = Stopwatch.StartNew();
            var result = new CaStatistics { AsOf = now };
            var templates = new Dictionary<string, StatisticsGroup>(StringComparer.OrdinalIgnoreCase);
            var requesters = new Dictionary<string, StatisticsGroup>(StringComparer.OrdinalIgnoreCase);
            var months = new Dictionary<string, StatisticsGroup>();
            var localMonths = new Dictionary<string, StatisticsGroup>();
            var types = new Dictionary<string, StatisticsGroup>();
            var reasons = new Dictionary<string, StatisticsGroup>();
            foreach (var record in records)
            {
                // Count each request disposition and expand the observed request ID range.
                token.ThrowIfCancellationRequested();
                var row = record.Certificate;
                result.Total++;
                result.Dispositions[row.Disposition] = result.Count(row.Disposition) + 1;
                result.FirstId = Math.Min(result.FirstId ?? row.RequestId, row.RequestId);
                result.LastId = Math.Max(result.LastId ?? row.RequestId, row.RequestId);

                // Classify issued certificates by current validity and upcoming expiration.
                if (row.Disposition == 20)
                {
                    if (!row.NotBefore.HasValue || !row.NotAfter.HasValue) result.MissingValidity++;
                    if (row.NotAfter <= now) result.Expired++;
                    else if (row.NotBefore.HasValue && row.NotAfter.HasValue)
                    {
                        if (row.NotBefore > now) result.Future++;
                        else result.Valid++;
                    }
                    if (row.NotAfter > now)
                    {
                        var days = (row.NotAfter.Value - now).TotalDays;
                        result.Expiry[days <= 7 ? 0 : days <= 30 ? 1 : days <= 60 ? 2 : days <= 90 ? 3 : 4]++;
                    }
                }
                // Accumulate validity durations only for issued or revoked certificates with usable dates.
                if (row.Disposition is 20 or 21 && row.NotAfter >= row.NotBefore &&
                    row.NotBefore.HasValue && row.NotAfter.HasValue)
                {
                    result.DatedCertificates++;
                    result.ValidityDays += (row.NotAfter.Value - row.NotBefore.Value).TotalDays;
                }
                // Group request activity by template, requester, format, and revocation reason.
                Add(templates, row.TemplateLabel, row, now);
                Add(requesters, row.Requester, row, now);
                Add(types, RequestTypeName(record.RequestType), row, now);
                if (row.Disposition == 21) Add(reasons, ReasonName(row.RevocationReason), row, now);
                if (!record.Submitted.HasValue) result.MissingSubmission++;
                else
                {
                    // Track submission bounds, recent activity, and the oldest pending request.
                    var submitted = record.Submitted.Value;
                    if (!result.FirstSubmission.HasValue || submitted < result.FirstSubmission)
                        result.FirstSubmission = submitted;
                    if (!result.LastSubmission.HasValue || submitted > result.LastSubmission)
                        result.LastSubmission = submitted;
                    var age = (now - submitted).TotalDays;
                    if (age >= 0)
                    {
                        if (age <= 1) result.Recent[0]++;
                        if (age <= 7) result.Recent[1]++;
                        if (age <= 30) result.Recent[2]++;
                    }
                    // Group submissions by month and retain the age of the pending backlog.
                    if (row.Disposition == 9 && (!result.OldestPending.HasValue || submitted < result.OldestPending))
                        result.OldestPending = submitted;
                    Add(months, submitted.ToString("yyyy-MM", CultureInfo.InvariantCulture), row, now);
                    Add(localMonths, TimeDisplay.Display(submitted, false).ToString("yyyy-MM",
                        CultureInfo.InvariantCulture), row, now);

                    // Measure resolution time only for completed requests with consistent timestamps.
                    if (row.Disposition is not (8 or 9) && record.Resolved >= submitted)
                    {
                        var seconds = (record.Resolved.Value - submitted).TotalSeconds;
                        result.TimedResolutions++;
                        result.ResolutionSeconds += seconds;
                        result.LongestResolutionSeconds = Math.Max(result.LongestResolutionSeconds, seconds);
                    }
                }
                if (result.Total % 4096 == 0) progress?.Invoke(result.Total);
            }
            // Rank the completed groups and calculate their shares of the relevant totals.
            token.ThrowIfCancellationRequested();
            result.TemplateCount = templates.Count;
            result.RequesterCount = requesters.Count;
            result.Templates = Ranked(templates, result.Total, 100);
            result.Requesters = Ranked(requesters, result.Total, 100);
            result.Types = Ranked(types, result.Total);
            result.Reasons = Ranked(reasons, result.Count(21));
            result.utcMonths = months.Values.OrderByDescending(group => group.Name).ToArray();
            result.localMonths = localMonths.Values.OrderByDescending(group => group.Name).ToArray();
            foreach (var month in result.utcMonths.Concat(result.localMonths))
                month.Percent = result.Total == 0 ? 0 : 100.0 * month.Count / result.Total;

            // Finish only an uncancelled snapshot and record how long the scan took.
            token.ThrowIfCancellationRequested();
            result.Elapsed = watch.Elapsed;
            return result;
        }

        private static void Add(Dictionary<string, StatisticsGroup> groups, string name,
            CertificateRow row, DateTime now)
        {
            // Update one grouping bucket with disposition and expiry counts.
            name = string.IsNullOrWhiteSpace(name) ? "(Not Recorded)" : name;
            if (!groups.TryGetValue(name, out var group)) groups.Add(name, group = new StatisticsGroup { Name = name });
            group.Count++;
            if (row.Disposition == 21) group.Revoked++;
            if (row.Disposition != 20) return;
            group.Issued++;
            if (row.NotAfter <= now) group.Expired++;
            else if (row.NotAfter <= now.AddDays(30)) group.DueSoon++;
        }

        private static StatisticsGroup[] Ranked(Dictionary<string, StatisticsGroup> groups, long total,
            int limit = int.MaxValue)
        {
            // Rank the largest groups and express each count as a share of the full total.
            var ranked = groups.Values.OrderByDescending(group => group.Count)
                .ThenBy(group => group.Name, StringComparer.OrdinalIgnoreCase).Take(limit).ToArray();
            foreach (var group in ranked) group.Percent = total == 0 ? 0 : 100.0 * group.Count / total;
            return ranked;
        }

        internal static string RequestTypeName(int? type)
        {
            // Decode the request format bits independently of other request flags.
            if (!type.HasValue) return "(Not Recorded)";
            return (type.Value & 0xff00) switch
            {
                0 => "Unspecified Format", 0x100 => "PKCS #10", 0x200 => "Keygen (SPKAC)", 0x300 => "PKCS #7",
                0x400 => "CMC", 0x500 => "Challenge Response", 0x600 => "Signed Certificate Timestamp List",
                _ => $"Other (0x{type.Value:X8})"
            };
        }

        private static string ReasonName(int? reason)
        {
            // Map recorded revocation reasons while retaining unknown numeric values.
            var names = new[] { "Unspecified", "Key Compromise", "CA Compromise", "Affiliation Changed",
                "Superseded", "Cessation Of Operation", "Certificate Hold", "Unused", "Remove From CRL",
                "Privilege Withdrawn", "AA Compromise" };
            return !reason.HasValue ? "(Not Recorded)" : reason >= 0 && reason < names.Length ?
                names[reason.Value] : "Other (" + reason + ")";
        }

        private static IEnumerable<StatisticsRecord> ReadRecords(string configuration, CancellationToken token, OidNames oids)
        {
            // Select only fields needed for statistics instead of fetching certificate blobs.
            var names = new[] { "RequestID", "CertificateTemplate", "Request.RequesterName", "NotBefore", "NotAfter",
                "Request.Disposition", "Request.RevokedReason", "Request.SubmittedWhen", "Request.ResolvedWhen",
                "Request.RequestType" };
            using (var scope = ComScope<ICertView>.Create("CertificateAuthority.View"))
            {
                // Open a CA view that streams metadata for every request.
                var view = scope.Value;
                view.OpenConnection(configuration);
                var indexes = names.Select(name => view.GetColumnIndex(0, name)).ToArray();
                view.SetResultColumnCount(indexes.Length);
                foreach (var index in indexes) view.SetResultColumn(index);
                CertificateStore.Restrict(view, "RequestID", 16, 0);
                using (var rows = new ComScope<ICertViewRow>(view.OpenView()))
                {
                    var ordinals = new Dictionary<int, int>();
                    while (true)
                    {
                        // Create one aggregate input record at a time with cancellation support.
                        token.ThrowIfCancellationRequested();
                        if (rows.Value.Next() < 0) yield break;
                        var row = new CertificateRow();
                        var record = new StatisticsRecord { Certificate = row };
                        using (var columns = new ComScope<ICertViewColumn>(rows.Value.EnumCertViewColumn()))
                        {
                            int index;
                            while ((index = columns.Value.Next()) >= 0)
                            {
                                // Cache native column mappings across the statistics scan.
                                if (!ordinals.TryGetValue(index, out var ordinal))
                                {
                                    var name = columns.Value.GetName();
                                    ordinal = Array.FindIndex(names, candidate => string.Equals(
                                        candidate.Replace("Request.", ""), name.Replace("Request.", ""),
                                        StringComparison.OrdinalIgnoreCase));
                                    ordinals[index] = ordinal;
                                }
                                // Skip missing values and normalize returned dates as UTC.
                                var value = columns.Value.GetValue(1);
                                if (value == null || value == DBNull.Value) continue;
                                var date = value is DateTime time ? (DateTime?)DateTime.SpecifyKind(time,
                                    DateTimeKind.Utc) : null;

                                // Populate statistics fields and resolve template identities for grouping.
                                switch (ordinal)
                                {
                                    case 0: row.RequestId = Convert.ToInt32(value); break;
                                    case 1:
                                        row.Template = Convert.ToString(value);
                                        row.ResolvedTemplate = oids.Template(row.Template);
                                        break;
                                    case 2: row.Requester = Convert.ToString(value); break;
                                    case 3: row.NotBefore = date; break;
                                    case 4: row.NotAfter = date; break;
                                    case 5: row.Disposition = Convert.ToInt32(value); break;
                                    case 6: row.RevocationReason = Convert.ToInt32(value); break;
                                    case 7: record.Submitted = date; break;
                                    case 8: record.Resolved = date; break;
                                    case 9: record.RequestType = Convert.ToInt32(value); break;
                                }
                            }
                        }
                        // Reject rows without a request identity before aggregation.
                        if (row.RequestId < 1) throw new InvalidOperationException("The CA returned no request ID.");
                        yield return record;
                    }
                }
            }
        }
    }

    internal sealed class StatisticsFile
    {
        public string Path { get; set; }
        public string Kind { get; set; }
        public long Bytes { get; set; }
        public string Size => CaServerStatistics.Size(Bytes);
    }

    internal sealed class CaServerStatistics
    {
        public List<DetailValue> Authority { get; } = new List<DetailValue>();
        public List<DetailValue> Server { get; } = new List<DetailValue>();
        public List<DetailValue> Storage { get; } = new List<DetailValue>();
        public List<StatisticsFile> Files { get; } = new List<StatisticsFile>();
        public long? DatabaseBytes { get; private set; }
        private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

        internal static CaServerStatistics Read(string config, CancellationToken token, OidNames names = null)
        {
            // Capture the selected CA and server identities before collecting independent metrics.
            token.ThrowIfCancellationRequested();
            names ??= OidNames.Load(config);
            token.ThrowIfCancellationRequested();
            var result = new CaServerStatistics();
            var host = config.Substring(0, config.IndexOf('\\'));
            Add(result.Authority, "Connected CA", config);
            Add(result.Server, "Target Server", host);

            // Read supported CA properties without letting one unavailable value stop the report.
            Attempt(result.Authority, "CA Properties", token, () => CaAdministration.Use(config, admin =>
            {
                foreach (var id in new[] { 6, 22, 10, 1, 2, 5, 11, 23, 24, 25, 29 })
                {
                    Attempt(result.Authority, "CA Property " + id, token, () =>
                    {
                        var type = admin.GetCAPropertyFlags(config, id) & 255;
                        var value = admin.GetCAProperty(config, id, 0, type, 1);
                        if (id == 10) value = CaTypeName(Convert.ToInt32(value));
                        Add(result.Authority, Dialogs.Caption(admin.GetCAPropertyDisplayName(config, id)),
                            value);
                    });
                }
                // Collect publication status and the available base and delta CRL metadata.
                Attempt(result.Authority, "CRL Publication", token, () =>
                    Add(result.Authority, "CRL Publication", CaAdministration.CrlPublicationStatus(config, admin)));
                Attempt(result.Authority, "CRL Metadata", token, () =>
                {
                    // Visit each distinct signing key once when reading its CRLs.
                    var count = Convert.ToInt32(admin.GetCAProperty(config, 11, 0, 1, 0));
                    var keys = new HashSet<int>();
                    for (var index = 0; index < count; index++)
                    {
                        var key = (Convert.ToInt32(admin.GetCAProperty(config, 39, index, 1, 0)) >> 16) & 0xffff;
                        if (!keys.Add(key)) continue;
                        foreach (var property in new[] { 17, 18 })
                        {
                            var label = "Key " + key + (property == 17 ? " Base CRL" : " Delta CRL");
                            Attempt(result.Authority, label, token, () => Add(result.Authority, label,
                                CertificateValidation.CrlMetadata(Convert.FromBase64String(Convert.ToString(
                                    admin.GetCAProperty(config, property, key, 3, 1))))));
                        }
                    }
                });
                return true;
            }));

            // Describe the current CA signing certificate, validity period, and key.
            Attempt(result.Authority, "Current Signing Certificate", token, () =>
            {
                using (var request = ComScope<ICertRequest>.Create("CertificateAuthority.Request"))
                using (var certificate = new X509Certificate2(Convert.FromBase64String(
                    request.Value.GetCACertificate(0, config, 1))))
                {
                    var described = CertificateUtilities.Describe(certificate, names);
                    Add(result.Authority, "Signing Certificate Subject", certificate.Subject);
                    Add(result.Authority, "Signing Certificate Issuer", certificate.Issuer);
                    Add(result.Authority, "Signing Certificate Thumbprint", certificate.Thumbprint);
                    Add(result.Authority, "Signing Certificate Valid From (UTC)",
                        certificate.NotBefore.ToUniversalTime());
                    Add(result.Authority, "Signing Certificate Expires (UTC)",
                        certificate.NotAfter.ToUniversalTime());
                    Add(result.Authority, "Signing Certificate Key",
                        described.Algorithm + " / " + described.KeyBits + " Bits");
                    Add(result.Authority, "Signing Certificate Size", Size(certificate.RawData.Length));
                }
            });

            // Connect to server WMI for operating system, service, and storage metrics.
            Attempt(result.Server, "Server Metrics", token, () =>
            {
                var scope = new ManagementScope(@"\\" + host + @"\root\cimv2",
                    new ConnectionOptions { Timeout = Timeout });
                scope.Connect();
                Attempt(result.Server, "Operating System", token, () => Query(scope,
                    "SELECT Caption, Version, OSArchitecture, LastBootUpTime, TotalVisibleMemorySize, " +
                    "FreePhysicalMemory FROM Win32_OperatingSystem", token, item =>
                {
                    // Report operating system identity, uptime, and physical memory.
                    Add(result.Server, "Operating System", item["Caption"] + " / " + item["Version"] +
                        " / " + item["OSArchitecture"]);
                    var boot = ManagementDateTimeConverter.ToDateTime(Convert.ToString(item["LastBootUpTime"]));
                    Add(result.Server, "Last Boot (UTC)", boot.ToUniversalTime());
                    Add(result.Server, "Server Uptime", (DateTime.Now - boot).ToString(@"d\d\ hh\h\ mm\m"));
                    Add(result.Server, "Visible / Free Physical Memory", Size(Convert.ToInt64(
                        item["TotalVisibleMemorySize"]) * 1024) + " / " + Size(Convert.ToInt64(
                        item["FreePhysicalMemory"]) * 1024));
                }));

                // Read processor capacity and Certificate Services state independently.
                Attempt(result.Server, "Processor", token, () => Query(scope,
                    "SELECT Name, NumberOfCores, NumberOfLogicalProcessors, LoadPercentage FROM Win32_Processor",
                    token, item => Add(result.Server, "Processor", item["Name"] + " / " + item["NumberOfCores"] +
                        " Cores / " + item["NumberOfLogicalProcessors"] + " Logical / " +
                        (item["LoadPercentage"] == null ? "Load Unavailable" : item["LoadPercentage"] + "% Load"))));
                Attempt(result.Server, "Certificate Services", token, () => Query(scope,
                    "SELECT State, StartMode, ProcessId, StartName FROM Win32_Service WHERE Name='CertSvc'",
                    token, item =>
                {
                    // Record the service identity and inspect its process only when it is running.
                    Add(result.Server, "Certificate Services", item["State"] + " / " + item["StartMode"]);
                    Add(result.Server, "Service Account", item["StartName"]);
                    var pid = Convert.ToInt32(item["ProcessId"]);
                    if (pid == 0) return;
                    Query(scope, "SELECT CreationDate, WorkingSetSize, PrivatePageCount FROM Win32_Process " +
                        "WHERE ProcessId=" + pid.ToString(CultureInfo.InvariantCulture), token, process =>
                    {
                        // Report the CA process start time and memory use.
                        Add(result.Server, "Service Process ID", pid);
                        Add(result.Server, "Service Started (UTC)", ManagementDateTimeConverter.ToDateTime(
                            Convert.ToString(process["CreationDate"])).ToUniversalTime());
                        Add(result.Server, "Service Working Set / Private Bytes", Size(Convert.ToInt64(
                            process["WorkingSetSize"])) + " / " + Size(Convert.ToInt64(process["PrivatePageCount"])));
                    });
                }));

                // Collect fixed-volume capacity before inspecting configured CA files.
                Attempt(result.Storage, "Server Volumes", token, () => Query(scope,
                    "SELECT DeviceID, Size, FreeSpace FROM Win32_LogicalDisk WHERE DriveType=3", token, item =>
                        Add(result.Storage, "Volume " + item["DeviceID"] + " — Total / Free",
                            Size(Convert.ToInt64(item["Size"])) + " / " + Size(Convert.ToInt64(item["FreeSpace"])))));
                ReadStorage(result, scope, host, token);
            });

            // Make missing storage data explicit and honor cancellation before returning.
            if (result.Storage.Count == 0)
                Add(result.Storage, "Storage Metrics", "Unavailable — Server WMI Could Not Be Read.");
            token.ThrowIfCancellationRequested();
            return result;
        }

        private static void ReadStorage(CaServerStatistics result, ManagementScope scope, string host,
            CancellationToken token)
        {
            // Read CA storage paths through the target server registry provider.
            Attempt(result.Storage, "Database Configuration", token, () =>
            {
                var local = IsLocalHost(host);
                Add(result.Storage, "File Size Collection", local ? "Local File Metadata" : "Remote WMI File Metadata");
                var registryScope = new ManagementScope(@"\\" + host + @"\root\default",
                    new ConnectionOptions { Timeout = Timeout });
                using (var registry = new ManagementClass(registryScope, new ManagementPath("StdRegProv"), null))
                {
                    // Group configured storage roles by folder to avoid duplicate file scans.
                    var folders = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
                    var entries = new[] { "DBDirectory", "DBLogDirectory", "DBSystemDirectory", "DBTempDirectory" };
                    var labels = new[] { "Database Directory", "Log Directory", "System Directory", "Temporary Directory" };
                    for (var i = 0; i < entries.Length; i++)
                    {
                        var name = entries[i];
                        var label = labels[i];
                        Attempt(result.Storage, label, token, () =>
                        {
                            // Read the configured path and expand environment variables on the server.
                            string path;
                            using (var input = registry.GetMethodParameters("GetStringValue"))
                            {
                                input["hDefKey"] = 0x80000002u;
                                input["sSubKeyName"] = @"SYSTEM\CurrentControlSet\Services\CertSvc\Configuration";
                                input["sValueName"] = name;
                                using (var output = registry.InvokeMethod("GetStringValue", input,
                                    new InvokeMethodOptions { Timeout = Timeout }))
                                    path = Convert.ToString(output["sValue"]);
                                if (string.IsNullOrEmpty(path) || path.Contains("%"))
                                {
                                    using (var output = registry.InvokeMethod("GetExpandedStringValue", input,
                                        new InvokeMethodOptions { Timeout = Timeout }))
                                    {
                                        var error = Convert.ToInt32(output["ReturnValue"]);
                                        if (error != 0) throw new Win32Exception(error);
                                        path = Convert.ToString(output["sValue"]);
                                    }
                                }
                            }
                            // Require an absolute server path before associating it with storage roles.
                            if (string.IsNullOrWhiteSpace(path) || path.Contains("%") ||
                                path.Length < 3 || path[1] != ':')
                                throw new InvalidOperationException(
                                    "The Server Did Not Return An Absolute Local Folder.");
                            path = path.TrimEnd('\\');
                            Add(result.Storage, label, path);
                            if (!folders.TryGetValue(path, out var roles))
                                folders.Add(path, roles = new List<string>());
                            roles.Add(name);
                        });
                    }
                    // Inspect each distinct configured folder while isolating access failures.
                    foreach (var folder in folders)
                    {
                        Attempt(result.Storage, "Files In " + folder.Key, token, () =>
                        {
                            var files = new List<StatisticsFile>();
                            var drive = folder.Key.Substring(0, 2);
                            var path = folder.Key.Substring(2) + "\\";
                            void AddFile(string name, long bytes)
                            {
                                // Classify files by extension and the configured role of their folder.
                                token.ThrowIfCancellationRequested();
                                var extension = Path.GetExtension(name).ToLowerInvariant();
                                var kind = extension == ".edb" && folder.Value.Contains("DBDirectory") ? "Database" :
                                    extension == ".log" && folder.Value.Contains("DBLogDirectory") ? "Transaction Log" :
                                    extension == ".jrs" && folder.Value.Contains("DBLogDirectory") ? "Reserve Log" :
                                    extension == ".chk" ? "Checkpoint" : "Other";
                                files.Add(new StatisticsFile { Path = name, Kind = kind, Bytes = bytes });
                            }
                            // Use local file metadata or targeted WMI queries according to the CA host.
                            if (local)
                            {
                                foreach (var file in new DirectoryInfo(folder.Key + "\\").EnumerateFiles())
                                    AddFile(file.FullName, file.Length);
                            }
                            else Query(scope, "SELECT Name, FileSize FROM CIM_DataFile WHERE Drive='" +
                                Wql(drive) + "' AND Path='" + Wql(path) + "'", token, item =>
                            {
                                if (item["FileSize"] == null) throw new IOException("A File Size Was Not Available.");
                                AddFile(Convert.ToString(item["Name"]), Convert.ToInt64(item["FileSize"]));
                            });

                            // Record folder totals and retain database size for the summary.
                            result.Files.AddRange(files);
                            Add(result.Storage, "Files In " + folder.Key,
                                $"{files.Count:N0} / " + Size(files.Sum(file => file.Bytes)));
                            if (folder.Value.Contains("DBDirectory"))
                            {
                                var databases = files.Where(file => file.Kind == "Database").ToArray();
                                if (databases.Length > 0) result.DatabaseBytes = databases.Sum(file => file.Bytes);
                            }
                        });
                    }
                    // Summarize database size and file counts for each storage category.
                    Add(result.Storage, "Database Files (*.edb)", result.DatabaseBytes.HasValue ?
                        Size(result.DatabaseBytes.Value) : "Unavailable — No Database File Sizes Were Read.");
                    foreach (var group in result.Files.GroupBy(file => file.Kind))
                        Add(result.Storage, group.Key + " Files",
                            $"{group.Count():N0} / " + Size(group.Sum(file => file.Bytes)));
                }
            });
        }

        private static void Query(ManagementScope scope, string query, CancellationToken token,
            Action<ManagementBaseObject> read)
        {
            // Run a bounded forward-only WMI query with cancellation between results.
            token.ThrowIfCancellationRequested();
            using (var search = new ManagementObjectSearcher(scope, new ObjectQuery(query),
                new EnumerationOptions { ReturnImmediately = true, Rewindable = false, Timeout = Timeout }))
            using (var results = search.Get())
            {
                var count = 0;
                foreach (ManagementBaseObject item in results)
                {
                    using (item) { token.ThrowIfCancellationRequested(); read(item); count++; }
                }
                if (count == 0 && !query.Contains("CIM_DataFile"))
                    throw new InvalidOperationException("The Server Returned No Data.");
            }
        }

        private static void Attempt(List<DetailValue> values, string label, CancellationToken token, Action read)
        {
            // Keep unavailable metrics visible while letting cancellation stop the whole collection.
            token.ThrowIfCancellationRequested();
            try { read(); }
            catch (OperationCanceledException) { throw; }
            catch (Exception error) { Add(values, label, "Unavailable — " + CaAdministration.Error(error)); }
        }

        internal static void Add(List<DetailValue> values, string name, object value) =>
            values.Add(new DetailValue { Name = name, Value = value == null ? "Not Recorded" : CertificateStore.Format(value),
                Time = value is DateTime date ? TimeDisplay.Utc(date) : (DateTime?)null, Report = value as TimeReport });

        internal static string Date(DateTime? date) => TimeDisplay.Stamp(date);
        internal static string Size(long bytes) => bytes >= 1073741824 ?
            $"{bytes / 1073741824.0:N2} GiB ({bytes:N0} Bytes)" :
            bytes >= 1048576 ? $"{bytes / 1048576.0:N2} MiB ({bytes:N0} Bytes)" : $"{bytes:N0} Bytes";

        internal static bool IsLocalHost(string host)
        {
            // Recognize common local aliases before choosing local or remote file access.
            var local = IPGlobalProperties.GetIPGlobalProperties();
            var names = new[] { ".", "localhost", Environment.MachineName, local.HostName,
                local.HostName + "." + local.DomainName };
            return names.Any(name => string.Equals(host.TrimEnd('.'), name, StringComparison.OrdinalIgnoreCase));
        }

        internal static string CaTypeName(int type)
        {
            // Translate the CA installation type into a readable server classification.
            return type switch
            {
                0 => "Enterprise Root", 1 => "Enterprise Subordinate", 3 => "Standalone Root",
                4 => "Standalone Subordinate", _ => "Unknown (" + type + ")"
            };
        }

        private static string Wql(string value) => value.Replace("\\", "\\\\").Replace("'", "\\'");
    }
}
