//
// Copyright (c) Bryan Berns.
// Licensed under GPLv3. See LICENSE.md.
//

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading;

namespace Certitude
{
    internal static class EntryPoint
    {
        [STAThread]
        public static int Main(string[] args)
        {
            // Route command-line requests to export without initializing WPF.
            if (args.Length > 0) return ExportCommand.Execute(args);
            var app = new App();
            app.InitializeComponent();
            return app.Run();
        }
    }

    internal sealed class ExportField
    {
        public string Name { get; }
        public Type Type { get; }
        public Func<CertificateRow, object> Read { get; }
        private ExportField(string name, Type type, Func<CertificateRow, object> read)
        { Name = name; Type = type; Read = read; }

        public static readonly ExportField[] All =
        {
            new ExportField("RequestID", typeof(int), row => row.RequestId),
            new ExportField("CommonName", typeof(string), row => row.CommonName),
            new ExportField("RequesterName", typeof(string), row => row.Requester),
            new ExportField("CertificateTemplate", typeof(string), row => row.Template),
            new ExportField("SerialNumber", typeof(string), row => row.SerialNumber),
            new ExportField("NotBefore", typeof(DateTime), row => row.NotBefore),
            new ExportField("NotAfter", typeof(DateTime), row => row.NotAfter),
            new ExportField("Status", typeof(string), row => row.Status),
            new ExportField("Disposition", typeof(int), row => row.Disposition),
            new ExportField("RevocationReason", typeof(int), row => row.RevocationReason),
            new ExportField("TemplateDisplayName", typeof(string), row => row.TemplateDisplayName),
            new ExportField("TemplateName", typeof(string), row => row.TemplateName),
            new ExportField("TemplateOid", typeof(string), row => row.TemplateOid),
            new ExportField("Configuration", typeof(string), row => row.Configuration)
        };
        public static readonly string[] Defaults = All.Take(8).Select(field => field.Name).ToArray();

        public static ExportField Find(string name)
        {
            // Resolve accepted aliases to one canonical export field definition.
            var aliases = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                { "Requester", "RequesterName" }, { "Template", "CertificateTemplate" },
                { "Request.Disposition", "Disposition" }, { "Request.RevokedReason", "RevocationReason" }
            };
            if (aliases.TryGetValue(name.Trim(), out var alias)) name = alias;
            return All.FirstOrDefault(field => field.Name.Equals(name.Trim(), StringComparison.OrdinalIgnoreCase)) ??
                throw new ArgumentException("Unknown field '" + name + "'. Use export --list-fields.");
        }

        public static ExportField[] Select(string[] names)
        {
            // Expand default or wildcard selections and reject empty or repeated output columns.
            names ??= Defaults;
            if (names.Length == 1 && names[0].Trim() == "*") return All;
            var fields = names.Select(Find).ToArray();
            if (fields.Length == 0 || fields.Select(field => field.Name).Distinct().Count() != fields.Length)
                throw new ArgumentException("Select at least one field, without duplicates.");
            return fields;
        }
    }

    internal sealed class ExportCondition
    {
        public ExportField Field { get; private set; }
        public string Operator { get; private set; }
        public object Value { get; private set; }

        public static ExportCondition Parse(string expression, DateTime now)
        {
            // Recognize the supported condition grammar without evaluating arbitrary expressions.
            var match = Regex.Match(expression,
                @"^\s*(?<field>[A-Za-z][A-Za-z0-9_.]*)(?:\s*(?<op>!=|>=|<=|=|>|<)\s*(?<value>.*?)|" +
                @"\s+(?<op>contains|startswith|endswith)\s+(?<value>.+?)|\s+(?<op>is\s+(?:not\s+)?null))\s*$",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            if (!match.Success) throw new ArgumentException(
                "Invalid condition '" + expression + "'. See export --help.");

            // Resolve field metadata and normalize operators before interpreting the comparison value.
            var condition = new ExportCondition
            {
                Field = ExportField.Find(match.Groups["field"].Value),
                Operator = Regex.Replace(match.Groups["op"].Value.ToLowerInvariant(), @"\s+", " ")
            };
            if (condition.Operator is "is null" or "is not null") return condition;

            // Unquote literal values and reject operators incompatible with the selected field type.
            var value = match.Groups["value"].Value;
            if (value.Length >= 2 && (value[0] == '\'' || value[0] == '"') && value[0] == value[value.Length - 1])
                value = value.Substring(1, value.Length - 2);
            var textOperator = condition.Operator is "contains" or "startswith" or "endswith";
            if (condition.Field.Type != typeof(string) && textOperator || condition.Field.Type == typeof(string) &&
                !textOperator && condition.Operator != "=" && condition.Operator != "!=")
                throw new ArgumentException("Operator '" + condition.Operator +
                    "' is not supported for " + condition.Field.Name + ".");

            // Convert values once so each exported row can use a typed comparison.
            if (condition.Field.Type == typeof(string)) condition.Value = value;
            else if (condition.Field.Type == typeof(DateTime)) condition.Value = ParseDate(value, now);
            else
            {
                var number = condition.Field.Name == "Disposition" ? Disposition(value) : null;
                if (!number.HasValue && !int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out _))
                    throw new ArgumentException("Enter an integer for " + condition.Field.Name +
                        (condition.Field.Name == "Disposition" ?
                            " or a disposition name such as Issued or Pending." : "."));
                condition.Value = number ?? int.Parse(value, CultureInfo.InvariantCulture);
            }
            return condition;
        }

        internal static int? Disposition(string value)
        {
            // Match friendly disposition names to their native CA codes while tolerating spacing and case.
            foreach (var number in new[] { 8, 9, 12, 15, 16, 17, 20, 21, 30, 31 })
                if (CertificateRow.State(number).Replace(" ", "").Equals(value.Replace(" ", ""),
                    StringComparison.OrdinalIgnoreCase)) return number;
            return null;
        }

        private static DateTime ParseDate(string value, DateTime now)
        {
            // Resolve relative dates against the single UTC instant captured for this export command.
            var relative = Regex.Match(value, @"^(now|today)(?:([+-]\d+)([dhm]))?$", RegexOptions.IgnoreCase);
            if (relative.Success)
            {
                var date = relative.Groups[1].Value.Equals("today",
                    StringComparison.OrdinalIgnoreCase) ? now.Date : now;
                if (!relative.Groups[2].Success) return date;
                if (!int.TryParse(relative.Groups[2].Value, NumberStyles.Integer,
                    CultureInfo.InvariantCulture, out var amount))
                    throw new ArgumentException("Relative date offset is too large.");
                var unit = relative.Groups[3].Value.ToLowerInvariant();
                return unit == "d" ? date.AddDays(amount) :
                    unit == "h" ? date.AddHours(amount) : date.AddMinutes(amount);
            }
            // Require ISO calendar values and normalize explicit or implicit offsets to UTC.
            if (!Regex.IsMatch(value, @"^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}:\d{2}" +
                @"(?:\.\d{1,7})?(?:Z|[+-]\d{2}:\d{2})?)?$",
                RegexOptions.IgnoreCase) || !DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed))
                throw new ArgumentException(
                    "Use an ISO date/time, now, today, or an offset such as today+30d: " + value);
            return parsed.UtcDateTime;
        }

        public bool Matches(CertificateRow row)
        {
            // Handle null predicates before ordinary comparisons so absent values remain distinguishable.
            var actual = Field.Read(row);
            var empty = actual == null || actual is string text && text.Length == 0;
            if (Operator == "is null") return empty;
            if (Operator == "is not null") return !empty;

            // Apply literal, case-insensitive text matching without wildcard interpretation.
            if (Field.Type == typeof(string))
            {
                var left = (string)actual ?? "";
                var right = (string)Value;
                if (Operator == "contains") return left.IndexOf(right, StringComparison.OrdinalIgnoreCase) >= 0;
                if (Operator == "startswith") return left.StartsWith(right, StringComparison.OrdinalIgnoreCase);
                if (Operator == "endswith") return left.EndsWith(right, StringComparison.OrdinalIgnoreCase);
                var equal = string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
                return Operator == "=" ? equal : !equal;
            }
            // Exclude absent numeric or date values, then apply their typed ordering relation.
            if (actual == null) return false;
            var comparison = ((IComparable)actual).CompareTo(Value);
            return Operator switch
            {
                "=" => comparison == 0, "!=" => comparison != 0, ">" => comparison > 0,
                ">=" => comparison >= 0, "<" => comparison < 0, _ => comparison <= 0
            };
        }
    }

    internal sealed class ExportCommand
    {
        public string Configuration { get; private set; }
        public string Output { get; private set; }
        public string[] Fields { get; private set; } = ExportField.Defaults;
        public List<ExportCondition> Conditions { get; } = new List<ExportCondition>();
        public bool Force { get; private set; }
        public bool Help { get; private set; }
        public bool ListFields { get; private set; }

        public static ExportCommand Parse(string[] args)
        {
            // Recognize help or export mode before processing options that require a destination.
            var command = new ExportCommand();
            if (args.Length == 1 && args[0].ToLowerInvariant() is "--help" or "-h" or "/?")
            { command.Help = true; return command; }
            if (args.Length == 0 || !args[0].Equals("export", StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException(
                    "Use Certitude.exe export ... or --help. Start without arguments for the GUI.");

            // Capture one relative-date reference and enforce uniqueness for nonrepeatable options.
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var now = DateTime.UtcNow;
            for (var i = 1; i < args.Length; i++)
            {
                var option = args[i].ToLowerInvariant();
                if (option != "--where" && !seen.Add(option))
                    throw new ArgumentException("Duplicate option: " + option);
                if (option == "--help" || option == "-h") { command.Help = true; continue; }
                if (option == "--list-fields") { command.ListFields = true; continue; }
                if (option == "--force") { command.Force = true; continue; }

                // Consume only supported valued options and accumulate repeated conditions as an AND filter.
                if (option is not ("--ca" or "--output" or "--fields" or "--where"))
                    throw new ArgumentException("Unknown option: " + args[i]);
                if (++i == args.Length || args[i].StartsWith("--", StringComparison.Ordinal))
                    throw new ArgumentException("Missing value for " + option + ".");
                var value = args[i];
                if (option == "--ca") command.Configuration = value;
                else if (option == "--output") command.Output = value;
                else if (option == "--fields") command.Fields = ExportField.Select(value.Split(','))
                    .Select(field => field.Name).ToArray();
                else command.Conditions.Add(ExportCondition.Parse(value, now));
            }
            // Validate executable export requests after allowing offline help and field discovery.
            if (command.Help || command.ListFields) return command;
            if (string.IsNullOrWhiteSpace(command.Output)) throw new ArgumentException("Specify --output <CSV file>.");
            command.Output = Path.GetFullPath(command.Output);
            if (command.Configuration != null) new CertificateStore(command.Configuration);
            return command;
        }

        public QuerySpec Query()
        {
            // Push disposition constraints into the CA query to reduce the rows streamed to the client.
            var query = new QuerySpec { Disposition = null };
            var disposition = Conditions.FirstOrDefault(item =>
                item.Field.Name == "Disposition" && item.Operator == "=");
            if (disposition != null) query.Disposition = (int)disposition.Value;
            var status = Conditions.FirstOrDefault(item => item.Field.Name == "Status" && item.Operator == "=");
            if (!query.Disposition.HasValue && status != null)
                query.Disposition = string.Equals((string)status.Value, "Expired", StringComparison.OrdinalIgnoreCase) ?
                    20 : ExportCondition.Disposition((string)status.Value);

            // Choose a selective exact field restriction while retaining all conditions for final row matching.
            foreach (var name in new[] { "RequestID", "CommonName", "SerialNumber", "RequesterName", "CertificateTemplate" })
            {
                var condition = Conditions.FirstOrDefault(item => item.Field.Name == name && item.Operator == "=" &&
                    (item.Value is int number ? number > 0 : ((string)item.Value).Length > 0));
                if (condition == null) continue;
                query.Field = name;
                query.Value = Convert.ToString(condition.Value, CultureInfo.InvariantCulture);
                break;
            }
            // Combine expiry conditions into the narrowest server-side range with exclusive upper bounds.
            foreach (var condition in Conditions.Where(item => item.Field.Name == "NotAfter" && item.Value != null))
            {
                var date = (DateTime)condition.Value;
                if (condition.Operator is "=" or ">" or ">=" &&
                    (!query.ExpiresFrom.HasValue || date > query.ExpiresFrom)) query.ExpiresFrom = date;
                if (condition.Operator == "<=" || condition.Operator == "=")
                {
                    if (date == DateTime.MaxValue) continue;
                    date = date.AddTicks(1);
                }
                if (condition.Operator is "=" or "<" or "<=" &&
                    (!query.ExpiresBefore.HasValue || date < query.ExpiresBefore)) query.ExpiresBefore = date;
            }
            // Leave contradictory predicates to final matching instead of constructing an invalid CA range.
            if (query.ExpiresFrom >= query.ExpiresBefore) query.ExpiresBefore = null;
            return query;
        }

        public static int Run(string[] args, TextWriter output, TextWriter error, CancellationToken token)
        {
            // Separate argument errors from runtime failures and serve discovery commands without a CA connection.
            ExportCommand command;
            try { command = Parse(args); }
            catch (Exception failure)
            { error.WriteLine(failure.Message + "\nUse Certitude.exe export --help for syntax."); return 2; }
            if (command.Help) { output.WriteLine(Usage); return 0; }
            if (command.ListFields)
            {
                foreach (var field in ExportField.All)
                    output.WriteLine(field.Name + "\t" + (field.Type == typeof(DateTime) ? "UTC Date/Time" :
                        field.Type == typeof(int) ? "Integer" : "Text"));
                return 0;
            }
            try
            {
                // Stream matching rows to the requested destination using the explicit or local CA configuration.
                token.ThrowIfCancellationRequested();
                var config = command.Configuration ?? CertificateStore.LocalConfiguration();
                var store = new CertificateStore(config);
                var watch = Stopwatch.StartNew();
                var count = store.Export(command.Query(), command.Output, token, null, command.Fields,
                    row => command.Conditions.All(condition => condition.Matches(row)), command.Force);

                // Report OID lookup limitations when the chosen fields or filters depend on resolved template names.
                if (store.LoadedOids?.Warning.Length > 0 &&
                    (ExportField.Select(command.Fields).Any(field =>
                        field.Name.StartsWith("Template", StringComparison.Ordinal)) ||
                    command.Conditions.Any(condition =>
                        condition.Field.Name.StartsWith("Template", StringComparison.Ordinal))))
                    error.WriteLine(store.LoadedOids.Warning);
                output.WriteLine($"Exported {count} rows to {command.Output} in {watch.Elapsed.TotalSeconds:F2}s.");
                return 0;
            }
            // Return distinct cancellation and failure codes while preserving the destination on interrupted exports.
            catch (OperationCanceledException)
            { error.WriteLine("Export cancelled; destination unchanged."); return 130; }
            catch (Exception failure) { error.WriteLine(CaAdministration.Error(failure)); return 1; }
        }

        [DllImport("kernel32.dll")]
        private static extern bool AttachConsole(uint processId);
        [DllImport("kernel32.dll")]
        private static extern IntPtr GetStdHandle(int identifier);
        [DllImport("kernel32.dll")]
        private static extern bool SetStdHandle(int identifier, IntPtr handle);
        [DllImport("kernel32.dll")]
        private static extern uint GetFileType(IntPtr handle);
        [DllImport("kernel32.dll")]
        private static extern IntPtr GetConsoleWindow();

        public static int Execute(string[] args)
        {
            // Attach to the caller console without replacing handles already redirected to files or pipes.
            var stdout = GetStdHandle(-11);
            var stderr = GetStdHandle(-12);
            var redirectedOut = GetFileType(stdout) is 1 or 3;
            var redirectedError = GetFileType(stderr) is 1 or 3;
            AttachConsole(uint.MaxValue);
            if (redirectedOut) SetStdHandle(-11, stdout);
            if (redirectedError) SetStdHandle(-12, stderr);

            // Translate Ctrl+C into cooperative export cancellation only when a console is available.
            var attached = GetConsoleWindow() != IntPtr.Zero;
            using (var cancellation = new CancellationTokenSource())
            {
                ConsoleCancelEventHandler cancel = (sender, e) => { e.Cancel = true; cancellation.Cancel(); };
                if (attached) Console.CancelKeyPress += cancel;
                try { return Run(args, Console.Out, Console.Error, cancellation.Token); }
                finally { if (attached) Console.CancelKeyPress -= cancel; }
            }
        }

        internal const string Usage = @"Certitude CSV Export
  Certitude.exe export --output <file.csv> [--ca <SERVER\CA Name>]
      [--fields <field,field,...|*>] [--where <condition>]... [--force]
  Certitude.exe export --list-fields
  Certitude.exe export --help

All records are eligible by default. Repeat --where to combine conditions with AND.
Fields are case-insensitive; their order determines the CSV column order.
Aliases: Requester, Template, Request.Disposition, Request.RevokedReason.
CertificateTemplate retains the raw CA value. TemplateDisplayName, TemplateName and
TemplateOid expose resolved template identifiers and also support --where conditions.
Text: =, !=, contains, startswith, endswith (case-insensitive, literal text).
Numbers and dates: =, !=, >, >=, <, <=. Any field: is null, is not null (blank/missing).
Missing numeric/date values do not match comparisons, including !=.
Disposition accepts integers or Processing, Pending, ForeignCertificate, CACertificate,
CAChain, RecoveryAgent, Issued, Revoked, Failed, Denied. Issued includes expired rows;
Status=Expired selects issued rows past their expiry; Status=Issued selects the remainder.
Dates: ISO 8601; no offset means UTC. Relative: now, today, today+30d, now-12h, now+15m.
Quote each condition and any argument containing spaces. --ca defaults to the local CA.
Output is UTF-8 CSV with UTC dates. Existing files require --force. Errors go to stderr.
Exit codes: 0 success (also zero matches), 1 export failure, 2 usage error, 130 cancelled.
Ctrl+C cancels between CA calls; a pending native call must finish first.

PowerShell (Out-Host waits for this GUI executable and preserves its exit code):
  .\Certitude.exe export --output issued.csv --fields 'RequestID,CommonName,NotAfter' `
      --where 'Disposition=Issued' --where 'NotAfter<today+30d' | Out-Host
  $LASTEXITCODE
Command Prompt: prefix the command with start """" /wait.
Start without arguments for the GUI.";
    }
}
