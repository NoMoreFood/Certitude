//
// Copyright (c) Bryan Berns.
// Licensed under GPLv3. See LICENSE.md.
//

using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.ServiceProcess;

namespace Certitude
{
    internal enum MaintenanceOperation { Health, BackupDatabase, BackupAndLogs, BackupCa, Configuration, Integrity, Compact }

    internal sealed class MaintenancePlan
    {
        public MaintenanceOperation Operation { get; set; }
        public string Configuration { get; set; }
        public string Database { get; set; }
        public string Destination { get; set; }
        public string TemporaryDatabase { get; set; }
        public string Review { get; set; }
    }

    internal static class CaMaintenance
    {
        private const string ServiceKey = @"SYSTEM\CurrentControlSet\Services\CertSvc";
        private const string ConfigurationKey = ServiceKey + @"\Configuration";

        public static string Caption(MaintenanceOperation operation)
        {
            // Keep action labels consistent between selection, review, and result reporting.
            switch (operation)
            {
                case MaintenanceOperation.Health: return "Check CA Connectivity";
                case MaintenanceOperation.BackupDatabase: return "Back Up Database";
                case MaintenanceOperation.BackupAndLogs: return "Back Up And Truncate Logs";
                case MaintenanceOperation.BackupCa: return "Back Up CA And Private Key";
                case MaintenanceOperation.Configuration: return "Export CA Configuration";
                case MaintenanceOperation.Integrity: return "Check Database Integrity";
                case MaintenanceOperation.Compact: return "Compact Database";
                default: throw new ArgumentOutOfRangeException(nameof(operation));
            }
        }

        public static string Description(MaintenanceOperation operation)
        {
            // Describe maintenance effects and recovery expectations before user approval.
            switch (operation)
            {
                case MaintenanceOperation.Health:
                    return "Check the selected CA's request and administration interfaces, then read CA information.";
                case MaintenanceOperation.BackupDatabase:
                    return "Create a full online database backup and export CA configuration. Preserve transaction logs.";
                case MaintenanceOperation.BackupAndLogs:
                    return "Create a full online database backup and let Certificate Services truncate backed-up logs.";
                case MaintenanceOperation.BackupCa:
                    return "Back up the database, CA signing certificate and exportable private key with password protection. " +
                        "Export CA configuration and preserve transaction logs. HSM keys require their provider's backup tools.";
                case MaintenanceOperation.Configuration:
                    return "Export the local CA's registry configuration for recovery. This does not include private keys.";
                case MaintenanceOperation.Integrity:
                    return "Temporarily stop Certificate Services and check the active database with Windows ESE. " +
                        "This check does not repair or delete records.";
                case MaintenanceOperation.Compact:
                    return "Back up the database and configuration, then stop Certificate Services and reclaim unused " +
                        "database space with Windows ESE. Retain all records and a copy of the original database.";
                default: throw new ArgumentOutOfRangeException(nameof(operation));
            }
        }

        internal static void ValidateLocalTarget(string configuration)
        {
            // Match both the local host and active CA before allowing database or service changes.
            var parsed = new CertificateStore(configuration).Configuration;
            var separator = parsed.IndexOf('\\');
            var local = CertificateStore.LocalConfiguration();
            if (!CaServerStatistics.IsLocalHost(parsed.Substring(0, separator)) || string.IsNullOrEmpty(local) ||
                !string.Equals(parsed.Substring(separator + 1), local.Substring(local.IndexOf('\\') + 1),
                    StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Run database maintenance on the selected CA server. " +
                    "The selection must match this machine's active CA.");

            // Require elevation for changes to local CA files or service configuration.
            using (var identity = WindowsIdentity.GetCurrent())
                if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
                    throw new InvalidOperationException("Run Certitude as administrator for local CA maintenance.");
        }

        public static MaintenancePlan Prepare(MaintenanceOperation operation, string configuration, string folder)
        {
            // Build the review first and allow remote connectivity checks without a local backup plan.
            var plan = new MaintenancePlan { Operation = operation,
                Configuration = new CertificateStore(configuration).Configuration };
            plan.Review = Caption(operation) + "\r\nCA: " + configuration + "\r\n\r\n" + Description(operation);
            if (operation == MaintenanceOperation.Health) return plan;
            ValidateLocalTarget(configuration);

            // Choose a unique folder on a local fixed drive without creating it before confirmation.
            var directory = Path.GetFullPath(Environment.ExpandEnvironmentVariables(folder.Trim().Trim('"')));
            if (!Directory.Exists(directory) || new DriveInfo(Path.GetPathRoot(directory)).DriveType != DriveType.Fixed)
                throw new ArgumentException("Choose an existing backup folder on a local fixed drive.");
            plan.Destination = Path.Combine(directory, "Certitude-" + operation + "-" +
                DateTime.Now.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture) + "-" + Guid.NewGuid().ToString("N"));
            plan.Review += "\r\n\r\nNew Backup / Results Folder:\r\n" + plan.Destination;
            if (operation == MaintenanceOperation.Configuration) return plan;

            // Discover the database only while the running CA can report its authoritative name.
            using (var service = new ServiceController("CertSvc"))
                if (service.Status != ServiceControllerStatus.Running)
                    throw new InvalidOperationException("Start Certificate Services before preparing this operation.");
            var name = CaAdministration.Use(configuration,
                admin => Convert.ToString(admin.GetCAProperty(configuration, 7, 0, 4, 0)));
            if (string.IsNullOrWhiteSpace(name) || name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
                throw new InvalidOperationException("The CA did not return a valid database name.");

            // Resolve the database path from the local CA registry configuration.
            using (var key = Registry.LocalMachine.OpenSubKey(ConfigurationKey))
            {
                var databaseDirectory = Convert.ToString(key?.GetValue("DBDirectory"));
                if (!Path.IsPathRooted(databaseDirectory))
                    throw new InvalidOperationException("The CA database directory is unavailable.");
                plan.Database = Path.Combine(databaseDirectory, name + ".edb");
            }
            // Validate the database and choose a separate temporary path before estimating storage needs.
            if (!File.Exists(plan.Database)) throw new FileNotFoundException("The active CA database was not found.", plan.Database);
            plan.TemporaryDatabase = Path.Combine(Path.GetDirectoryName(plan.Database),
                "Certitude-" + Guid.NewGuid().ToString("N") + ".edb");
            CheckSpace(plan);

            // Include database size and expected downtime in the maintenance confirmation.
            plan.Review += "\r\n\r\nActive Database:\r\n" + plan.Database + "\r\nCurrent Size: " +
                CaServerStatistics.Size(new FileInfo(plan.Database).Length);
            if (operation == MaintenanceOperation.Compact || operation == MaintenanceOperation.Integrity)
                plan.Review += "\r\n\r\nCA Downtime: Certificate Services will be temporarily disabled and stopped. " +
                    "Its startup mode and running state will be restored afterward. " +
                    "Wait for maintenance to finish before closing Certitude.";
            return plan;
        }

        private static void CheckSpace(MaintenancePlan plan)
        {
            // Reserve working space and include database and transaction-log backup sizes.
            var size = new FileInfo(plan.Database).Length;
            var needs = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
            var outputDrive = Path.GetPathRoot(plan.Destination);
            needs[outputDrive] = 256L * 1024 * 1024;
            if (plan.Operation != MaintenanceOperation.Integrity)
            {
                using (var key = Registry.LocalMachine.OpenSubKey(ConfigurationKey))
                {
                    var logs = Convert.ToString(key?.GetValue("DBLogDirectory"));
                    needs[outputDrive] += size + new DirectoryInfo(logs).EnumerateFiles("*.log").Sum(file => file.Length);
                }
            }
            // Account for the original copy and compaction workspace even when both share a volume.
            if (plan.Operation == MaintenanceOperation.Compact)
            {
                needs[outputDrive] += size;
                var databaseDrive = Path.GetPathRoot(plan.Database);
                needs.TryGetValue(databaseDrive, out var required);
                needs[databaseDrive] = required + size + size / 5 + 256L * 1024 * 1024;
            }
            // Reject the plan before maintenance if any required volume lacks sufficient free space.
            foreach (var drive in needs)
                if (new DriveInfo(drive.Key).AvailableFreeSpace < drive.Value)
                    throw new IOException("Insufficient free space on " + drive.Key + ". Allow at least " +
                        CaServerStatistics.Size(drive.Value) + " for this operation.");
        }

        public static void Execute(MaintenancePlan plan, string password, Action<string> output)
        {
            // Redact the backup password from every result line produced by the operation.
            var watch = Stopwatch.StartNew();
            var sink = output;
            if (!string.IsNullOrEmpty(password)) output = text => sink(text.Replace(password, "[Password]"));
            output(plan.Review);

            // Run fixed connectivity checks without preparing local file changes.
            if (plan.Operation == MaintenanceOperation.Health)
            {
                foreach (var verb in new[] { "-ping", "-pingadmin", "-CAInfo" })
                    RunTool("certutil.exe", "-config " + ToolWindow.QuoteArgument(plan.Configuration) + " " + verb, output);
                output("Connectivity Checks Completed.");
                return;
            }
            // Recheck the target, password, destination, and storage before creating maintenance output.
            ValidateLocalTarget(plan.Configuration);
            if (plan.Operation == MaintenanceOperation.BackupCa && string.IsNullOrWhiteSpace(password))
                throw new ArgumentException("Enter a password to protect the CA private-key backup.");
            if (Directory.Exists(plan.Destination) || File.Exists(plan.Destination))
                throw new IOException("The destination already exists. Prepare a new operation.");
            if (plan.Database != null) CheckSpace(plan);
            Directory.CreateDirectory(plan.Destination);
            File.WriteAllText(Path.Combine(plan.Destination, "operation.txt"), plan.Review);

            // Save recovery configuration alongside backup and compaction results.
            if (plan.Operation != MaintenanceOperation.Integrity)
            {
                RunTool("reg.exe", "export " + ToolWindow.QuoteArgument("HKLM\\" + ConfigurationKey) + " " +
                    ToolWindow.QuoteArgument(Path.Combine(plan.Destination, "CA-Configuration.reg")), output);
            }
            // Complete the online backup with the chosen key and log retention policy.
            if (plan.Operation != MaintenanceOperation.Configuration && plan.Operation != MaintenanceOperation.Integrity)
            {
                output("Creating Online Backup…");
                var backup = plan.Operation == MaintenanceOperation.BackupCa ?
                    "-p " + ToolWindow.QuoteArgument(password) + " -backup " : "-backupDB ";
                var logs = plan.Operation == MaintenanceOperation.BackupAndLogs ? "" : " KeepLog";
                RunTool("certutil.exe", "-config " + ToolWindow.QuoteArgument(plan.Configuration) + " " + backup +
                    ToolWindow.QuoteArgument(Path.Combine(plan.Destination, "Database")) + logs, output);
                output("Backup Completed: " + plan.Destination);
            }
            // Run ESE work only while the service is stopped under restoration protection.
            if (plan.Operation == MaintenanceOperation.Compact || plan.Operation == MaintenanceOperation.Integrity)
            {
                var before = new FileInfo(plan.Database).Length;
                WithOfflineService(plan.Configuration, output, () =>
                {
                    if (plan.Operation == MaintenanceOperation.Integrity)
                        RunTool("esentutl.exe", "/g " + ToolWindow.QuoteArgument(plan.Database) + " /o", output);
                    else
                    {
                        // Preserve the original database and verify the compacted copy before restarting.
                        RunTool("esentutl.exe", "/d " + ToolWindow.QuoteArgument(plan.Database) + " /o /t" +
                            ToolWindow.QuoteArgument(plan.TemporaryDatabase) + " /b" +
                            ToolWindow.QuoteArgument(Path.Combine(plan.Destination, "Original.edb")), output);
                        RunTool("esentutl.exe", "/g " + ToolWindow.QuoteArgument(plan.Database) + " /o", output);
                    }
                });

                // Report size changes after offline work and service restoration have completed.
                var after = new FileInfo(plan.Database).Length;
                output("Database Before: " + CaServerStatistics.Size(before) + "\r\nDatabase After: " +
                    CaServerStatistics.Size(after) + "\r\nSpace Reclaimed: " + CaServerStatistics.Size(Math.Max(0, before - after)));
            }
            output(Caption(plan.Operation) + " Completed In " + watch.Elapsed.TotalSeconds.ToString("N2") + "s.");
        }

        private static void WithOfflineService(string configuration, Action<string> output, Action operation)
        {
            ValidateLocalTarget(configuration);
            using (var service = new ServiceController("CertSvc"))
            using (var key = Registry.LocalMachine.OpenSubKey(ServiceKey))
            {
                // Capture running and startup states so maintenance can restore them after failure.
                var running = service.Status == ServiceControllerStatus.Running;
                if (!running && service.Status != ServiceControllerStatus.Stopped)
                    throw new InvalidOperationException("Wait for Certificate Services to finish changing state.");
                var start = Convert.ToInt32(key.GetValue("Start"));
                var delayedValue = key.GetValue("DelayedAutoStart");
                var delayed = Convert.ToInt32(delayedValue ?? 0) != 0;
                var mode = start == 2 ? delayed ? "delayed-auto" : "auto" : start == 3 ? "demand" : "disabled";
                if (start < 2 || start > 4) throw new InvalidOperationException("Unsupported Certificate Services startup mode.");
                Exception failure = null;
                try
                {
                    // Prevent restarts while the operation has exclusive access to the database.
                    output("Temporarily Disabling And Stopping Certificate Services…");
                    RunTool("sc.exe", "config CertSvc start= disabled", output);
                    if (running) service.Stop();
                    service.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(60));
                    operation();
                }
                catch (Exception error) { failure = error; }
                finally
                {
                    try
                    {
                        // Restore startup mode and running state even after an offline failure.
                        RunTool("sc.exe", "config CertSvc start= " + (running && start == 4 ? "demand" : mode), output);
                        try { if (running) output(CaAdministration.Service(configuration, "Start")); }
                        finally
                        {
                            if (running && start == 4) RunTool("sc.exe", "config CertSvc start= disabled", output);

                            // SC can clear the delayed-start flag while changing the startup type.
                            using (var settings = Registry.LocalMachine.OpenSubKey(ServiceKey, true))
                            {
                                if (delayedValue == null) settings.DeleteValue("DelayedAutoStart", false);
                                else settings.SetValue("DelayedAutoStart", delayedValue, RegistryValueKind.DWord);
                            }
                        }
                        output("Certificate Services State Restored: " + (running ? "Running" : "Stopped") + " / " + mode);
                    }
                    catch (Exception error)
                    {
                        // Preserve both failures and the original service state for manual recovery.
                        failure = new InvalidOperationException((failure == null ? "" : failure.Message + "\r\n") +
                            "Could not restore Certificate Services. Original state: " +
                            (running ? "Running" : "Stopped") + " / " + mode + ". " + error.Message, error);
                    }
                }
                if (failure != null) throw new InvalidOperationException("CA maintenance failed. " + failure.Message, failure);
            }
        }

        internal static void RunTool(string tool, string arguments, Action<string> output)
        {
            // Launch the selected Windows tool with hidden, redirected process streams.
            using (var process = new Process { StartInfo = new ProcessStartInfo
            {
                FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), tool),
                Arguments = arguments, UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true, RedirectStandardInput = true
            } })
            {
                // Forward both output streams and prevent waits for interactive input.
                process.OutputDataReceived += (sender, e) => { if (e.Data != null) output(e.Data); };
                process.ErrorDataReceived += (sender, e) => { if (e.Data != null) output(e.Data); };
                output("Running " + tool + "…");
                process.Start();
                process.StandardInput.Close();
                process.BeginOutputReadLine();
                process.BeginErrorReadLine();
                process.WaitForExit();

                // Report a nonzero native exit code after collecting diagnostic output.
                if (process.ExitCode != 0)
                    throw new InvalidOperationException(tool + " failed with exit code 0x" + process.ExitCode.ToString("X8") +
                        ". See the operation output above.");
            }
        }
    }
}
