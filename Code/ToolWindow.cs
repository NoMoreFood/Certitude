//
// Copyright (c) Bryan Berns.
// Licensed under GPLv3. See LICENSE.md.
//

using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;

namespace Certitude
{
    internal sealed class ToolWindow : WorkspacePage
    {
        private readonly string config;
        private readonly Action<string> record;
        private readonly TextBox folder;
        private readonly PasswordBox password;
        private readonly TextBox output;
        private readonly TextBlock status;
        private readonly StackPanel editor;
        private readonly StringBuilder pending = new StringBuilder();
        private readonly object outputLock = new object();
        private readonly DispatcherTimer timer;
        private bool busy;

        public ToolWindow(string configuration, Action<string> log)
        {
            // Bind the maintenance workspace to the selected CA and explain its execution scope.
            config = configuration;
            record = log;
            Title = "Advanced Tools — " + config;
            var layout = new DockPanel { Margin = new Thickness(8) };
            editor = new StackPanel();
            DockPanel.SetDock(editor, Dock.Top);
            layout.Children.Add(editor);
            Dialogs.Note(editor, "Choose a maintenance operation. Database, backup and configuration operations " +
                "require this machine's active CA and administrator rights. Connectivity checks support remote CAs.");

            // Collect the destination folder and optional private-key backup password.
            folder = Dialogs.Field(editor, "Backup / Results Parent Folder (Existing Local Folder)",
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments));
            editor.Children.Add(new TextBlock { Text = "Private-Key Backup Password (CA And Private Key Backup Only)",
                Margin = new Thickness(0, 5, 0, 3) });
            password = new PasswordBox { MaxWidth = 380, HorizontalAlignment = HorizontalAlignment.Left };
            password.Width = 380;
            editor.Children.Add(password);

            // Expose the supported maintenance operations with their descriptions.
            var actions = new WrapPanel { Margin = new Thickness(0, 6, 0, 0) };
            editor.Children.Add(actions);
            foreach (MaintenanceOperation operation in Enum.GetValues(typeof(MaintenanceOperation)))
            {
                var button = Dialogs.Button(actions, CaMaintenance.Caption(operation), async () => await Execute(operation));
                button.Tag = operation;
                button.ToolTip = CaMaintenance.Description(operation);
            }
            // Keep operation status and output export controls beneath the maintenance form.
            Dialogs.Note(editor, "Each operation shows its target, destination and downtime before making changes. " +
                "Compaction creates a backup first. Offline maintenance must finish before leaving this page.");
            var footer = new StackPanel { Margin = new Thickness(0, 6, 0, 0) };
            DockPanel.SetDock(footer, Dock.Bottom);
            layout.Children.Add(footer);
            status = new TextBlock { Text = "Ready", TextWrapping = TextWrapping.Wrap };
            footer.Children.Add(status);
            var controls = new WrapPanel();
            footer.Children.Add(controls);
            Dialogs.Button(controls, "_Save Visible Output", async () =>
            {
                // Save the visible maintenance output to the selected text file.
                var save = new FilePicker(true) { FileName = "Certitude-maintenance.txt", Filter = "Text|*.txt" };
                if (await save.ShowAsync() != true) return;
                try { File.WriteAllText(save.FileName, output.Text); }
                catch (Exception error) { status.Text = CaAdministration.Error(error); }
            });

            // Provide a scrolling console-style output area for maintenance results.
            output = new TextBox
            {
                IsReadOnly = true, AcceptsReturn = true, VerticalContentAlignment = VerticalAlignment.Top,
                FontFamily = new System.Windows.Media.FontFamily("Consolas"),
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto, HorizontalScrollBarVisibility = ScrollBarVisibility.Auto
            };
            layout.Children.Add(output);
            Content = layout;

            // Batch output updates and prevent navigation before maintenance restores the service.
            timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(150) };
            timer.Tick += (sender, e) => Drain();
            Closing += (sender, e) =>
            {
                if (!busy) return;
                e.Cancel = true;
                status.Text = "Wait For Maintenance To Finish And Certificate Services To Be Restored.";
            };
        }

        public static string QuoteArgument(string value)
        {
            // Quote a Windows process argument while preserving embedded quotes and backslashes.
            var result = new StringBuilder("\"");
            var slashes = 0;
            foreach (var character in value)
            {
                if (character == '\\') { slashes++; continue; }
                result.Append('\\', character == '"' ? slashes * 2 + 1 : slashes);
                result.Append(character);
                slashes = 0;
            }
            return result.Append('\\', slashes * 2).Append('"').ToString();
        }

        private async Task Execute(MaintenanceOperation operation)
        {
            // Prevent overlapping maintenance and capture the backup password for this operation.
            if (busy) return;
            using var cursor = BusyCursor.Enter();
            busy = true;
            editor.IsEnabled = false;
            var secret = password.Password;
            try
            {
                // Prepare the target and destination, then confirm the concrete maintenance plan.
                status.Text = "Preparing " + CaMaintenance.Caption(operation) + "…";
                var directory = folder.Text;
                if (operation == MaintenanceOperation.BackupCa && string.IsNullOrWhiteSpace(secret))
                    throw new ArgumentException("Enter a password to protect the CA private-key backup.");
                var plan = await Task.Run(() => CaMaintenance.Prepare(operation, config, directory));
                if (operation != MaintenanceOperation.Health &&
                    !await Dialogs.Confirm(this, "Review CA Maintenance", plan.Review))
                { status.Text = "Cancelled. No Changes Made."; return; }

                // Run maintenance in the background while periodically displaying its output.
                status.Text = CaMaintenance.Caption(operation) + "…";
                output.Clear();
                timer.Start();
                await Task.Run(() => CaMaintenance.Execute(plan, secret, Queue));
                status.Text = CaMaintenance.Caption(operation) + " Completed";
            }
            catch (Exception error)
            {
                // Show the failure both in the status line and the captured output.
                status.Text = CaAdministration.Error(error);
                Queue("FAILED: " + status.Text);
            }
            finally
            {
                // Flush remaining output, clear backup credentials, and restore the editor.
                timer.Stop();
                Drain();
                if (operation == MaintenanceOperation.BackupCa) password.Clear();
                busy = false;
                editor.IsEnabled = true;
                record(status.Text);
            }
        }

        private void Queue(string text)
        {
            // Bound queued worker output while synchronizing access with the UI thread.
            lock (outputLock)
            {
                pending.AppendLine(text);
                if (pending.Length > 64000) pending.Remove(0, pending.Length - 64000);
            }
        }

        private void Drain()
        {
            // Drain queued output in one update and cap the visible preview size.
            string text;
            lock (outputLock) { text = pending.ToString(); pending.Clear(); }
            if (text.Length == 0) return;
            if (output.Text.Length + text.Length > 200000)
                output.Text = "Earlier Output Omitted From Preview.\r\n" +
                    output.Text.Substring(Math.Max(0, output.Text.Length - 120000));
            output.AppendText(text);
            output.ScrollToEnd();
        }
    }
}
