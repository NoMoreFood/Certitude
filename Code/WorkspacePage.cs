//
// Copyright (c) Bryan Berns.
// Licensed under GPLv3. See LICENSE.md.
//

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;

namespace Certitude
{
    internal sealed class BusyCursor : IDisposable
    {
        private static readonly List<BusyCursor> active = new List<BusyCursor>();
        private static Cursor previous;
        private static bool captured;
        private readonly Action release;
        private int suspended;
        private bool disposed;

        private BusyCursor(Action release = null) { this.release = release; }

        public static BusyCursor Enter()
        {
            // Capture the original cursor only for the outermost operation, then register this busy scope.
            if (active.Count == 0) { previous = Mouse.OverrideCursor; captured = true; }
            var scope = new BusyCursor();
            active.Add(scope);
            Apply();
            return scope;
        }

        public static BusyCursor Suspend()
        {
            // Suspend the current operations while a prompt accepts input without hiding later nested work.
            var scopes = active.ToArray();
            foreach (var scope in scopes) scope.suspended++;
            Apply();
            return new BusyCursor(() =>
            {
                // Restore only the scopes suspended by this prompt when it closes.
                foreach (var scope in scopes) scope.suspended--;
                Apply();
            });
        }

        private static void Apply()
        {
            // Keep the busy cursor until the last unsuspended operation completes.
            if (!captured) return;
            Mouse.OverrideCursor = active.Any(scope => scope.suspended == 0) ? Cursors.AppStarting : previous;
            if (active.Count == 0) captured = false;
        }

        public static void OnSorting(DataGrid grid) => grid.Sorting += (sender, e) =>
        {
            // Keep sorting feedback visible until the dispatcher has processed the grid update.
            var scope = Enter();
            grid.Dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.ContextIdle,
                new Action(scope.Dispose));
        };

        public void Dispose()
        {
            // Release this scope once and restore the cursor state of any remaining operations.
            if (disposed) return;
            disposed = true;
            if (release != null) release();
            else { active.Remove(this); Apply(); }
        }
    }

    internal class WorkspacePage : UserControl
    {
        private readonly TaskCompletionSource<bool?> completion =
            new TaskCompletionSource<bool?>(TaskCreationOptions.RunContinuationsAsynchronously);
        public string Title { get; set; }
        public DependencyObject Owner { get; set; }
        public event CancelEventHandler Closing;
        public async Task<bool?> ShowAsync()
        {
            // Await an inline page result while temporarily restoring the input cursor.
            using (BusyCursor.Suspend())
            {
                ((MainWindow)Application.Current.MainWindow).ShowPage(this);
                return await completion.Task;
            }
        }
        public void Show() => ((MainWindow)Application.Current.MainWindow).ShowPage(this);
        public bool? DialogResult { set => Close(value); }
        public void Close() => Close(null);
        private void Close(bool? result)
        {
            // Let pending work veto navigation before removing this page from the workspace.
            if (!CanClose()) return;
            ((MainWindow)Application.Current.MainWindow).ClosePage(this, result);
        }
        internal bool CanClose()
        {
            // Ask the page owner whether closing would interrupt an operation.
            var args = new CancelEventArgs();
            Closing?.Invoke(this, args);
            return !args.Cancel;
        }
        internal void Complete(bool? result) => completion.TrySetResult(result);
    }

    internal sealed class FilePicker : WorkspacePage
    {
        private readonly bool save;
        private readonly TextBox folder = new TextBox();
        private readonly TextBox names = new TextBox();
        private readonly ComboBox formats = new ComboBox();
        private readonly DataGrid files = new DataGrid { SelectionMode = DataGridSelectionMode.Single };
        private readonly TextBlock status = new TextBlock { TextWrapping = TextWrapping.Wrap };
        private string[] patterns;
        private int generation;
        private bool initialized;
        public string Filter { get; set; } = "All Files|*.*";
        public string FileName { get; set; } = "";
        public string[] FileNames { get; private set; } = new string[0];
        public int FilterIndex { get; set; } = 1;
        public bool Multiselect { get; set; }

        public FilePicker(bool save = false)
        {
            // Build folder navigation and choose the open or save workflow for this picker.
            this.save = save;
            Title = save ? "Save File" : "Open File";
            var panel = new DockPanel { Margin = new Thickness(8) };
            var header = new DockPanel { Margin = new Thickness(0, 0, 0, 6) };
            DockPanel.SetDock(header, Dock.Top);
            panel.Children.Add(header);
            var actions = Dialogs.RightActions(header);
            Dialogs.Button(actions, "_Up", async () =>
            {
                try { await ReadFolder(Directory.GetParent(folder.Text)?.FullName ?? folder.Text); }
                catch (Exception error) { status.Text = CaAdministration.Error(error); }
            });
            Dialogs.Button(actions, "_Go", async () => await ReadFolder(folder.Text));
            Dialogs.Button(actions, "New _Folder", async () =>
            {
                // Create a user-named child folder and immediately navigate into it.
                var name = await Dialogs.Prompt(this, "New Folder", "Folder Name", "");
                if (name == null) return;
                try { await ReadFolder(Directory.CreateDirectory(Path.Combine(folder.Text, name)).FullName); }
                catch (Exception error) { status.Text = CaAdministration.Error(error); }
            });
            header.Children.Add(folder);
            folder.KeyDown += async (sender, e) =>
            {
                // Treat Enter in the path field as navigation without forwarding the key to the page.
                if (e.Key != Key.Enter) return;
                e.Handled = true;
                await ReadFolder(folder.Text);
            };

            // Keep filename entry, format selection, and completion actions below the file list.
            var footer = new StackPanel();
            DockPanel.SetDock(footer, Dock.Bottom);
            panel.Children.Add(footer);
            footer.Children.Add(new TextBlock { Text = "File Name / Full Path", Margin = new Thickness(0, 6, 0, 3) });
            footer.Children.Add(names);
            var choices = new DockPanel { Margin = new Thickness(0, 6, 0, 4) };
            footer.Children.Add(choices);
            var buttons = Dialogs.RightActions(choices);
            Dialogs.Button(buttons, save ? "_Save" : "_Open", async () => await Accept());
            Dialogs.Button(buttons, "_Cancel", Close);
            choices.Children.Add(formats);
            footer.Children.Add(status);

            // Show file metadata and mirror selected filenames into the editable selection field.
            files.Columns.Add(new DataGridTextColumn { Header = "Name", Binding = new Binding("Name"),
                Width = new DataGridLength(1, DataGridLengthUnitType.Star) });
            files.Columns.Add(new DataGridTextColumn { Header = "Type", Binding = new Binding("Type"), Width = 100 });
            files.Columns.Add(new DataGridTextColumn { Header = "Modified", Binding = new Binding("Modified"), Width = 160 });
            BusyCursor.OnSorting(files);
            files.SelectionChanged += (sender, e) =>
            {
                var selected = files.SelectedItems.Cast<FileChoice>().Where(item => !item.Directory).ToArray();
                if (selected.Length > 0) names.Text = string.Join(Environment.NewLine, selected.Select(item => item.Name));
            };
            files.MouseDoubleClick += async (sender, e) =>
            {
                // Open folders on double-click and accept files only when a real row was clicked.
                if (!(files.SelectedItem is FileChoice item) ||
                    !(ItemsControl.ContainerFromElement(files, e.OriginalSource as DependencyObject) is DataGridRow)) return;
                if (item.Directory) await ReadFolder(item.Path);
                else await Accept();
            };
            formats.SelectionChanged += async (sender, e) =>
            {
                // Keep the proposed save extension and visible listing consistent with the selected format.
                FilterIndex = formats.SelectedIndex + 1;
                if (save && names.Text.Length > 0)
                {
                    var extension = patterns[formats.SelectedIndex].Split(';')[0];
                    if (extension.StartsWith("*.") && extension != "*.*")
                        names.Text = Path.ChangeExtension(names.Text, extension.Substring(1));
                }
                if (initialized) await ReadFolder(folder.Text);
            };
            panel.Children.Add(files);
            Content = panel;
            Loaded += async (sender, e) =>
            {
                // Initialize format choices and selection behavior once when the picker first becomes visible.
                if (initialized) return;
                var parts = Filter.Split('|');
                patterns = parts.Where((part, i) => i % 2 == 1).ToArray();
                formats.ItemsSource = parts.Where((part, i) => i % 2 == 0).Select(Dialogs.Caption).ToArray();
                formats.SelectedIndex = Math.Max(0, Math.Min(FilterIndex - 1, patterns.Length - 1));
                names.Text = Path.IsPathRooted(FileName) ? Path.GetFileName(FileName) : FileName;
                names.AcceptsReturn = Multiselect;
                names.Height = Multiselect ? 50 : double.NaN;
                files.SelectionMode = Multiselect ? DataGridSelectionMode.Extended : DataGridSelectionMode.Single;
                initialized = true;

                // Start in the supplied file directory or the current user documents folder.
                var path = Path.IsPathRooted(FileName) ? Path.GetDirectoryName(FileName) :
                    Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
                await ReadFolder(path);
            };
            Closing += (sender, e) => generation++;
        }

        private async Task ReadFolder(string path)
        {
            // Give this folder request an identity so a later navigation can supersede its result.
            using var cursor = BusyCursor.Enter();
            var request = ++generation;
            try
            {
                // Clear the old listing before enumerating matching entries off the UI thread.
                path = Path.GetFullPath(Environment.ExpandEnvironmentVariables(path));
                folder.Text = path;
                files.ItemsSource = null;
                status.Text = "Reading Folder…";
                var pattern = patterns[Math.Max(0, formats.SelectedIndex)].Split(';');
                var rows = await Task.Run(() => new DirectoryInfo(path).EnumerateFileSystemInfos()
                    .Where(item => (item.Attributes & FileAttributes.Directory) != 0 || pattern.Any(filter =>
                        filter == "*.*" || item.Name.EndsWith(filter.TrimStart('*'), StringComparison.OrdinalIgnoreCase)))
                    .Take(5001).Select(item => new FileChoice
                    {
                        Name = item.Name, Path = item.FullName, Directory = (item.Attributes & FileAttributes.Directory) != 0,
                        Modified = item.LastWriteTime.ToString("yyyy-MM-dd HH:mm")
                    }).OrderByDescending(item => item.Directory).ThenBy(item => item.Name).ToArray());

                // Publish only the current request and cap the displayed list while allowing full-path entry.
                if (request != generation) return;
                files.ItemsSource = rows.Take(5000).ToArray();
                status.Text = rows.Length > 5000 ? "Showing 5,000 Entries. Enter A Full Path To Select Another File." :
                    rows.Length + " Entries";
            }
            catch (Exception error) { if (request == generation) status.Text = CaAdministration.Error(error); }
        }

        private async Task Accept()
        {
            try
            {
                // Resolve typed names against the current folder and allow directory entries to navigate.
                var paths = names.Text.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                    .Select(name => Path.GetFullPath(Path.Combine(folder.Text, name.Trim().Trim('"')))).ToArray();
                if (paths.Length == 0 || (!Multiselect && paths.Length != 1))
                    throw new ArgumentException("Enter a file path.");
                if (paths.Length == 1 && Directory.Exists(paths[0])) { await ReadFolder(paths[0]); return; }

                // Apply the selected save extension and reject missing files or destination folders.
                var extension = patterns[formats.SelectedIndex].Split(';')[0];
                if (save && !Path.HasExtension(paths[0]) && extension.StartsWith("*.") && extension != "*.*")
                    paths[0] += extension.Substring(1);
                if (!save && paths.Any(path => !File.Exists(path))) throw new FileNotFoundException("A selected file does not exist.");
                if (save && !Directory.Exists(Path.GetDirectoryName(paths[0])))
                    throw new DirectoryNotFoundException("The destination folder does not exist.");

                // Confirm replacement before returning the chosen paths to the calling workflow.
                if (save && File.Exists(paths[0]) && !await Dialogs.Confirm(this, "Replace File", paths[0])) return;
                FileNames = paths;
                FileName = paths[0];
                DialogResult = true;
            }
            catch (Exception error) { status.Text = CaAdministration.Error(error); }
        }

        private sealed class FileChoice
        {
            public string Name { get; set; }
            public string Path { get; set; }
            public string Modified { get; set; }
            public bool Directory { get; set; }
            public string Type => Directory ? "Folder" : "File";
        }
    }
}
