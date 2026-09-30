//
// Copyright (c) Bryan Berns.
// Licensed under GPLv3. See LICENSE.md.
//

using System;
using System.IO;
using System.Reflection;
using System.Windows;
using System.Windows.Media;

[assembly: AssemblyTitle("Certitude")]
[assembly: AssemblyProduct("Certitude")]
[assembly: AssemblyDescription("Windows Certificate Authority administration")]
[assembly: AssemblyVersion("1.0.2.0")]
[assembly: AssemblyFileVersion("1.0.2.0")]

namespace Certitude
{
    public partial class App : Application
    {
        public static bool IsDark { get; private set; }
        private static readonly string ThemePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Certitude", "theme.txt");

        public static void ApplyTheme(bool dark, bool save = true)
        {
            // Select the shared palette so every page follows the same theme.
            IsDark = dark;
            var colors = new[,]
            {
                { "Ink", "#182D43", "#E4ECF3" },
                { "Muted", "#62778B", "#A3B5C6" },
                { "Accent", "#126C75", "#67D5D0" },
                { "AppBackground", "#F3F6F8", "#111A24" },
                { "Surface", "#FFFFFF", "#182431" },
                { "SurfaceAlt", "#EBF0F4", "#223243" },
                { "Sidebar", "#EAF0F4", "#16222F" },
                { "Header", "#182D43", "#0D151E" },
                { "HeaderInk", "#FFFFFF", "#E4ECF3" },
                { "HeaderMuted", "#C4D4E0", "#A3B5C6" },
                { "Border", "#DCE3E8", "#35495C" },
                { "GridLine", "#EDF0F3", "#283949" },
                { "AlternateRow", "#F8FAFB", "#1B2A39" },
                { "Hover", "#DFEAF0", "#30465A" },
                { "Selection", "#CDE7E8", "#245B64" },
                { "SelectionInk", "#143B40", "#EEFFFF" }
            };

            // Replace the resource brushes once so existing dynamic bindings repaint together.
            for (var i = 0; i < colors.GetLength(0); i++)
            {
                var brush = new SolidColorBrush((Color)ColorConverter.ConvertFromString(colors[i, dark ? 2 : 1]));
                brush.Freeze();
                Current.Resources[colors[i, 0]] = brush;
            }
            // Align native control colors with the application palette, including selection and disabled text.
            var systemBrushes = new object[,]
            {
                { SystemColors.WindowBrushKey, "Surface" }, { SystemColors.WindowTextBrushKey, "Ink" },
                { SystemColors.ControlBrushKey, "SurfaceAlt" }, { SystemColors.ControlTextBrushKey, "Ink" },
                { SystemColors.MenuBrushKey, "Surface" }, { SystemColors.MenuTextBrushKey, "Ink" },
                { SystemColors.HighlightBrushKey, "Selection" }, { SystemColors.HighlightTextBrushKey, "SelectionInk" },
                { SystemColors.InactiveSelectionHighlightBrushKey, "Selection" },
                { SystemColors.InactiveSelectionHighlightTextBrushKey, "SelectionInk" },
                { SystemColors.GrayTextBrushKey, "Muted" }, { SystemColors.ScrollBarBrushKey, "SurfaceAlt" }
            };
            for (var i = 0; i < systemBrushes.GetLength(0); i++)
                Current.Resources[systemBrushes[i, 0]] = Current.Resources[systemBrushes[i, 1]];

            // Update the theme action and persist explicit user changes for the next launch.
            Current.Resources["ThemeAction"] = dark ? "_Light Mode" : "_Dark Mode";
            if (!save) return;
            Directory.CreateDirectory(Path.GetDirectoryName(ThemePath));
            File.WriteAllText(ThemePath, dark ? "dark" : "light");
        }

        protected override void OnStartup(StartupEventArgs e)
        {
            // Restore the saved preference while allowing startup when its file cannot be read.
            base.OnStartup(e);
            var dark = false;
            try { dark = File.Exists(ThemePath) && File.ReadAllText(ThemePath).Trim() == "dark"; }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
            ApplyTheme(dark, false);

            // Create the main workspace after its theme resources are ready.
            var window = new MainWindow();
            MainWindow = window;
            window.Show();
        }
    }
}
