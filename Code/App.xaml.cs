//
// Copyright (c) Bryan Berns.
// Licensed under GPLv3. See LICENSE.md.
//

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;

[assembly: AssemblyTitle("Certitude")]
[assembly: AssemblyProduct("Certitude")]
[assembly: AssemblyDescription("Windows Certificate Authority administration")]
[assembly: AssemblyVersion("1.0.4.0")]
[assembly: AssemblyFileVersion("1.0.4.0")]

namespace Certitude
{
    public sealed class TimeDisplay : INotifyPropertyChanged, IMultiValueConverter
    {
        public static TimeDisplay Current { get; } = new TimeDisplay();
        private bool useUtc;
        public bool UseUtc
        {
            get => useUtc;
            set
            {
                if (useUtc == value) return;
                useUtc = value;
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(null));
            }
        }
        public string Zone => UseUtc ? "UTC" : "Local";
        public event PropertyChangedEventHandler PropertyChanged;

        internal static DateTime Utc(DateTime date) => date.Kind == DateTimeKind.Unspecified ?
            DateTime.SpecifyKind(date, DateTimeKind.Utc) : date.ToUniversalTime();

        internal static DateTime Display(DateTime date, bool? utc = null) => (utc ?? Current.UseUtc) ?
            Utc(date) : Utc(date).ToLocalTime();

        internal static string Format(DateTime date, string format = "yyyy-MM-dd HH:mm:ss", bool? utc = null) =>
            Display(date, utc).ToString(format, CultureInfo.InvariantCulture);

        internal static string Stamp(DateTime? date, bool? utc = null) => !date.HasValue ? "Not recorded" :
            Format(date.Value, (utc ?? Current.UseUtc) ? "yyyy-MM-dd HH:mm:ss 'UTC'" : "yyyy-MM-dd HH:mm:ss zzz", utc);

        internal static string Entry(DateTime? date) => date.HasValue ? Format(date.Value,
            Current.UseUtc && date.Value.TimeOfDay == TimeSpan.Zero ? "yyyy-MM-dd" :
                "yyyy-MM-dd HH:mm:ss.FFFFFFF" + (Current.UseUtc ? "" : " zzz")) : "";

        internal static DateTime Parse(string text, bool? utc = null, string format = null)
        {
            // Interpret date editors in the selected zone while keeping native and persisted values in UTC.
            var formats = format == null ? new[] { "yyyy-MM-dd", "yyyy-MM-dd HH:mm:ss.FFFFFFF",
                "yyyy-MM-dd HH:mm:ss.FFFFFFF zzz" } : new[] { format, format + " zzz" };
            if (!DateTime.TryParseExact(text.Trim(), formats, CultureInfo.InvariantCulture,
                DateTimeStyles.None, out var date))
            {
                if (format != null) throw new FormatException("Enter the date and time as " + format + ".");
                date = DateTime.Parse(text, CultureInfo.CurrentCulture, DateTimeStyles.AllowWhiteSpaces);
            }
            if (date.Kind != DateTimeKind.Unspecified) return date.ToUniversalTime();
            if (utc ?? Current.UseUtc) return DateTime.SpecifyKind(date, DateTimeKind.Utc);
            if (TimeZoneInfo.Local.IsInvalidTime(date))
                throw new ArgumentException(
                    "This local time does not exist because of the daylight-saving transition.");
            return TimeZoneInfo.ConvertTimeToUtc(date);
        }

        internal static MultiBinding Binding(string path = null, string format = null, object source = null)
        {
            // Observe the shared display mode so existing tables and reports update immediately.
            var binding = new MultiBinding { Converter = Current, ConverterParameter = format, Mode = BindingMode.OneWay };
            binding.Bindings.Add(source == null ? new Binding(path) : new Binding(path) { Source = source });
            binding.Bindings.Add(new Binding(nameof(UseUtc)) { Source = Current });
            return binding;
        }

        internal static void Text(TextBox box, Func<string> text) =>
            box.SetBinding(TextBox.TextProperty, Binding(source: text));
        internal static void Text(TextBlock block, Func<string> text) =>
            block.SetBinding(TextBlock.TextProperty, Binding(source: text));

        internal static void Label(DependencyObject target, DependencyProperty property, string caption) =>
            BindingOperations.SetBinding(target, property,
                Binding(source: (Func<string>)(() => caption.Replace("UTC", Current.Zone))));

        internal static void Input(WorkspacePage page, TextBox box, string format = "yyyy-MM-dd HH:mm:ss",
            Func<bool> enabled = null) =>
            page.TimeChanged += previousUtc =>
            {
                // Preserve an already entered instant when its editor changes zones.
                if (string.IsNullOrWhiteSpace(box.Text) || enabled?.Invoke() == false) return;
                try { box.Text = Format(Parse(box.Text, previousUtc, format), format + (Current.UseUtc ? "" : " zzz")); }
                catch (Exception error) when (error is FormatException or ArgumentException) { }
            };

        public object Convert(object[] values, Type targetType, object parameter, CultureInfo culture) =>
            values[0] switch
        {
            DateTime date => Format(date, parameter as string ?? "yyyy-MM-dd HH:mm:ss"),
            TimeReport text => text.ToString(),
            Func<string> text => text(),
            null => "",
            _ => values[0]
        };

        public object[] ConvertBack(object value, Type[] targetTypes, object parameter, CultureInfo culture) =>
            throw new NotSupportedException();
    }

    internal sealed class TimeReport
    {
        private readonly List<object> parts = new List<object>();
        public TimeReport(string text = "") { Append(text); }
        public TimeReport Append(string text) { parts.Add(text); return this; }
        public TimeReport Append(Func<string> text) { parts.Add(text); return this; }
        public TimeReport Append(TimeReport text) { parts.AddRange(text.parts); return this; }
        public TimeReport AppendTime(DateTime? date)
        {
            parts.Add(date.HasValue ? (object)date.Value : "Not recorded"); return this;
        }
        public TimeReport AppendLine(string text = "") => Append(text).Append(Environment.NewLine);
        public TimeReport AppendLine(TimeReport text) => Append(text).Append(Environment.NewLine);
        public override string ToString()
        {
            // Retain typed timestamps until rendering, including those in nested CRL and certificate reports.
            var text = new System.Text.StringBuilder();
            foreach (var part in parts) text.Append(part switch
                { DateTime date => TimeDisplay.Stamp(date), Func<string> render => render(), _ => part });
            return text.ToString();
        }
        public static implicit operator string(TimeReport text) => text?.ToString();
    }

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
