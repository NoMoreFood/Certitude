//
// Copyright (c) Bryan Berns.
// Licensed under GPLv3. See LICENSE.md.
//

using System;
using System.Globalization;
using System.Linq;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using Calendar = System.Windows.Controls.Calendar;

namespace Certitude
{
    public sealed class DateTimePicker : TextBox
    {
        public static readonly DependencyProperty IsPickerEnabledProperty = DependencyProperty.Register(
            nameof(IsPickerEnabled), typeof(bool), typeof(DateTimePicker), new PropertyMetadata(true,
                (target, args) => { if (!(bool)args.NewValue) ((DateTimePicker)target).ClosePicker(false); }));
        private readonly ComboBox[] clock = new ComboBox[3];
        private Button pickerButton;
        private Popup popup;
        private Calendar calendar;
        private TextBlock error;
        private DateTime originalUtc;
        private long fractionalTicks;
        internal string EntryFormat { get; set; }
        public bool IsPickerEnabled
        {
            get => (bool)GetValue(IsPickerEnabledProperty);
            set => SetValue(IsPickerEnabledProperty, value);
        }

        public DateTimePicker()
        {
            // Dismiss an open picker when navigation removes or disables its editor.
            Unloaded += (sender, args) => ClosePicker(false);
            IsEnabledChanged += (sender, args) => { if (!IsEnabled) ClosePicker(false); };
        }

        public override void OnApplyTemplate()
        {
            // Reconnect template parts without retaining handlers from a replaced template.
            ClosePicker(false);
            if (pickerButton != null) pickerButton.Click -= PickerClick;
            base.OnApplyTemplate();
            pickerButton = GetTemplateChild("PART_PickerButton") as Button;
            popup = GetTemplateChild("PART_PickerPopup") as Popup;
            if (pickerButton != null) pickerButton.Click += PickerClick;
        }

        protected override void OnPreviewKeyDown(KeyEventArgs args)
        {
            // Offer the same keyboard shortcuts as a native date picker while retaining text editing.
            if (popup?.IsOpen != true && (args.Key == Key.F4 || args.Key == Key.System &&
                args.SystemKey == Key.Down && Keyboard.Modifiers == ModifierKeys.Alt))
            {
                if (IsPickerEnabled && !IsReadOnly && IsEnabled)
                {
                    TogglePicker();
                    args.Handled = true;
                    return;
                }
            }
            base.OnPreviewKeyDown(args);
        }

        protected override void OnTextChanged(TextChangedEventArgs args)
        {
            // Discard a stale popup selection when restored filters or time-zone changes replace its entry.
            ClosePicker(false);
            base.OnTextChanged(args);
        }

        private void PickerClick(object sender, RoutedEventArgs args) => TogglePicker();

        private void TogglePicker()
        {
            // Seed the calendar from the current entry without changing text until Apply is chosen.
            if (popup == null || !IsPickerEnabled || IsReadOnly || !IsEnabled) return;
            if (popup.IsOpen) { ClosePicker(); return; }
            if (popup.Child == null) BuildPicker();
            var utc = DateTime.UtcNow;
            var preserveFraction = false;
            if (!string.IsNullOrWhiteSpace(Text))
            {
                try { utc = TimeDisplay.Parse(Text, format: EntryFormat); preserveFraction = true; }
                catch (Exception exception) when (exception is FormatException or ArgumentException) { }
            }
            SetSelection(utc, preserveFraction);
            error.Text = "";
            popup.IsOpen = true;
            calendar.Focus();
        }

        private void BuildPicker()
        {
            // Use the shared calendar and input styles so the popup follows themes and contrast colors.
            var panel = new StackPanel { Margin = new Thickness(8) };
            KeyboardNavigation.SetTabNavigation(panel, KeyboardNavigationMode.Cycle);
            calendar = new Calendar { Style = (Style)FindResource("CalendarStyle") };
            panel.Children.Add(calendar);
            var caption = new TextBlock { Margin = new Thickness(0, 6, 0, 4), FontWeight = FontWeights.SemiBold };
            TimeDisplay.Label(caption, TextBlock.TextProperty, "Time (UTC)");
            panel.Children.Add(caption);

            // Provide selectable and editable 24-hour time components with explicit accessible labels.
            var time = new StackPanel { Orientation = Orientation.Horizontal };
            var labels = new[] { "Hour", "Minute", "Second" };
            for (var i = 0; i < clock.Length; i++)
            {
                var field = new StackPanel { Margin = new Thickness(0, 0, i == 2 ? 0 : 8, 0) };
                var box = new ComboBox { Width = 64, IsEditable = true, IsTextSearchEnabled = false,
                    MaxDropDownHeight = 220, ItemsSource = Enumerable.Range(0, i == 0 ? 24 : 60)
                        .Select(value => value.ToString("D2", CultureInfo.InvariantCulture)).ToArray() };
                var label = new Label { Content = labels[i], Target = box, Padding = new Thickness(0),
                    Margin = new Thickness(0, 0, 0, 3) };
                AutomationProperties.SetLabeledBy(box, label);
                field.Children.Add(label);
                field.Children.Add(box);
                time.Children.Add(field);
                clock[i] = box;
            }
            panel.Children.Add(time);
            error = new TextBlock { TextWrapping = TextWrapping.Wrap, MaxWidth = 260,
                Margin = new Thickness(0, 5, 0, 0) };
            error.SetResourceReference(ForegroundProperty, "Ink");
            panel.Children.Add(error);

            // Keep optional empty values available and commit the complete timestamp in one text change.
            var actions = new WrapPanel { Margin = new Thickness(0, 8, 0, 0) };
            panel.Children.Add(actions);
            Glyphs.SetIcon(Dialogs.Button(actions, "_Now", () =>
            {
                SetSelection(DateTime.UtcNow, false);
                error.Text = "";
            }), Glyphs.Calendar);
            Glyphs.SetIcon(Dialogs.Button(actions, "_Clear", () => SetText("")), Glyphs.Cancel);
            Glyphs.SetIcon(Dialogs.Button(actions, "_Apply", ApplySelection), Glyphs.Check);
            var border = new Border { Child = panel, BorderThickness = new Thickness(1) };
            border.SetResourceReference(BackgroundProperty, "Surface");
            border.SetResourceReference(BorderBrushProperty, "Border");
            border.PreviewKeyDown += (sender, args) =>
            {
                // Close without editing on Escape and accept time edits on Enter.
                if (args.Key == Key.Escape) { ClosePicker(); args.Handled = true; }
                else if (args.Key == Key.Enter && !calendar.IsKeyboardFocusWithin && args.OriginalSource is not Button)
                {
                    ApplySelection();
                    args.Handled = true;
                }
            };
            popup.Child = border;
        }

        private void SetSelection(DateTime utc, bool preserveFraction = true)
        {
            // Preserve subsecond precision and the existing instant through an unchanged picker selection.
            fractionalTicks = EntryFormat == null && preserveFraction ? utc.Ticks % TimeSpan.TicksPerSecond : 0;
            originalUtc = utc.AddTicks(fractionalTicks - utc.Ticks % TimeSpan.TicksPerSecond);
            var date = TimeDisplay.Display(originalUtc);
            calendar.DisplayMode = CalendarMode.Month;
            calendar.DisplayDate = date.Date;
            calendar.SelectedDate = date.Date;
            var parts = new[] { date.Hour, date.Minute, date.Second };
            for (var i = 0; i < clock.Length; i++) clock[i].SelectedIndex = parts[i];
        }

        private void ApplySelection()
        {
            // Validate the full selection before replacing the entry or triggering live filters.
            if (!calendar.SelectedDate.HasValue) { error.Text = "Select a date."; return; }
            var parts = new int[3];
            for (var i = 0; i < clock.Length; i++)
            {
                if (int.TryParse(clock[i].Text.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out parts[i]) &&
                    parts[i] >= 0 && parts[i] < (i == 0 ? 24 : 60)) continue;
                error.Text = "Enter an hour from 0 to 23, and minutes and seconds from 0 to 59.";
                clock[i].Focus();
                return;
            }
            try
            {
                // Apply the selected zone's daylight-saving rules without shifting nonexistent local times.
                var selected = DateTime.SpecifyKind(calendar.SelectedDate.Value.Date, DateTimeKind.Unspecified)
                    .AddHours(parts[0]).AddMinutes(parts[1]).AddSeconds(parts[2]).AddTicks(fractionalTicks);
                var utc = selected == TimeDisplay.Display(originalUtc) ? originalUtc :
                    TimeDisplay.Parse(selected.ToString("yyyy-MM-dd HH:mm:ss.FFFFFFF", CultureInfo.InvariantCulture));
                SetText(EntryFormat == null ? TimeDisplay.Entry(utc) :
                    TimeDisplay.Format(utc, EntryFormat + (TimeDisplay.Current.UseUtc ? "" : " zzz")));
            }
            catch (Exception exception) when (exception is FormatException or ArgumentException)
            {
                error.Text = exception.Message;
            }
        }

        private void SetText(string text)
        {
            ClosePicker();
            SetCurrentValue(TextProperty, text);
            CaretIndex = Text.Length;
        }

        private void ClosePicker(bool focus = true)
        {
            if (popup == null || !popup.IsOpen) return;
            popup.IsOpen = false;
            if (focus) Focus();
        }
    }
}
