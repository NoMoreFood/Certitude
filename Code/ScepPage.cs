//
// Copyright (c) Bryan Berns.
// Licensed under GPLv3. See LICENSE.md.
//

using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;

namespace Certitude
{
    internal sealed class ScepPage : WorkspacePage
    {
        private readonly Action<string> record;
        private readonly StackPanel editor = new StackPanel();
        private readonly TextBox endpoint, identifier, subject, fingerprint;
        private readonly PasswordBox challenge = new PasswordBox { MaxLength = 4096 };
        private readonly Expander enrollment;
        private readonly Button check, cancel, save, enroll, poll, view;
        private readonly TextBlock status = new TextBlock { TextWrapping = TextWrapping.Wrap };
        private readonly TextBox output = Dialogs.OutputBox();
        private CancellationTokenSource cancellation;
        private ScepTester server;
        private ScepEnrollment transaction;
        private TimeReport report;
        private byte[] issued;

        internal ScepPage(Action<string> record)
        {
            // Keep discovery available without a CA connection, account credentials or an enrollment request.
            this.record = record;
            Title = "SCEP Tester";
            var layout = new DockPanel { Margin = new Thickness(8) };
            DockPanel.SetDock(editor, Dock.Top);
            layout.Children.Add(editor);
            var target = new WrapPanel();
            editor.Children.Add(target);
            endpoint = new TextBox { Width = 394 };
            Dialogs.StackedField(target, "_Endpoint URL", endpoint);
            endpoint.ToolTip = "https://server.example.com/certsrv/mscep/mscep.dll";
            identifier = new TextBox { Width = 215 };
            Dialogs.StackedField(target, "CA _Identifier (Optional)", identifier);
            var actions = new WrapPanel();
            editor.Children.Add(actions);
            check = Dialogs.Button(actions, "_Check Endpoint", async () =>
            {
                if (transaction?.CanPoll == true) Reset();
                else await Run(false);
            });
            check.ToolTip = "Retrieve the SCEP capabilities and CA/RA certificates.";

            // Collect enrollment-only inputs separately and keep the challenge out of reports and saved settings.
            var form = new StackPanel { Margin = new Thickness(6, 0, 0, 0) };
            enrollment = new Expander { Header = "Test Enrollment (Optional)", Content = form, IsEnabled = false };
            enrollment.SetResourceReference(ForegroundProperty, "Ink");
            editor.Children.Add(enrollment);
            var identity = new WrapPanel { Margin = new Thickness(0, 5, 0, 0) };
            form.Children.Add(identity);
            subject = new TextBox { Text = "CN=Certitude SCEP Test", Width = 300 };
            Dialogs.StackedField(identity, "Test Certificate _Subject", subject);
            challenge.Width = 285;
            Dialogs.StackedField(identity, "Challenge _Password (If Required)", challenge);
            fingerprint = Dialogs.Field(form, "Trusted CA _Fingerprint (Required for HTTP)", width: 580);
            fingerprint.ToolTip = "SHA-256 or SHA-1 fingerprint of the CA certificate, obtained from a trusted source.";
            var submit = new WrapPanel { Margin = new Thickness(0, 6, 0, 0) };
            form.Children.Add(submit);
            enroll = Dialogs.Button(submit, "Sub_mit Test Enrollment…", async () => await Run(true));
            poll = Dialogs.Button(submit, "Check Pending _Request", async () => await Run(true, true));
            view = Dialogs.Button(submit, "_View Issued Certificate…", async () =>
                await Dialogs.Certificate(this, issued, refreshNames: false));
            poll.Visibility = view.Visibility = Visibility.Collapsed;

            // Keep cancellation, status and report export visible while the form scrolls.
            var footer = new StackPanel { Margin = new Thickness(0, 5, 0, 0) };
            DockPanel.SetDock(footer, Dock.Bottom);
            layout.Children.Add(footer);
            footer.Children.Add(status);
            var buttons = new WrapPanel();
            footer.Children.Add(buttons);
            cancel = Dialogs.Button(buttons, "C_ancel", Cancel);
            save = Dialogs.Button(buttons, "Save Rep_ort…", async () => await Dialogs.SaveFile(this,
                "Certitude-SCEP.txt", "Text|*.txt", _ => Encoding.UTF8.GetBytes(report.ToString()), status));
            cancel.IsEnabled = save.IsEnabled = false;
            layout.Children.Add(output);
            Dialogs.ScrollHeader(layout, editor);
            Content = layout;
            endpoint.TextChanged += (sender, e) => Reset();
            identifier.TextChanged += (sender, e) => Reset();
            Closing += (sender, e) =>
            {
                if (cancellation == null) return;
                e.Cancel = true;
                Cancel();
            };
            Closed += () => { challenge.Clear(); transaction?.Dispose(); };
        }

        private void Cancel()
        {
            // Keep the page and transaction alive until the interrupted request has unwound.
            cancel.IsEnabled = false;
            status.Text = "Cancelling the SCEP operation…";
            cancellation?.Cancel();
        }

        private void Reset()
        {
            // Invalidate the discovery and its key whenever the target changes or discovery restarts.
            transaction?.Dispose();
            transaction = null;
            server = null;
            report = null;
            issued = null;
            output.Clear();
            status.Text = "";
            check.Content = "_Check Endpoint";
            endpoint.IsEnabled = identifier.IsEnabled = true;
            enrollment.IsExpanded = enrollment.IsEnabled = save.IsEnabled = false;
            enroll.Visibility = Visibility.Visible;
            poll.Visibility = view.Visibility = Visibility.Collapsed;
            subject.IsEnabled = challenge.IsEnabled = fingerprint.IsEnabled = true;
            challenge.Clear();
            fingerprint.Clear();
        }

        private async Task Run(bool submit, bool pending = false)
        {
            if (cancellation != null) return;
            using var cursor = BusyCursor.Enter();
            using var operation = new CancellationTokenSource();
            cancellation = operation;
            var token = operation.Token;
            editor.IsEnabled = false;
            save.IsEnabled = false;
            try
            {
                if (!submit)
                {
                    // Keep one discovery snapshot bound to the exact endpoint and CA identifier tested.
                    Reset();
                    var target = new ScepTester(endpoint.Text, identifier.Text);
                    status.Text = "Checking SCEP capabilities and CA certificates…";
                    cancel.IsEnabled = true;
                    await Task.Run(() => target.Discover(token), token);
                    server = target;
                    report = target.Report;
                    enrollment.IsEnabled = target.Certificates.Length > 0;
                    status.Text = target.Summary;
                    return;
                }

                // Review the real CA-side effect before creating a test key or submitting a request.
                if (server?.Certificates.Length is not > 0 || pending != (transaction?.CanPoll == true)) return;
                var name = subject.Text.Trim();
                var pin = fingerprint.Text.Trim();
                if (!pending)
                {
                    if (name.Length == 0) throw new ArgumentException("Enter a test certificate subject.");
                    issued = null;
                    status.Text = "Verifying the enrollment authorities…";
                    cancel.IsEnabled = true;
                    transaction = await Task.Run(() => new ScepEnrollment(server, name, pin), token);
                    token.ThrowIfCancellationRequested();
                    if (!await Dialogs.Confirm(this, "Submit Test Enrollment",
                        server.Endpoint.AbsoluteUri + (identifier.Text.Length == 0 ? "" :
                        "\r\nCA identifier: " + identifier.Text) + "\r\nSubject: " + name + "\r\n" +
                        transaction.AuthoritySummary +
                        "\r\n\r\nSubmit a real certificate request to this endpoint? " +
                        "The CA can retain the request and issue a certificate. Certitude keeps the public " +
                        "certificate in the report and discards the temporary private key when the test ends. " +
                        "Revoke the test certificate at the CA when you are finished.", token))
                    { status.Text = "Enrollment cancelled."; return; }
                    token.ThrowIfCancellationRequested();
                    report.AppendLine().AppendLine("Test subject: " + name).AppendLine(transaction.AuthoritySummary)
                        .AppendLine("Transaction ID: " + transaction.TransactionId);
                }

                // Keep the same key available to poll pending requests and recover a missing response.
                var secret = pending ? null : challenge.Password;
                challenge.Clear();
                cancel.IsEnabled = true;
                status.Text = pending ? "Checking the pending SCEP request…" : "Submitting test enrollment…";
                var outcome = await Task.Run(() => transaction.Exchange(secret, pending, token), token);
                issued = transaction.IssuedCertificate;
                report.AppendLine(outcome);
                if (issued != null)
                    report.AppendLine(Encoding.ASCII.GetString(CertificateUtilities.ExportPublic([issued], 1)))
                        .AppendLine("Revoke the test certificate at the CA when you are finished.");
                status.Text = outcome.Split('\r')[0];
            }
            catch (Exception error)
            {
                status.Text = error is OperationCanceledException ? "SCEP operation cancelled." : error.Message;
                report?.AppendLine(status.Text);
                if (transaction?.CanPoll == true)
                    report.AppendLine("The CA may have received the request. Check its status with this transaction.");
            }
            finally
            {
                // Release finished keys and expose only the actions available for this transaction.
                if (submit) challenge.Clear();
                var canPoll = transaction?.CanPoll == true;
                if (!canPoll) { transaction?.Dispose(); transaction = null; }
                check.Content = canPoll ? "End _Test" : "_Check Endpoint";
                endpoint.IsEnabled = identifier.IsEnabled = !canPoll;
                enroll.Visibility = canPoll ? Visibility.Collapsed : Visibility.Visible;
                poll.Visibility = canPoll ? Visibility.Visible : Visibility.Collapsed;
                view.Visibility = issued != null ? Visibility.Visible : Visibility.Collapsed;
                subject.IsEnabled = challenge.IsEnabled = fingerprint.IsEnabled = !canPoll;
                if (report != null) TimeDisplay.Text(output, () => report?.ToString() ?? "");
                save.IsEnabled = report != null;
                cancel.IsEnabled = false;
                editor.IsEnabled = true;
                cancellation = null;
                record?.Invoke(status.Text);
            }
        }
    }
}
