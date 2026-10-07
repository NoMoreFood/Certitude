//
// Copyright (c) Bryan Berns.
// Licensed under GPLv3. See LICENSE.md.
//

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;

namespace Certitude
{
    internal sealed class SearchProgress
    {
        internal sealed class Source(SearchProgress owner, string configuration)
        {
            private long received, response = Stopwatch.GetTimestamp();
            private int calls, responded, completed, unavailable;
            private string stage = "Waiting to start";
            internal string Configuration { get; } = configuration;
            internal long Received => Interlocked.Read(ref received);
            internal bool Completed => Volatile.Read(ref completed) != 0;

            internal readonly struct Call(Source source) : IDisposable
            {
                public void Dispose() => Interlocked.Decrement(ref source.calls);
            }

            internal Call BeginCall(string message)
            {
                // Track outstanding calls without posting a UI update for every row or network request.
                Volatile.Write(ref stage, message);
                if (Interlocked.Increment(ref calls) == 1 && Volatile.Read(ref responded) == 0)
                    Interlocked.Exchange(ref response, Stopwatch.GetTimestamp());
                return new Call(this);
            }

            internal void Response(int count = 0)
            {
                // Record successful responses independently of whether their rows match the search.
                Interlocked.Add(ref received, count);
                Interlocked.Add(ref owner.received, count);
                Interlocked.Exchange(ref response, Stopwatch.GetTimestamp());
                Volatile.Write(ref responded, 1);
            }

            internal void Complete(bool failed = false)
            {
                if (failed) Volatile.Write(ref unavailable, 1);
                Volatile.Write(ref completed, 1);
            }

            internal string Describe(long now, out bool waiting)
            {
                // Make a silent WAN call visible while keeping an active local scan distinct.
                var seconds = (now - Interlocked.Read(ref response)) / (double)Stopwatch.Frequency;
                waiting = !Completed && Volatile.Read(ref calls) > 0 && seconds >= 3;
                var message = Completed ? Volatile.Read(ref unavailable) != 0 ? "Unavailable" : "Finished" :
                    waiting ? Volatile.Read(ref responded) != 0 ?
                        $"Waiting for CA response ({seconds:N0}s since last response)" :
                        $"Waiting for first CA response ({seconds:N0}s)" : Volatile.Read(ref stage);
                return Configuration + " · " + message + $" · {Received:N0} records read";
            }
        }

        internal readonly struct Display(string title, string summary, string details)
        {
            internal readonly string Title = title, Summary = summary, Details = details;
        }

        private readonly ConcurrentDictionary<string, Source> sources =
            new ConcurrentDictionary<string, Source>(StringComparer.OrdinalIgnoreCase);
        private readonly Stopwatch watch = Stopwatch.StartNew();
        private long received, matches;
        private string stage = "Starting search";
        internal long Received => Interlocked.Read(ref received);
        internal long Matches => Interlocked.Read(ref matches);

        internal Source For(string configuration) => sources.GetOrAdd(configuration, name => new Source(this, name));
        internal void SetStage(string message) => Volatile.Write(ref stage, message);
        internal void Found() => Interlocked.Increment(ref matches);
        internal void SetMatches(long count) => Interlocked.Exchange(ref matches, count);

        internal IEnumerable<CertificateRow> CountMatches(IEnumerable<CertificateRow> rows)
        {
            // Count accepted results at the consumer so OR branches and parallel readers do not double-count them.
            foreach (var row in rows)
            {
                Found();
                yield return row;
            }
        }

        internal void Sorting(long count)
        {
            SetMatches(count);
            foreach (var source in sources.Values) source.Complete();
            SetStage("Sorting matching records");
        }

        internal Display Describe(bool cancelling)
        {
            // Poll a query-scoped snapshot so delayed updates cannot overwrite a newer search.
            var now = Stopwatch.GetTimestamp();
            var waiting = 0;
            var active = 0;
            var details = sources.Values.OrderBy(source => source.Configuration, StringComparer.OrdinalIgnoreCase)
                .Select(source =>
            {
                var text = source.Describe(now, out var stalled);
                if (!source.Completed) active++;
                if (stalled) waiting++;
                return text;
            }).ToArray();
            var title = cancelling ? "Stopping search" : Volatile.Read(ref stage);
            if (!cancelling && active > 0 && waiting == active) title = "Waiting for CA response";
            var elapsed = watch.Elapsed;
            var time = elapsed.ToString(elapsed.TotalHours >= 1 ? @"h\:mm\:ss" : @"m\:ss");
            var summary = $"{time} elapsed · {Received:N0} records read · {Matches:N0} matches found";
            if (details.Length > 1)
                summary += $" · {details.Length - active:N0}/{details.Length:N0} CAs finished";
            return new Display(title, summary, string.Join(Environment.NewLine, details));
        }
    }
}
