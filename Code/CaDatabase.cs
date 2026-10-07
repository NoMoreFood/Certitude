//
// Copyright (c) Bryan Berns.
// Licensed under GPLv3. See LICENSE.md.
//

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace Certitude
{
    internal readonly struct DatabaseRestriction(string field, int seek, object value, int sort = 0)
    {
        internal readonly string Field = field;
        internal readonly int Seek = seek, Sort = sort;
        internal readonly object Value = value;
    }

    internal sealed class DatabaseRecord(object[] values, ICertViewRow nativeRow = null)
    {
        internal object[] Values { get; } = values;
        internal ICertViewRow NativeRow { get; } = nativeRow;
    }

    internal static class CaDatabase
    {
        private readonly struct Column(int index, int type)
        {
            internal readonly int Index = index, Type = type;
        }
        private static readonly ConcurrentDictionary<string, Dictionary<string, Column>> schemas =
            new ConcurrentDictionary<string, Dictionary<string, Column>>(StringComparer.OrdinalIgnoreCase);
        private static readonly Guid AdministrationClass = new Guid("d99e6e73-fc88-11d0-b498-00a0c90312f3");
        private const string InvalidResponse = "The CA returned invalid database data.";

        [DllImport("ole32.dll")]
        private static extern int CoSetProxyBlanket(IntPtr proxy, uint authentication, uint authorization,
            IntPtr principal, uint level, uint impersonation, IntPtr identity, uint capabilities);

        internal static IEnumerable<DatabaseRecord> Read(string configuration, string[] fields,
            IEnumerable<DatabaseRestriction> restrictions, CancellationToken token, int maximum = int.MaxValue,
            int table = 0, bool nativeExtensions = false, int batchSize = 1000, SearchProgress progress = null)
        {
            // Keep per-request extension access on the native view and batch ordinary metadata over RPC.
            if (table != 0 || nativeExtensions)
            {
                foreach (var record in ReadNative(configuration, fields, restrictions, token, maximum, table, progress))
                    yield return record;
                yield break;
            }
            using var rows = ReadRpc(configuration, fields, restrictions.ToArray(), token, maximum, batchSize, progress)
                .GetEnumerator();
            var available = false;
            var fallback = false;
            try { available = rows.MoveNext(); }
            catch (COMException error) when (error.HResult is unchecked((int)0x80040154) or
                unchecked((int)0x80040155) or unchecked((int)0x80004002)) { fallback = true; }
            if (fallback)
            {
                // Retry unsupported transports before exposing any records, never after a partial read.
                foreach (var record in ReadNative(configuration, fields, restrictions, token, maximum, 0, progress))
                    yield return record;
                yield break;
            }
            while (available)
            {
                yield return rows.Current;
                available = rows.MoveNext();
            }
        }

        private static IEnumerable<DatabaseRecord> ReadRpc(string configuration, string[] fields,
            DatabaseRestriction[] restrictions, CancellationToken token, int maximum, int batchSize,
            SearchProgress progress)
        {
            // Activate the CA administration transport with encrypted, impersonated calls on this worker.
            token.ThrowIfCancellationRequested();
            var separator = configuration.IndexOf('\\');
            var server = configuration.Substring(0, separator);
            var authority = configuration.Substring(separator + 1);
            var activity = progress?.For(configuration);
            ICertAdminD connection;
            using (activity?.BeginCall("Connecting to CA"))
            {
                connection = (ICertAdminD)Activator.CreateInstance(
                    Type.GetTypeFromCLSID(AdministrationClass, server, true));
                activity?.Response();
            }
            using var scope = new ComScope<ICertAdminD>(connection);
            var proxy = Marshal.GetComInterfaceForObject(scope.Value, typeof(ICertAdminD));
            try
            {
                var status = CoSetProxyBlanket(proxy, 9, 0, IntPtr.Zero, 6, 3, IntPtr.Zero, 0);
                if (status == unchecked((int)0x800706d3))
                    status = CoSetProxyBlanket(proxy, 10, 0, IntPtr.Zero, 6, 3, IntPtr.Zero, 0);
                Marshal.ThrowExceptionForHR(status);
            }
            finally { Marshal.Release(proxy); }

            // Cache immutable column identities per CA without caching a failed schema lookup.
            var schema = schemas.GetOrAdd(configuration, _ => ReadSchema(scope.Value, authority, token, activity));
            Column Find(string name) => schema.TryGetValue(name, out var column) ? column : schema["Request." + name];
            var selected = fields.Select(Find).ToArray();
            var indexes = selected.Select(column => column.Index).ToArray();
            var ordinals = indexes.Select((index, ordinal) => new { index, ordinal })
                .ToDictionary(item => item.index, item => item.ordinal);
            var bounds = new CaViewRestriction[restrictions.Length];
            var opened = false;
            try
            {
                // Encode restrictions using the database column's actual wire type.
                for (var index = 0; index < bounds.Length; index++)
                {
                    var restriction = restrictions[index];
                    var column = Find(restriction.Field);
                    var bytes = column.Type switch
                    {
                        1 => BitConverter.GetBytes(Convert.ToInt32(restriction.Value, CultureInfo.InvariantCulture)),
                        2 => BitConverter.GetBytes(((DateTime)restriction.Value).ToFileTimeUtc()),
                        3 => (byte[])restriction.Value,
                        4 => Encoding.Unicode.GetBytes(Convert.ToString(restriction.Value,
                            CultureInfo.InvariantCulture) + "\0"),
                        _ => throw new InvalidDataException(InvalidResponse)
                    };
                    bounds[index] = new CaViewRestriction { Column = column.Index, Seek = restriction.Seek,
                        Sort = restriction.Sort, Length = bytes.Length, Value = Marshal.AllocCoTaskMem(bytes.Length) };
                    Marshal.Copy(bytes, 0, bounds[index].Value, bytes.Length);
                }

                // Bound each response and release its native buffer before yielding managed rows.
                var position = 1;
                var read = 0;
                while (read < maximum)
                {
                    token.ThrowIfCancellationRequested();
                    var requested = Math.Min(batchSize, maximum - read);
                    int status, fetched;
                    CaBlob blob;
                    using (activity?.BeginCall(opened ? "Reading records" : "Preparing search"))
                        status = !opened ? scope.Value.OpenView(authority, bounds.Length, bounds, indexes.Length,
                            indexes, position, requested, out fetched, out blob) :
                            scope.Value.EnumView(authority, position, requested, out fetched, out blob);
                    byte[] data;
                    try
                    {
                        Marshal.ThrowExceptionForHR(status);
                        opened = true;
                        if (fetched < 0 || fetched > requested) throw new InvalidDataException(InvalidResponse);
                        data = CopyBlob(blob);
                        activity?.Response(fetched);
                    }
                    finally { Marshal.FreeCoTaskMem(blob.Data); }
                    token.ThrowIfCancellationRequested();
                    var offset = 0;
                    for (var index = 0; index < fetched; index++)
                    {
                        // Validate all extents before decoding data received from the CA.
                        token.ThrowIfCancellationRequested();
                        if (offset > data.Length - 12) throw new InvalidDataException(InvalidResponse);
                        var count = BitConverter.ToInt32(data, offset + 4);
                        var length = BitConverter.ToInt32(data, offset + 8);
                        var header = 12L + (long)count * 16;
                        if (count != selected.Length || length < header || length > data.Length - offset)
                            throw new InvalidDataException(InvalidResponse);
                        var values = new object[selected.Length];
                        for (var item = 0; item < count; item++)
                        {
                            var descriptor = offset + 12 + item * 16;
                            if (!ordinals.TryGetValue(BitConverter.ToInt32(data, descriptor + 4), out var ordinal))
                                throw new InvalidDataException(InvalidResponse);
                            var valueOffset = BitConverter.ToInt32(data, descriptor + 8);
                            var valueLength = BitConverter.ToInt32(data, descriptor + 12);
                            if (valueLength == 0) continue;
                            var type = BitConverter.ToInt32(data, descriptor) & 0xff;
                            if (type != selected[ordinal].Type || valueOffset < header || valueLength < 0 ||
                                (long)valueOffset + valueLength > length)
                                throw new InvalidDataException(InvalidResponse);
                            var start = offset + valueOffset;
                            switch (type)
                            {
                                case 1 when valueLength == 4:
                                    values[ordinal] = BitConverter.ToInt32(data, start);
                                    break;
                                case 2 when valueLength == 8:
                                    values[ordinal] = DateTime.FromFileTimeUtc(BitConverter.ToInt64(data, start));
                                    break;
                                case 3:
                                    var binary = new byte[valueLength];
                                    Buffer.BlockCopy(data, start, binary, 0, valueLength);
                                    values[ordinal] = binary;
                                    break;
                                case 4 when valueLength >= 2 && valueLength % 2 == 0 &&
                                    data[start + valueLength - 1] == 0 && data[start + valueLength - 2] == 0:
                                    values[ordinal] = Encoding.Unicode.GetString(data, start, valueLength - 2);
                                    break;
                                default: throw new InvalidDataException(InvalidResponse);
                            }
                        }
                        read++;
                        offset += length;
                        yield return new DatabaseRecord(values);
                    }
                    if (fetched < requested) yield break;
                    position = checked(position + fetched);
                }
            }
            finally
            {
                // End the server view on cancellation, early disposal and failed reads as well as completion.
                if (opened)
                    using (activity?.BeginCall("Closing search")) scope.Value.CloseView(authority);
                foreach (var bound in bounds) Marshal.FreeCoTaskMem(bound.Value);
            }
        }

        private static Dictionary<string, Column> ReadSchema(ICertAdminD connection, string authority,
            CancellationToken token, SearchProgress.Source activity)
        {
            // Enumerate schema pages so additional server columns cannot truncate name lookup.
            var columns = new Dictionary<string, Column>(StringComparer.OrdinalIgnoreCase);
            for (var first = 0; ; first += 128)
            {
                token.ThrowIfCancellationRequested();
                int status, fetched;
                CaBlob blob;
                using (activity?.BeginCall("Preparing search"))
                    status = connection.EnumViewColumn(authority, first, 128, out fetched, out blob);
                byte[] data;
                try
                {
                    Marshal.ThrowExceptionForHR(status);
                    if (fetched < 0 || fetched > 128) throw new InvalidDataException(InvalidResponse);
                    data = CopyBlob(blob);
                    activity?.Response();
                }
                finally { Marshal.FreeCoTaskMem(blob.Data); }
                if (data.Length < fetched * 20) throw new InvalidDataException(InvalidResponse);
                for (var index = 0; index < fetched; index++)
                {
                    var offset = index * 20;
                    var name = BitConverter.ToInt32(data, offset + 12);
                    if (name < fetched * 20 || name > data.Length - 2 || name % 2 != 0)
                        throw new InvalidDataException(InvalidResponse);
                    var end = name;
                    while (end <= data.Length - 2 && (data[end] != 0 || data[end + 1] != 0)) end += 2;
                    if (end > data.Length - 2) throw new InvalidDataException(InvalidResponse);
                    columns.Add(Encoding.Unicode.GetString(data, name, end - name),
                        new Column(BitConverter.ToInt32(data, offset + 4), BitConverter.ToInt32(data, offset) & 0xff));
                }
                if (fetched < 128) return columns;
            }
        }

        private static byte[] CopyBlob(CaBlob blob)
        {
            // Reject impossible native buffers before copying into bounded managed storage.
            if (blob.Length < 0 || blob.Length > 64 * 1024 * 1024 ||
                (blob.Length > 0 && blob.Data == IntPtr.Zero)) throw new InvalidDataException(InvalidResponse);
            var data = new byte[blob.Length];
            if (data.Length > 0) Marshal.Copy(blob.Data, data, 0, data.Length);
            return data;
        }

        private static IEnumerable<DatabaseRecord> ReadNative(string configuration, string[] fields,
            IEnumerable<DatabaseRestriction> restrictions, CancellationToken token, int maximum, int table,
            SearchProgress progress)
        {
            // Retain row-bound extension access and use the selected table's result-column identities.
            token.ThrowIfCancellationRequested();
            var activity = progress?.For(configuration);
            using var view = ComScope<ICertView2>.Create("CertificateAuthority.View");
            using (activity?.BeginCall("Connecting to CA"))
            {
                view.Value.OpenConnection(configuration);
                activity?.Response();
            }
            ICertViewRow nativeRows;
            using (activity?.BeginCall("Preparing search"))
            {
                if (table != 0) view.Value.SetTable(table);
                view.Value.SetResultColumnCount(fields.Length);
                foreach (var field in fields) view.Value.SetResultColumn(view.Value.GetColumnIndex(0, field));
                foreach (var restriction in restrictions)
                {
                    var value = restriction.Value;
                    view.Value.SetRestriction(view.Value.GetColumnIndex(0, restriction.Field), restriction.Seek,
                        restriction.Sort, ref value);
                }
                token.ThrowIfCancellationRequested();
                nativeRows = view.Value.OpenView();
                activity?.Response();
            }
            using var rows = new ComScope<ICertViewRow>(nativeRows);
            var ordinals = new Dictionary<int, int>();
            for (var read = 0; read < maximum; read++)
            {
                token.ThrowIfCancellationRequested();
                var values = new object[fields.Length];
                using (activity?.BeginCall(table == 0 ? "Reading records" : "Searching DNS names"))
                {
                    if (rows.Value.Next() < 0) yield break;
                    using var columns = new ComScope<ICertViewColumn>(rows.Value.EnumCertViewColumn());
                    int index;
                    while ((index = columns.Value.Next()) >= 0)
                    {
                        if (!ordinals.TryGetValue(index, out var ordinal))
                        {
                            var name = columns.Value.GetName().Replace("Request.", "");
                            ordinal = Array.FindIndex(fields, field => string.Equals(field.Replace("Request.", ""),
                                name, StringComparison.OrdinalIgnoreCase));
                            ordinals[index] = ordinal;
                        }
                        if (ordinal >= 0) values[ordinal] = columns.Value.GetValue(1);
                    }
                    activity?.Response(1);
                }
                yield return new DatabaseRecord(values, rows.Value);
            }
        }
    }
}
