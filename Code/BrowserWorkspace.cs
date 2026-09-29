using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using System.Xml.Serialization;

namespace Certitude
{
    public sealed class BrowserColumn
    {
        public string Key { get; set; } = "";
        public int Order { get; set; }
        public double Width { get; set; }
        public bool Visible { get; set; } = true;

        internal BrowserColumn Copy() => (BrowserColumn)MemberwiseClone();
    }

    public sealed class BrowserView
    {
        public string Name { get; set => field = (value ?? "").Trim(); } = "";
        public bool Pinned { get; set; }
        public string Configuration { get; set; } = "";
        public QuerySpec Filter { get; set; } = new QuerySpec { Field = "All", Match = SearchMatch.Contains };
        public int? ExpiryDays { get; set; }
        public string SortField { get; set; } = nameof(CertificateRow.RequestId);
        public ListSortDirection SortDirection { get; set; } = ListSortDirection.Descending;
        public bool AutoAuthorityColumn { get; set; } = true;
        public List<BrowserColumn> Columns { get; set; } = new List<BrowserColumn>();

        internal QuerySpec Query(DateTime utcNow)
        {
            // Resolve rolling expiry presets at load time without changing explicitly saved dates.
            var filter = Filter ?? throw new InvalidDataException("The saved view has no filters.");
            var today = utcNow.ToUniversalTime().Date;
            return new QuerySpec
            {
                Disposition = filter.Disposition, Field = filter.Field, Value = filter.Value,
                Match = filter.Match, PageSize = filter.PageSize,
                ExpiresFrom = ExpiryDays.HasValue ? (ExpiryDays > 0 ? today : (DateTime?)null) : filter.ExpiresFrom,
                ExpiresBefore = ExpiryDays.HasValue ? today.AddDays(ExpiryDays.Value) : filter.ExpiresBefore
            };
        }

        internal BrowserView Copy()
        {
            // Isolate the mutable filter and column settings before editing a saved view.
            var copy = (BrowserView)MemberwiseClone();
            copy.Filter = new QuerySpec
            {
                Disposition = Filter.Disposition, Field = Filter.Field, Value = Filter.Value,
                Match = Filter.Match, PageSize = Filter.PageSize,
                ExpiresFrom = Filter.ExpiresFrom, ExpiresBefore = Filter.ExpiresBefore
            };
            copy.Columns = Columns.Select(column => column.Copy()).ToList();
            return copy;
        }

        internal void Validate(bool named)
        {
            // Reject unusable names and targets before restoring controls or replacing settings.
            if (named && (string.IsNullOrWhiteSpace(Name) || Name.Length > 80 || Name.Any(char.IsControl)))
                throw new ArgumentException("Use a view name of 1 to 80 characters without control characters.");
            if (Configuration == null || Configuration.Length > 2048 ||
                (Configuration.Length > 0 && Configuration != CaDirectory.AllAuthorities &&
                    !CaDirectory.Configurations(new[] { Configuration }).Contains(Configuration)))
                throw new InvalidDataException("The saved view has an invalid certificate authority.");
            if (named && Configuration.Length == 0)
                throw new InvalidDataException("Connect to a certificate authority before saving a view.");
            // Accept only filters and rolling presets represented by the browser controls.
            if (Filter == null || Filter.Value == null || Filter.Value.Length > 32768)
                throw new InvalidDataException("The saved view has invalid search text.");
            Filter.Validate();
            if (Filter.Disposition is not (null or 20 or 9 or 21 or 30 or 31))
                throw new InvalidDataException("The saved view has an unsupported record category.");
            if (Filter.PageSize is not (500 or 1000 or 5000 or 10000 or 15000 or 20000 or 25000))
                throw new InvalidDataException("The saved view has an unsupported page size.");
            if (ExpiryDays.HasValue && (ExpiryDays is not (0 or 7 or 30 or 60 or 90) ||
                Filter.Disposition != 20))
                throw new InvalidDataException("The saved view has an invalid expiry preset.");
            // Bound column sizes and reject ambiguous layouts rather than silently changing them.
            if (!BrowserWorkspace.ColumnKeys.Contains(SortField) ||
                !Enum.IsDefined(typeof(ListSortDirection), SortDirection))
                throw new InvalidDataException("The saved view has an unsupported sort order.");
            if (Columns == null || Columns.Count > BrowserWorkspace.ColumnKeys.Length ||
                Columns.Any(column => column == null || !BrowserWorkspace.ColumnKeys.Contains(column.Key) ||
                    column.Order < 0 || column.Order >= BrowserWorkspace.ColumnKeys.Length ||
                    double.IsNaN(column.Width) || double.IsInfinity(column.Width) ||
                    column.Width < 24 || column.Width > 4000) ||
                Columns.Select(column => column.Key).Distinct().Count() != Columns.Count ||
                Columns.Select(column => column.Order).Distinct().Count() != Columns.Count ||
                (Columns.Count == BrowserWorkspace.ColumnKeys.Length && Columns.All(column => !column.Visible)))
                throw new InvalidDataException("The saved view has an invalid column layout.");
        }

        public override string ToString() => Name;
    }

    public sealed class BrowserWorkspace
    {
        internal static readonly string[] ColumnKeys =
        {
            "RequestId", "Configuration", "CommonName", "Status", "Requester", "Template",
            "NotAfter", "NotBefore", "SerialNumber"
        };
        internal static readonly string DefaultPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Certitude", "workspace.xml");
        private const long MaximumFileSize = 4 * 1024 * 1024;
        private string revision;
        public int Version { get; set; } = 1;
        public List<string> Authorities { get; set; } = new List<string>();
        public BrowserView Current { get; set; } = new BrowserView();
        public List<BrowserView> Views { get; set; } = new List<BrowserView>();

        internal static BrowserWorkspace Load(string path)
        {
            // Bound input and disable XML entities before reading per-user workspace settings.
            if (!File.Exists(path)) return new BrowserWorkspace();
            using var stream = File.OpenRead(path);
            if (stream.Length > MaximumFileSize) throw new InvalidDataException("The workspace file is too large.");
            var revision = Revision(stream);
            stream.Position = 0;
            using var reader = XmlReader.Create(stream, new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = MaximumFileSize
            });
            var workspace = (BrowserWorkspace)new XmlSerializer(typeof(BrowserWorkspace)).Deserialize(reader);
            workspace.Validate();
            workspace.revision = revision;
            return workspace;
        }

        private static string Revision(Stream stream)
        {
            // Identify the exact settings read so another instance cannot silently replace newer views.
            using var hash = SHA256.Create();
            return Convert.ToBase64String(hash.ComputeHash(stream));
        }

        private static string Revision(string path)
        {
            if (!File.Exists(path)) return null;
            using var stream = File.OpenRead(path);
            if (stream.Length > MaximumFileSize) throw new InvalidDataException("The workspace file is too large.");
            return Revision(stream);
        }

        internal void Validate()
        {
            // Keep unsupported versions and duplicate identities out of the writable workspace.
            if (Version != 1) throw new InvalidDataException("This workspace file version is not supported.");
            if (Authorities == null || Authorities.Count > 1000 ||
                Authorities.Any(value => value == null || value.Length > 2048) ||
                !Authorities.SequenceEqual(CaDirectory.Configurations(Authorities)))
                throw new InvalidDataException("The workspace has an invalid remembered authority list.");
            if (Current == null || Views == null || Views.Count > 200 || Views.Any(view => view == null))
                throw new InvalidDataException("The workspace has an invalid saved view list.");
            Current.Validate(false);
            foreach (var view in Views) view.Validate(true);
            if (Views.Select(view => view.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() != Views.Count)
                throw new InvalidDataException("Saved view names must be unique.");
        }

        internal void Save(string path)
        {
            // Serialize to a unique sibling file so failures preserve the previous workspace.
            Validate();
            var directory = Path.GetDirectoryName(Path.GetFullPath(path));
            Directory.CreateDirectory(directory);
            // Serialize cooperating writers and reject settings changed since this instance loaded them.
            using var writeLock = new FileStream(path + ".lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            if (revision != Revision(path))
                throw new IOException("Workspace settings changed in another instance. Restart Certitude to reload them before saving.");
            var temporary = Path.Combine(directory, ".workspace-" + Guid.NewGuid().ToString("N") + ".tmp");
            try
            {
                using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    using (var writer = XmlWriter.Create(stream, new XmlWriterSettings
                        { Encoding = new UTF8Encoding(false), Indent = true, CloseOutput = false }))
                        new XmlSerializer(typeof(BrowserWorkspace)).Serialize(writer, this);
                    if (stream.Length > MaximumFileSize) throw new InvalidDataException("The workspace file is too large.");
                    stream.Flush(true);
                }
                // Flush and close the temporary file before atomically publishing the new settings.
                var updated = Revision(temporary);
                if (File.Exists(path)) File.Replace(temporary, path, null);
                else File.Move(temporary, path);
                revision = updated;
            }
            finally { if (File.Exists(temporary)) File.Delete(temporary); }
        }

        internal void PutView(BrowserView view, bool replace)
        {
            // Require explicit replacement for an existing name and retain an independent snapshot.
            var copy = view.Copy();
            copy.Validate(true);
            var index = Views.FindIndex(value => value.Name.Equals(copy.Name, StringComparison.OrdinalIgnoreCase));
            if (index >= 0 && !replace) throw new ArgumentException("A view with that name already exists.");
            if (index < 0 && Views.Count >= 200) throw new InvalidOperationException("At most 200 views can be saved.");
            if (index < 0) Views.Add(copy);
            else Views[index] = copy;
        }
    }
}