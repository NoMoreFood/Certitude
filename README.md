# Certitude

A compact, x64 WPF administration application for Windows Certificate Services, targeting **.NET Framework 4.7.2**. It uses the current Windows identity and the CA's existing permissions. Run on a Windows CA with Desktop Experience and the AD CS management tools installed. There are no NuGet or third-party runtime dependencies.

Licensed under the [GNU General Public License v3.0](LICENSE.md).

## Build and run

Requires .NET Framework 4.7.2 or later. The configuration retains .NET Framework 4.8 WPF accessibility, high-DPI and cryptography behavior when running on 4.8 or later; those runtime improvements are unavailable on 4.7.2.

Use Visual Studio 2026 (or equivalent MSBuild with a C# 14 compiler), the .NET desktop development workload, and the .NET Framework 4.7.2 targeting pack. The project selects C# 14 explicitly. Compiler features such as null-conditional assignment and field-backed properties simplify the code without adding runtime dependencies:

```powershell
msbuild Code\Certitude.sln /m /p:Configuration=Release /p:Platform=x64
.\Code\bin\Release\Certitude.exe
```

`Build\Build.cmd` creates a signed portable ZIP under `Binaries`. It requires Windows SDK SignTool, Windows PowerShell 5.1 or later, an accessible code-signing certificate and timestamp-service access. It automatically removes any previous `Build\PackageStage` and same-version ZIP before building.

### Connect to a CA

The local CA is detected automatically. On domain-joined systems, the editable dropdown discovers enterprise CAs published in Active Directory. Choose a CA and **Connect**, use **Find CAs** to refresh, or enter `SERVER\CA name` for any CA, including standalone or unpublished CAs. Directory failures do not prevent manual connections.

Choose **All CAs → Connect** to browse every listed authority together, including CAs connected manually during this session after a successful query. Unverified or failed manual entries are not retained. Searches, sorting, paging and CSV export span those CAs; the Certificate Authority column identifies each result. Request IDs are local to a CA, so equal IDs from different CAs remain separate records. Details, certificate export/validation, request processing, revocation, extension editing and archived-key retrieval use each record's own CA. Bulk confirmations and results identify each CA and its requests. **Administration**, **Advanced Tools** and **Statistics** require selecting a single CA. Certificate Manager and other independent tools remain available; enrollment requires an explicit CA. Reconnect to update the All CAs list after discovery. CAs that cannot be queried are skipped for the current All CAs connection. One inline notice lists them and stays visible across searches, sorting and paging; hover over it for the error details. Connect to All CAs again to retry those authorities. If none are reachable, the query fails rather than reporting an empty result.

Operations use your Windows identity and require the corresponding CA permissions. Service control and local maintenance may require elevation; remote use requires AD CS client components and working DCOM/RPC. Deploy `Certitude.exe` and `Certitude.exe.config` together from `Code\bin\Release`.

## OID Manager

**Tools → OID Manager** reviews the forest's Active Directory OID registrations without a CA connection. Leave the domain/controller blank for the current domain, or enter a DNS name and choose **Load Directory**. Reads and writes use the displayed controller and your Windows identity, independently of the CA dropdown. Search by name, OID, type, template reference or directory object; select a row to inspect its references, AD group link, localized names and policy statements.

**Add OID** registers an assigned numeric OID as an application policy (EKU) or issuance policy, rejecting invalid syntax and forest duplicates. It neither allocates an enterprise OID arc nor assigns policies to templates. Registrations use `msPKI-Enterprise-Oid` objects in `CN=OID,CN=Public Key Services,CN=Services`, with the [documented policy types](https://techcommunity.microsoft.com/blog/askds/the-certificate-template-manager-hangs-indefinitely/396078).

**Remove OID** confirms the forest, controller and object. Template/forest OIDs, protected objects, and custom policies referenced by templates or AD groups cannot be removed. References are rechecked on that controller before deletion; external applications, issued certificates and unreplicated changes are outside this check. Removal leaves issued certificates unchanged. AD permissions govern changes; errors appear inline.

## Published certificates

**Tools → Forest Published** views, adds and removes public certificates in the forest's NTAuth, trusted root CA, AIA/intermediate CA, cross-certificate, KRA and Enrollment Services stores. These use the AD publication attributes described in the [CA directory specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/ad150321-4b89-4802-8713-6c7a51cc0b84) and [certutil publication commands](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil#-dspublish). Individual user/computer publications and CRLs are outside this area.

Leave the domain/controller field blank for the current domain, or enter a DNS name and **Load Directory**. The resolved controller and forest appear above the selected store. Its target is independent of the CA dropdown. Search by subject, issuer, thumbprint, status or AD object. Select a certificate for its exact directory location, details, DER/PEM export, or the native Windows certificate viewer; double-click and Enter also open the viewer. Expired certificates remain visible. Unreadable directory values show an error and their SHA-256 identity.

**Add Certificate** loads one public DER/PEM certificate, previews its contents and lets you select or name the publication object. A confirmation includes the target, thumbprint and store's purpose before any directory write. CA stores require CA basic constraints; KRA requires the Key Recovery Agent EKU. Duplicate values are rejected. Enrollment Services accepts existing service objects only; publishing there does not configure a CA or its templates. Cross-certificates are added as forward certificate pairs. Publication uses your Windows identity and AD permissions.

**Remove** confirms the selected certificate and location, rechecks the object and original value, then removes only that value. Other certificates, empty publication objects and service settings are retained. Removing one side of a cross-certificate pair preserves its other side. Changes replicate through AD; removal does not revoke a certificate or immediately clear client caches. Large multivalued stores are read using LDAP paging and ranges. Empty required attributes retain Windows' zero-byte placeholder, which is omitted from certificate lists.

## Appearance and live search

**Dark Mode / Light Mode** switches the workspace theme, saved per user in `%LOCALAPPDATA%\Certitude\theme.txt`. Compact grids and wrapping details accommodate large inventories and long values. Labels, keyboard mnemonics and Windows 10 system glyphs support Windows Server 2016 and later with Desktop Experience. The application version appears in the header; editable icon sources and a generator are under `Code\Assets`.

### Navigation and record actions

Workflows use the main panel for details, administration, confirmations, passwords, reports and file selection. **Back / Escape** returns to the previous panel with its inputs preserved; leaving a confirmation cancels it. Active operations must finish or be cancelled before navigation. The file browser supports local/UNC paths, multiple selections, format choices and new folders. Listings show up to 5,000 entries; full paths select other files.

Right-click a CA record for inspection, export, validation, copying identifiers and applicable request/certificate actions. Context menus and **More Actions** hide commands unavailable in the current view and disable those unavailable for the selection. Pending requests support extension editing; issued certificates support archived-key retrieval. **All Records** includes both when applicable.

Right-clicking a selected row preserves bulk selection; another row becomes the sole target, and empty space clears selection. **Enter** opens a record, **Delete** reviews database deletion, and **Select This Page / Ctrl+A** selects only the loaded page. **Certificate / CRL Check** validates the selected certificate and retains its report when returning from nested pages.

**Delete From Database** confirms the CA, IDs, count and statuses, then deletes selected records, including their attributes, extensions and archived keys. Deletion is permanent: it neither revokes certificates nor removes store copies, and deleting revoked records can remove entries from future CRLs. Results appear per record before refresh. Use expiry/status filters to narrow cleanup selections; changing filters does not delete anything.

**Open In Windows Certificate Viewer** opens the native dialog from certificate lists, details, validation/TLS reports and issued enrollment responses. Double-clicking a Certificate Manager row does the same. Installed certificates retain their store/private-key association. Requests without certificates have no viewer action.

Certificate Manager context menus also offer details, validation, export, copying, private-key testing, friendly-name editing, copy/move and **Remove From Store**. Store changes require a writable context; file views are read only. The **No Private Key** filter hides key testing. Store removal has its own confirmation and does not delete CA records.

### Search, sorting and export

Search defaults to **All fields · Contains**, covering names, requesters, templates, serial numbers, request IDs and status across the selected CA view. Choose one field and **Exact** for the fastest server-side lookup, or **Starts with** for prefix matching. Matching ignores case; empty searches include all records.

Template columns use the directory display name. Template and all-field searches match display names, internal names and raw OIDs; exact template searches merge the corresponding CA queries while retaining newest-first paging. Template sorting uses the displayed name, and statistics combine a template's internal-name and OID records without combining different templates that happen to share a display name.

OID names come from a cached, background lookup of the CA forest's templates and OID registrations, plus Windows' local OID catalog. This covers legacy and modern templates, custom issuance/application policies, EKUs, extension identifiers, signature/public-key algorithms and embedded ASN.1 OIDs in certificate and CRL details. Numeric identifiers remain visible in details. Unknown/deleted OIDs retain their numeric value; directory lookup failures appear inline and do not prevent querying the CA. **Refresh / F5** reloads directory names along with the records, and OID Manager add/remove operations invalidate cached names. Other new operations reuse a snapshot for up to five minutes; unsuccessful lookups can retry after 30 seconds. Existing displayed results keep their snapshot until reloaded. The resolver locates the CA's forest through its enrollment registration, with a remote domain-membership lookup as fallback; it does not assume a CA member server runs LDAP. Workgroup/offline clients retain local Windows names. Application, issuance and template OID names stay separate even when a numeric identifier appears in multiple categories. Certificate/application policy details and policy mappings use this same resolver and retain CPS links, user notices and unknown qualifier bytes. Forest Published uses the explicitly selected forest for its certificate names and publication previews. Offline validation and its certificate-details action reuse available names without starting a directory lookup. Windows' built-in certificate viewer continues to use Windows' own OID resolution.

Text, category, expiry and page-size changes apply after a 400 ms pause, reset to page one and cancel superseded queries. Filters remain editable while one browser query runs at a time. All CAs queries authorities concurrently for paging, full searches, sorting and CSV export. Full scans use bounded buffers, and ordered exports merge records by request ID and CA name without loading the entire inventory into memory. A read that fails after returning rows aborts the scan; an interrupted export preserves the previous destination. Invalid values appear inline; actions and export wait for filters to apply. **Refresh / Enter / F5** applies immediately. **Ctrl+F** focuses search.

Column headings sort all matching records across pages; click again to reverse. IDs sort numerically, dates chronologically and text without case differences, with descending Request ID as the tie breaker, then CA name for equal IDs across authorities. Blanks come first ascending and last descending. Paging preserves order; changing sort returns to page one.

The default newest-first view retains one page. Other sorts cache all matching metadata, with memory proportional to the match count; certificate bodies and private keys are not loaded. Refresh, filter changes, reconnecting and CA row operations reload the data. Cancelled or superseded results never replace newer results.

Contains, prefix and all-field searches scan metadata after CA category/date restrictions, beyond the displayed page. Rare or absent matches may scan every candidate. Use exact single-field searches and expiry bounds for large CAs. A busy cursor marks background operations; cancellation waits for an active native call to return.

Date filters accept typed dates, including `yyyy-MM-dd`. **Expiry presets** selects issued certificates with UTC calendar-day bounds for expired or upcoming 7/30/60/90-day certificates, retaining search text. CSV export covers all matching pages using the same filters.

### Statistics

**Statistics** scans the connected CA independently of browser filters, retaining aggregates rather than individual records or certificate bodies. Tabs cover disposition/validity/expiry totals, revocations, database size, the largest 100 template/requester groups, submission activity, latency, validity duration and revocation reasons. Dates use UTC; counts include imported records but cannot establish deleted history, deployment or trust. The scan is not a transactionally consistent snapshot. **Refresh** recollects; **Cancel** waits for the current native call, and leaving the page requests cancellation.

CA, Server and Storage tabs show configuration, templates, CRL publication, signing certificates, OS/process metrics, configured folders and volume usage. Collection uses native CA APIs, read-only WMI and local file metadata under your Windows identity. Remote WMI requires existing permissions/firewall access; unavailable metrics do not block counts. File sizes are logical lengths, not reclaimable space. Folder scans are top-level only, count shared folders once and may include unrelated files.

## CSV Export From The Command Line

The CA browser's **Export CSV** already exports every record matching the applied filters, across all pages. Certificate Manager also exports its filtered Windows-store/file inventory to CSV. The command below exports CA database records without starting WPF or opening any windows, using the current Windows identity.

```powershell
.\Certitude.exe export --ca 'SERVER\CA Name' --output 'C:\Reports\expiring.csv' `
    --fields 'RequestID,CommonName,CertificateTemplate,NotAfter,Status' `
    --where 'Disposition=Issued' --where 'NotAfter>=today' --where 'NotAfter<today+30d' | Out-Host
$LASTEXITCODE
```

`--ca` defaults to the local CA when omitted. Without `--where`, all CA records are eligible, including pending, failed, denied and revoked requests. Every repeated `--where` must match (AND); there is no SQL/expression evaluation. Quote each condition and paths or CA names containing spaces. `Out-Host` keeps PowerShell waiting for this Windows GUI executable and exposes its exit code; in Command Prompt use `start "" /wait Certitude.exe export ...`. Task schedulers can invoke `Certitude.exe` directly with the same arguments and collect its process exit code.

`--fields` selects columns in the supplied order. Omit it for the eight usual browser export fields, or use `--fields '*'` for all fields below. Field names, aliases, disposition names, and text comparisons are case-insensitive.

| Field | Type / Meaning |
| --- | --- |
| `RequestID` | Integer request ID |
| `CommonName` | Certificate common name |
| `RequesterName` | Requesting identity; alias `Requester` |
| `CertificateTemplate` | Template internal name or OID as stored by the CA; alias `Template` |
| `TemplateDisplayName` | Resolved template display name, falling back to the stored identifier |
| `TemplateName` | Resolved internal template name; blank for an unresolved numeric OID |
| `TemplateOid` | Resolved numeric template OID, where available |
| `SerialNumber` | Certificate serial number as text |
| `NotBefore`, `NotAfter` | UTC validity dates; absent for requests without a certificate |
| `Status` | Display status, including `Expired` for issued certificates whose expiry has passed |
| `Disposition` | CA disposition code; alias `Request.Disposition` |
| `RevocationReason` | Integer revocation reason, if present; alias `Request.RevokedReason` |
| `Configuration` | Source certificate authority as `SERVER\CA name` |

`CertificateTemplate` conditions and exports retain their raw-value semantics. Use `TemplateDisplayName`, `TemplateName` or `TemplateOid` to export or filter resolved identifiers, for example `--fields 'RequestID,CertificateTemplate,TemplateDisplayName,TemplateOid' --where 'TemplateDisplayName=Web Server'`. The default eight CSV columns remain unchanged.

| Condition Type | Supported Operators | Example |
| --- | --- | --- |
| Text | `=`, `!=`, `contains`, `startswith`, `endswith` | `CommonName endswith .example.com` |
| Integer / Date | `=`, `!=`, `>`, `>=`, `<`, `<=` | `RequestID>=10000` |
| Blank / Missing | `is null`, `is not null` | `NotAfter is null` |

Text operators match literal text, without wildcards or regular expressions. Missing numeric/date values fail comparisons, including `!=`; use the explicit null operators to include them. Empty text also counts as blank. Disposition accepts numeric codes or `Processing`, `Pending`, `ForeignCertificate`, `CACertificate`, `CAChain`, `RecoveryAgent`, `Issued`, `Revoked`, `Failed`, and `Denied`. `Disposition=Issued` includes expired certificates; `Status=Issued` excludes them. `Status=Expired` selects expired certificates with issued disposition.

Dates accept ISO 8601 values in `yyyy-MM-dd` format, optionally followed by `THH:mm:ss` and a `Z` or signed `HH:mm` UTC offset. A date/time without an offset is UTC. `now` means the current UTC instant; `today` means UTC midnight. Both accept signed integer offsets in days (`d`), hours (`h`), or minutes (`m`), such as `today+30d` or `now-12h`. Relative dates are resolved once when parsing the command. Bounds are literal: `<` excludes its boundary and `<=` includes it.

```powershell
# Discover fields and syntax without connecting to a CA.
.\Certitude.exe export --list-fields | Out-Host
.\Certitude.exe export --help | Out-Host

# Export pending requests, including a field that is not one of the default columns.
.\Certitude.exe export --output pending.csv --fields 'RequestID,RequesterName,Disposition' `
    --where 'Disposition=Pending' --where 'NotAfter is null' | Out-Host

# Export all fields for matching CA records; replace an existing output explicitly.
.\Certitude.exe export --output matching.csv --fields '*' --force `
    --where 'CommonName startswith server-' --where 'RequestID>=100' | Out-Host
```

Exports stream all matching records with bounded memory; they are not limited to the visible page. Exact field, disposition and expiry restrictions narrow queries on the CA where possible; remaining conditions run on streamed metadata. Selective exact-name/serial exports can use the CA field index, so CSV row order is not guaranteed. Conditions may reference fields omitted from `--fields`. These are the browser metadata fields, not arbitrary CA schema columns or decoded certificate extensions.

Output is UTF-8 CSV with a BOM, canonical field-name headers and ISO 8601 UTC dates. Values are quoted and escaped; formula-like text is protected as in GUI exports. Existing destinations require `--force`; a temporary sibling file is replaced into place only after success. The destination directory must already exist. Successful zero-match exports contain only headers. Standard output contains a completion summary; errors go to standard error. Exit codes are **0** success, **1** export/CA/file error, **2** invalid arguments, and **130** cancellation. Ctrl+C cancels cooperatively when attached to a console; an active native CA call must return before cancellation finishes. Normal cancellation/failure preserves the destination and removes the temporary file.

## Certificate Manager

Open **Certificate Manager** without connecting to a CA. Its three tabs share the main workspace and current theme.

### Windows stores and files

The local machine Personal store loads when the manager first opens. Choose **Local Machine** or **Current User**, a store, then **Load Store** to change the inventory. `My` is Personal. The inventory shows expiry, SANs, EKUs, algorithms, key sizes, private-key associations and basic legacy-algorithm findings. Search and date/key filters apply dynamically; export the filtered inventory to CSV. Listing metadata does not build chains, retrieve network data or open private keys. This local inventory is an in-memory snapshot, separate from the paged CA database. An expired certificate in a store does not prove a service still uses it.

**Open file** accepts DER/PEM certificates, PEM bundles, PKCS #7 and PFX up to 32 MB. Inspection does not install certificates, trust roots or persist keys. **Import file** reviews each certificate and the selected destination; all bundle members go into that store. Machine-store changes may require elevation. PFX import persists keys in the selected machine/user context, with later exportability opt-in. Root/TrustedPeople imports change trust.

Export public certificates as DER (one), PEM or PKCS #7 (bundles). Export one installed certificate/private key as a password-protected PFX if its provider permits; the issuer chain is not included automatically. **Test private key** signs/verifies a random challenge using RSA/ECDSA to check matching and access for the current identity. Hardware providers may request a PIN. It does not test another service account's permissions. **Remove** reports each selected store removal; it does not revoke the certificate or delete its private-key container.

**Friendly Name** edits the installed certificate's display name without changing its signed contents. **Copy / Move** transfers selected certificates between stores in the same machine/user context, retaining private-key associations and friendly names. Move removes each source only after verifying the destination and key association. Existing destination certificates are reported and leave the source intact. Each result is reported independently; cancellation stops between certificates. These operations do not change service bindings or copy keys to another identity.

### TLS endpoint

Enter a DNS name/IP and direct TLS port (for example 443 or 636). An optional separate SNI/expected name lets you connect to a particular address while checking the intended hostname. An expected SHA-1 or SHA-256 thumbprint verifies whether the deployed leaf matches a renewed certificate. Windows checks trust, hostname and optional revocation (on by default); failed validation is reported without accepting the handshake. No application data or client certificate is sent.

Reports capture the leaf, Windows-built chain and errors. This chain may include cached/downloaded issuers; it is not necessarily exactly what the peer sent. Successful handshakes show the negotiated protocol/cipher. Use the certificate/CRL checker for detailed revocation investigation. Export the leaf, chain or report. The timeout closes the connection; cancellation may still wait for an active native Windows validation call. STARTTLS, mutual TLS and application-specific policies are outside this check.

### Request and install

Enter an X.500 subject, DNS/IP SANs, RSA/ECDSA key choice, EKUs and optional template internal name/OID. Choose the machine/user context and whether encrypted private-key export is allowed. Preview/save the INF settings, then **Create CSR**. Windows certreq runs silently after showing the settings and creates a persistent key/pending request. The output CSR contains no private key. SANs are validated; quoted/percent-containing subjects are not supported by this form. The CA/template controls final extensions and validity.

Browse or generate a PKCS #10 request, specify a CA and **Submit request**. Results distinguish issued, pending, denied and failed outcomes and retain the request ID. **Retrieve** checks that ID again; save an issued response. **Accept response file** installs and associates the existing private key on the original machine/context using certreq. Inspect Personal afterward. These actions do not update IIS, RDS or other service bindings; check the TLS endpoint after deployment. Cancelled/failed operations can leave completed keys or CA changes in place.

## Certificate and CRL validation

Open **Certificate / CRL check** from the sidebar without connecting to a CA, or open an issued/revoked request and use the same button in its details. Select a DER/PEM public certificate. Optional issuer/CRL-signer certificates (DER, PEM or PKCS #7 chains) and local base/delta CRLs are held in a temporary memory store; they are not trusted or installed into Windows certificate stores.

Validation uses Windows CryptoAPI rather than parsing certutil output. It reports certificate-chain trust and revocation status separately, including unknown/offline results. The report includes distribution points, direct CRL retrieval errors, CRL signature and signing-key checks, issuer and distribution-point scope, this/next update, CRL numbers and extensions, certificate entries and revocation reasons. Base/delta processing is left to Windows. The chain report identifies the hashes of CRLs Windows actually used; online Windows checks may also use OCSP. An absent certificate entry in one CRL alone is never presented as a complete validity decision.

**Retrieve distribution-point CRLs** checks the selected certificate's CDP and freshest-CRL locations, then follows delta locations in retrieved base CRLs. Online retrieval bypasses the URL cache for these diagnostic downloads; the Windows chain engine can still use its normal cache and OCSP. **Offline / cache only** prevents network retrieval. HTTP(S), LDAP and file URLs use the Windows retrieval provider and its protocol policies, with a 100 MB limit per response. Windows commonly disables file-URL retrieval; use local CRL inputs in that case. The timeout applies per diagnostic retrieval and cumulatively to revocation retrievals for each chain element. Cancellation takes effect after the active native call returns. Save the report or any loaded/retrieved CRL from the validation panel.

This is a general certificate/CRL diagnostic check using the current user's Windows trust context. It does not check a TLS hostname or a particular application's certificate policy. CRL diagnostics run independently of CA browsing.

## Generating and publishing CRLs

In **Administration → CRLs**, choose base CRLs, delta CRLs, or both, then **Publish**. Base-only is the default, so CAs without delta publication enabled can generate a new CRL. Leave next update empty to use the CA's configured period, or provide a future UTC time. The CA may round or limit the requested expiry. **Republish existing CRLs** redistributes the existing lists and does not generate new CRL contents; it cannot be combined with an expiry override.

The native CA API publishes for the current and unexpired renewed signing certificates. The result report reads base/delta publication status for each signing-certificate index and exposes LDAP, file, HTTP, signature and other publication failures. Publication status is also available without generating a CRL. Inspect or export a base/delta CRL by signing-certificate index. Check the certificate's CDPs afterward to verify client reachability.

## Performance

Queries run in the background with pages of 500–10,000 records (default 1,000). The newest-first view retains one page; other sorts cache all matching metadata. Certificate bodies load only when needed. Exact-field searches and expiry bounds narrow large queries; CSV export streams all matches with bounded memory.

Date bounds are UTC, inclusive at the start and exclusive at the end. Live queries can reflect concurrent CA changes. Cancellation waits for active native calls and does not undo completed changes.

## Capabilities

| Area | Available workflow |
| --- | --- |
| Certificate browser | Issued, pending, revoked, failed, denied and all-record views; live all-field or targeted contains/prefix/exact searches; expiry bounds; resizable/reorderable columns; multiple selection |
| Inspection and export | Full database properties, attributes, extensions, inline certificate details, DER/PEM certificate export, matching-query CSV export |
| Certificate / CRL validation | Certificate-file or CA-request checks; Windows chain and revocation results; online/offline CDP and freshest-CRL retrieval; local base/delta files; signature, scope, expiry and entry diagnostics; CRL/report export |
| Request management | Issue/resubmit, deny, submit PKCS #10, import issued certificate, set pending-request attributes and binary extensions |
| Revocation | Bulk revoke with reason/effective UTC time, release certificate hold; generate or republish base/delta CRLs with optional next update; publication status; indexed CRL inspection/export |
| Database maintenance | Delete selected database rows; full online backup, backed-up log truncation, offline integrity checking and compaction |
| CA administration | CA information, role mask, schema, indexed CA properties, KRA properties, configuration entries, template publication, service status/start/stop/restart |
| Recovery | Encrypted archived-key retrieval; database / CA-private-key backups and CA registry configuration export |
| Advanced diagnostics | Dedicated CA connectivity and database integrity checks with bounded inline output |

The frequently used database and administration operations have native WPF controls. Windows template-definition editing and some MMC property pages remain outside this UI.

**Advanced Tools** provides dedicated operation buttons with named inputs and inline review:

- **Check CA Connectivity** checks the selected CA's request/admin interfaces and reads CA information.
- **Back Up Database** creates a full online database backup and exports configuration, preserving transaction logs.
- **Back Up And Truncate Logs** performs a full backup and lets Certificate Services truncate backed-up logs.
- **Back Up CA And Private Key** includes the CA signing certificate and exportable private key in a password-protected backup. Hardware-protected keys require their provider's backup procedure.
- **Export CA Configuration** exports the CA registry configuration for recovery.
- **Check Database Integrity** temporarily stops the CA for a read-only Windows ESE integrity check.
- **Compact Database** first backs up the database and configuration, temporarily disables/stops Certificate Services, compacts the database, checks its integrity, and reports before/after sizes. All records remain; space savings depend on unused database pages. The online backup and original database copy remain in the displayed results folder.

Maintenance requires an elevated application on the selected local CA; a different host or CA name is rejected. Connectivity checks support remote CAs. Choose an existing local backup/results folder; each operation creates a unique child folder. Compaction checks space for the backup, original copy, temporary database and working margin. Offline operations restore the service's previous startup mode and running state, including after failure. Closing is blocked until they finish. If restoration fails, the output identifies the original service state for recovery. The old arbitrary command/executable fields and command presets are removed. Maintenance invokes only fixed Windows operations with generated arguments, hidden consoles, closed standard input and bounded output. Passwords are excluded from review/output and the password field clears after a key-backup attempt. Restore, CA renewal, CA response installation and custom commands are no longer exposed through the removed command runner. Run those commands with the Windows administration tools. To remove every published template, use the Certification Authority console.

Bulk operations confirm the CA, selected IDs and action, then report each result independently. Resubmission distinguishes issuance from still-pending/denied outcomes. Only certificates revoked for certificate hold can be reinstated. Deleting a database row does not revoke its certificate. Publish CRLs separately after revocation changes.

CSV fields are quoted and formula-like text is prefixed with an apostrophe for spreadsheet use. Operation results remain visible inline and in the status bar; Certitude does not retain a session history.

Keyboard shortcuts: **F5** apply/refresh, **Ctrl+F** search, **Enter** apply from the search box, **Escape** cancel.
