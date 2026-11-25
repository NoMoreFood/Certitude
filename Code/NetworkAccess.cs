//
// Copyright (c) Bryan Berns.
// Licensed under GPLv3. See LICENSE.md.
//

using System;
using System.IO;
using System.Net;
using System.Net.Cache;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Certitude
{
    internal sealed class NetworkAccess
    {
        internal const string SystemProxy = "System", Direct = "Direct";
        internal static volatile NetworkAccess Current = new NetworkAccess(SystemProxy, null);
        internal string Setting { get; }
        internal Uri Address { get; }

        private NetworkAccess(string setting, Uri address) { Setting = setting; Address = address; }

        internal static NetworkAccess Parse(string value, bool manual = false)
        {
            // Store only a routing mode or an HTTP proxy authority, without credentials.
            if (!manual && value is SystemProxy or Direct) return new NetworkAccess(value, null);
            if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttp ||
                uri.Port == 0 || uri.UserInfo.Length != 0 || uri.PathAndQuery != "/" || uri.Fragment.Length != 0 ||
                !uri.IsWellFormedOriginalString())
                throw new ArgumentException("Enter an HTTP proxy address such as http://proxy.example.com:8080.");
            return new NetworkAccess(uri.AbsoluteUri, uri);
        }

        internal string HttpPolicy => Address != null ? "HTTP proxy " + Address.Authority :
            Setting == Direct ? "Direct connection" : "Windows proxy settings";

        internal string Route(Uri uri) => uri.IsLoopback ? "Direct connection (loopback)" : HttpPolicy;

        internal string CrlRoute(string url, bool offline) => offline ? "Windows URL cache" :
            Setting == SystemProxy || !Uri.TryCreate(url, UriKind.Absolute, out var uri) ||
            uri.Scheme is not ("http" or "https") ? "Windows URL retrieval" : Route(uri);

        internal (byte[] Body, string MediaType, int Status) Fetch(Uri uri, int seconds, int limit,
            CancellationToken token, byte[] post = null, bool redirects = false)
        {
            // Keep proxy credentials off the origin and give each request an independent cancellation deadline.
            token.ThrowIfCancellationRequested();
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
            deadline.CancelAfter(TimeSpan.FromSeconds(seconds));
            var request = WebRequest.CreateHttp(uri);
            request.Method = post == null ? "GET" : "POST";
            request.Proxy = Address != null ? new WebProxy(Address) : Setting == Direct ? null :
                WebRequest.GetSystemWebProxy();
            if (request.Proxy != null) request.Proxy.Credentials = CredentialCache.DefaultNetworkCredentials;
            request.CachePolicy = new RequestCachePolicy(RequestCacheLevel.NoCacheNoStore);
            request.AllowAutoRedirect = redirects;
            request.Timeout = request.ReadWriteTimeout = checked(seconds * 1000);
            using var abort = deadline.Token.Register(request.Abort);
            try
            {
                if (post != null)
                {
                    request.ContentType = "application/x-pki-message";
                    request.ContentLength = post.Length;
                    using var upload = request.GetRequestStream();
                    upload.Write(post, 0, post.Length);
                }
                using var response = (HttpWebResponse)request.GetResponse();
                var status = (int)response.StatusCode;
                if (status is < 200 or >= 300)
                    throw new IOException($"HTTP {status} ({response.StatusDescription}). " +
                        "Enter the final endpoint URL.");

                // Bound streamed responses even when the server omits Content-Length.
                var length = response.ContentLength;
                if (length > limit) throw new InvalidDataException("The HTTP response is too large.");
                using var body = new MemoryStream(length < 0 ? 0 : (int)length);
                using var stream = response.GetResponseStream();
                var buffer = new byte[64 * 1024];
                int read;
                while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    deadline.Token.ThrowIfCancellationRequested();
                    if (body.Length + read > limit) throw new InvalidDataException("The HTTP response is too large.");
                    body.Write(buffer, 0, read);
                }
                deadline.Token.ThrowIfCancellationRequested();
                if (length >= 0 && body.Length != length) throw new EndOfStreamException("Incomplete HTTP response.");
                return (body.ToArray(), response.ContentType.Split(';')[0].Trim(), status);
            }
            catch (Exception error)
            {
                using var failed = (error as WebException)?.Response as HttpWebResponse;
                token.ThrowIfCancellationRequested();
                if (deadline.IsCancellationRequested || error is WebException { Status: WebExceptionStatus.Timeout })
                    throw new TimeoutException("The HTTP request timed out.", error);
                if (failed != null)
                    throw new IOException($"HTTP {(int)failed.StatusCode} ({failed.StatusDescription}).", error);
                throw;
            }
        }

        internal async Task ConnectTls(TcpClient client, string host, int port, TimeReport report,
            CancellationToken token, bool direct = false)
        {
            // Native service probes connect directly unless an explicit HTTP tunnel is requested.
            var destination = new UriBuilder(Uri.UriSchemeHttps, host, port).Uri;
            var proxy = direct || destination.IsLoopback ? null : Address;
            token.ThrowIfCancellationRequested();
            if (proxy == null)
            {
                report.AppendLine(destination.IsLoopback ? "Route: Direct connection (loopback)" :
                    "Route: Direct connection");
                await client.ConnectAsync(host, port).ConfigureAwait(false);
                report.AppendLine("Direct connection: " + client.Client?.RemoteEndPoint);
                return;
            }
            report.AppendLine("Route: HTTP CONNECT proxy " + proxy.Authority)
                .AppendLine("An inspecting proxy can present its own certificate. Use a direct check to verify " +
                    "the service binding.");
            await client.ConnectAsync(proxy.IdnHost, proxy.Port).ConfigureAwait(false);
            var stream = client.GetStream();
            var authority = (destination.HostNameType == UriHostNameType.IPv6 ? destination.Host :
                destination.IdnHost) + ":" + port;
            var connect = Encoding.ASCII.GetBytes($"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
            await stream.WriteAsync(connect, 0, connect.Length, token).ConfigureAwait(false);

            // Finish the bounded CONNECT response before SslStream writes its first handshake byte.
            var buffer = new byte[16384];
            var count = 0;
            while (count < buffer.Length)
            {
                var read = await stream.ReadAsync(buffer, count, buffer.Length - count, token).ConfigureAwait(false);
                if (read == 0) break;
                count += read;
                var header = Encoding.ASCII.GetString(buffer, 0, count);
                if (!header.Contains("\r\n\r\n")) continue;
                var line = header.Substring(0, header.IndexOf("\r\n", StringComparison.Ordinal)).Split(' ');
                if (line.Length < 2 || !(line[0] is "HTTP/1.0" or "HTTP/1.1") || line[1].Length != 3 ||
                    !int.TryParse(line[1], out var status)) break;
                if (status == 407)
                    throw new IOException("HTTP 407. TLS endpoint checks require unauthenticated CONNECT.");
                if (status is < 200 or >= 300) throw new IOException($"The CONNECT proxy returned HTTP {status}.");
                return;
            }
            throw new IOException("The CONNECT proxy returned incomplete or oversized HTTP headers.");
        }
    }
}
