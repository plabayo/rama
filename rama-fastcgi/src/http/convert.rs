//! Conversion helpers between HTTP and FastCGI types.
//!
//! Emits the de-facto FastCGI parameter set that nginx / Apache / php-fpm
//! expect — see `specifications/nginx_fastcgi_params.md` for the curated
//! contract. Bodies stream through (no buffering) in both directions on the
//! request side; the response side currently collects stdout into a bounded
//! buffer (capped by
//! [`ClientOptions::max_stdout_bytes`][crate::client::ClientOptions::max_stdout_bytes]).

use rama_core::bytes::{Bytes, BytesMut};
use rama_core::error::{BoxError, ErrorContext as _, ErrorExt as _, extra::OpaqueError};
use rama_core::extensions::ExtensionsRef;
use rama_core::futures::TryStreamExt;
use rama_core::telemetry::tracing;
use rama_http_types::{
    Body, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Version, header,
};
use rama_net::Protocol;
use rama_net::http::RequestContext;
use rama_net::stream::SocketInfo;
use tokio_util::io::{ReaderStream, StreamReader};

use crate::body::FastCgiBody;
use crate::client::{FastCgiClientRequest, FastCgiClientResponse};
use crate::http::env::FastCgiHttpEnv;
use crate::proto::cgi;
use crate::server::{FastCgiRequest, FastCgiResponse};

// ─────────────────────────────────────────────────────────────────────────
// Header sets
// ─────────────────────────────────────────────────────────────────────────

static KEEP_ALIVE: HeaderName = HeaderName::from_static("keep-alive");
static PROXY_CONNECTION: HeaderName = HeaderName::from_static("proxy-connection");

/// HTTP request headers we don't forward as `HTTP_*` CGI variables —
/// either hop-by-hop (RFC 7230 §6.1) or because they have a dedicated CGI
/// variable (`Host` → `SERVER_NAME` + `SERVER_PORT`; `Content-Type` →
/// `CONTENT_TYPE`; `Content-Length` → `CONTENT_LENGTH`).
///
/// `&'static HeaderName` (not `HeaderName`) because `HeaderName` has
/// interior-mutable case storage that prevents owning copies inside a
/// `static` slice; rustc rejects with `E0492`. Same pattern as
/// `rama_http_core::proto::h2::CONNECTION_HEADERS`.
pub(crate) static HOP_BY_HOP_OR_DEDICATED: &[&HeaderName] = &[
    &header::CONNECTION,
    &KEEP_ALIVE,
    &PROXY_CONNECTION,
    &header::TRANSFER_ENCODING,
    &header::TE,
    &header::TRAILER,
    &header::UPGRADE,
    &header::HOST,
    &header::CONTENT_TYPE,
    &header::CONTENT_LENGTH,
];

// ─────────────────────────────────────────────────────────────────────────
// Outbound: HTTP request → FastCGI client request
// ─────────────────────────────────────────────────────────────────────────

/// Translate a `Version` to its CGI `SERVER_PROTOCOL` string.
///
/// Errors on unsupported / unknown versions rather than silently
/// down-casting — a backend deserves a clear `HTTP/x.y` mapping.
fn version_to_protocol(v: Version) -> Result<&'static str, BoxError> {
    match v {
        Version::HTTP_10 => Ok("HTTP/1.0"),
        Version::HTTP_11 => Ok("HTTP/1.1"),
        Version::HTTP_2 => Ok("HTTP/2"),
        Version::HTTP_3 => Ok("HTTP/3"),
        other => Err(OpaqueError::from_static_str(
            "fastcgi: unsupported HTTP version (cannot map to SERVER_PROTOCOL)",
        )
        .context_debug_field("version", other)),
    }
}

/// Server-side info derived from the request: host, port, transport scheme.
/// Always exists; falls back to localhost+default-port when no context can
/// be inferred.
struct ServerInfo {
    host: String,
    port: String,
    is_https: bool,
}

/// Derive server info via rama's `RequestContext` (which already does the
/// heavy lifting of URI / Forwarded / SNI / ProxyTarget / Host-header
/// resolution). Falls back to localhost only when *all* of those signals
/// are unavailable.
fn derive_server_info(req_ctx: Option<&RequestContext>) -> ServerInfo {
    let is_https = req_ctx.map(|c| c.protocol.is_secure()).unwrap_or(false);
    let scheme = if is_https {
        Protocol::HTTPS
    } else {
        Protocol::HTTP
    };
    let default_port = scheme.default_port().unwrap_or(80);

    let (host, port) = if let Some(ctx) = req_ctx {
        let host = ctx.authority.host.to_string();
        let port = ctx
            .authority
            .port
            .or_else(|| ctx.protocol.default_port())
            .unwrap_or(default_port);
        (host, port)
    } else {
        tracing::debug!(
            "fastcgi: no RequestContext could be derived from the request, falling back to localhost"
        );
        ("localhost".to_owned(), default_port)
    };

    ServerInfo {
        host,
        port: port.to_string(),
        is_https,
    }
}

/// Map a header name into its `HTTP_*` CGI form (uppercase, `-` → `_`).
fn http_star_name(name: &HeaderName) -> String {
    let n = name.as_str();
    let mut out = String::with_capacity(5 + n.len());
    out.push_str("HTTP_");
    for ch in n.chars() {
        out.push(if ch == '-' {
            '_'
        } else {
            ch.to_ascii_uppercase()
        });
    }
    out
}

fn io_error(e: BoxError) -> std::io::Error {
    std::io::Error::other(e)
}

/// Build a [`FastCgiClientRequest`] from an HTTP request **without** buffering
/// the body. The request body is plumbed through as a [`FastCgiBody`] backed
/// by the original [`Body`] stream.
///
/// CGI-environment defaults can be overridden by attaching a
/// [`FastCgiHttpEnv`] to the request's extensions before this is called.
pub(super) async fn http_request_to_fastcgi(
    req: Request,
) -> Result<FastCgiClientRequest, BoxError> {
    let peer = req.extensions().get_ref::<SocketInfo>().cloned();
    let env = req
        .extensions()
        .get_ref::<FastCgiHttpEnv>()
        .cloned()
        .unwrap_or_default();
    let req_ctx = RequestContext::try_from(&req).ok();

    let (parts, body) = req.into_parts();

    let protocol = version_to_protocol(parts.version)
        .context("fastcgi: build SERVER_PROTOCOL from HTTP version")?;

    let method = parts.method.as_str().to_owned();
    let path = parts.uri.path().to_owned();
    let query = parts.uri.query().unwrap_or("").to_owned();
    let request_uri = if query.is_empty() {
        path.clone()
    } else {
        format!("{path}?{query}")
    };

    let server = derive_server_info(req_ctx.as_ref());
    let scheme = if server.is_https {
        Protocol::HTTPS_SCHEME
    } else {
        Protocol::HTTP_SCHEME
    };

    let content_length_header = parts
        .headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    let gateway_interface = env
        .gateway_interface
        .unwrap_or(cgi::GATEWAY_INTERFACE_CGI_1_1);
    let redirect_status = env.redirect_status.unwrap_or(cgi::REDIRECT_STATUS_OK);

    let mut params: Vec<(Bytes, Bytes)> = Vec::with_capacity(24);

    macro_rules! param {
        ($name:expr, $value:expr) => {
            params.push(($name, Bytes::from($value)));
        };
    }

    // ── Required CGI/1.1 variables (RFC 3875 §4) ─────────────────────────
    params.push((cgi::GATEWAY_INTERFACE, gateway_interface));
    param!(cgi::SERVER_PROTOCOL, protocol);
    param!(cgi::REQUEST_METHOD, method);

    // ── Script / path split. The default policy treats the entire URL
    //    path as SCRIPT_NAME with empty PATH_INFO; this matches modern
    //    framework routing. Sites that need traditional script-file/extra
    //    path splitting should layer a router on top of this connector.
    param!(cgi::SCRIPT_NAME, path.clone());
    params.push((cgi::PATH_INFO, Bytes::new()));
    param!(cgi::QUERY_STRING, query);

    // ── nginx de-facto variables ─────────────────────────────────────────
    param!(cgi::REQUEST_URI, request_uri);
    param!(cgi::DOCUMENT_URI, path);
    param!(cgi::REQUEST_SCHEME, scheme);
    if server.is_https {
        params.push((cgi::HTTPS, cgi::HTTPS_ON));
    }
    // Required by php-fpm (with cgi.force_redirect=1, the default).
    params.push((cgi::REDIRECT_STATUS, redirect_status));

    if let Some(server_software) = env.server_software {
        params.push((cgi::SERVER_SOFTWARE, server_software));
    }

    param!(cgi::SERVER_NAME, server.host);
    param!(cgi::SERVER_PORT, server.port);

    if let Some(p) = peer.as_ref() {
        let peer_addr = p.peer_addr();
        param!(cgi::REMOTE_ADDR, peer_addr.ip_addr.to_string());
        param!(cgi::REMOTE_PORT, peer_addr.port.to_string());
        if let Some(local) = p.local_addr() {
            param!(cgi::SERVER_ADDR, local.ip_addr.to_string());
        }
    }

    // CONTENT_LENGTH always emitted (matches nginx; php-fpm depends on it
    // for `$_POST` parsing). Falls back to "0" when the upstream client
    // used chunked encoding — `php://input` still works because FastCGI
    // STDIN EOS terminates the body stream correctly.
    param!(
        cgi::CONTENT_LENGTH,
        content_length_header.unwrap_or_else(|| "0".to_owned())
    );

    if let Some(ct) = parts.headers.get(header::CONTENT_TYPE) {
        params.push((cgi::CONTENT_TYPE, Bytes::copy_from_slice(ct.as_bytes())));
    }

    // ── HTTP_* header mapping (RFC 3875 §4.1.18) ─────────────────────────
    for (name, value) in &parts.headers {
        if HOP_BY_HOP_OR_DEDICATED.contains(&name) {
            continue;
        }
        params.push((
            Bytes::from(http_star_name(name)),
            Bytes::copy_from_slice(value.as_bytes()),
        ));
    }

    // ── Body: stream into FastCgiBody (no .collect) ─────────────────────
    let body_stream = body.into_data_stream().map_err(io_error);
    let body_reader = StreamReader::new(body_stream);
    let stdin = FastCgiBody::from_reader(body_reader);

    Ok(FastCgiClientRequest::new(params).with_stdin(stdin))
}

// ─────────────────────────────────────────────────────────────────────────
// Inbound: FastCGI client response → HTTP response
// ─────────────────────────────────────────────────────────────────────────

/// Parse a `Status: NNN [reason]` value into a `StatusCode`.
fn parse_cgi_status(raw_value: &[u8]) -> Option<StatusCode> {
    let s = std::str::from_utf8(raw_value).ok()?;
    let code_str = s.split(' ').next()?;
    let n = code_str.parse::<u16>().ok()?;
    StatusCode::from_u16(n).ok()
}

/// Parse a [`FastCgiClientResponse`] (CGI stdout) into an HTTP [`Response`].
pub(super) fn fastcgi_response_to_http(resp: FastCgiClientResponse) -> Response {
    if !resp.stderr.is_empty() {
        tracing::debug!(
            stderr.bytes = resp.stderr.len(),
            stderr.body = %String::from_utf8_lossy(&resp.stderr),
            "fastcgi: backend wrote to STDERR"
        );
    }

    let stdout = resp.stdout;
    let (header_bytes, body_bytes) = split_cgi_response(&stdout);

    let mut builder = Response::builder().status(StatusCode::OK);

    for line in header_bytes.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        let Some(sep) = line.iter().position(|&b| b == b':') else {
            tracing::debug!(
                line = %String::from_utf8_lossy(line),
                "fastcgi: dropping malformed CGI response header (no ':' separator)"
            );
            continue;
        };
        let raw_name = &line[..sep];
        let raw_value = line[sep + 1..].trim_ascii();
        if raw_name.eq_ignore_ascii_case(b"Status") {
            match parse_cgi_status(raw_value) {
                Some(status) => builder = builder.status(status),
                None => {
                    tracing::debug!(
                        value = %String::from_utf8_lossy(raw_value),
                        "fastcgi: dropping invalid Status header; keeping default 200 OK"
                    );
                }
            }
            continue;
        }
        let Ok(header_name) = HeaderName::from_bytes(raw_name) else {
            tracing::debug!(
                header.name = %String::from_utf8_lossy(raw_name),
                "fastcgi: dropping response header with invalid name"
            );
            continue;
        };
        let Ok(header_value) = HeaderValue::from_bytes(raw_value) else {
            tracing::debug!(
                header.name = %header_name,
                header.value = %String::from_utf8_lossy(raw_value),
                "fastcgi: dropping response header with invalid value"
            );
            continue;
        };
        builder = builder.header(header_name, header_value);
    }

    builder
        .body(Body::from(Bytes::copy_from_slice(body_bytes)))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

// ─────────────────────────────────────────────────────────────────────────
// Inbound: FastCGI server request → HTTP request
// ─────────────────────────────────────────────────────────────────────────

/// Parse a CGI `SERVER_PROTOCOL` value into a `Version`. Returns `Err` on an
/// unrecognised value (instead of silently downgrading), and logs at debug
/// when defaulting because the variable was absent entirely.
fn parse_server_protocol(value: Option<&str>) -> Result<Version, BoxError> {
    match value {
        Some("HTTP/1.0") => Ok(Version::HTTP_10),
        Some("HTTP/1.1") => Ok(Version::HTTP_11),
        Some("HTTP/2" | "HTTP/2.0") => Ok(Version::HTTP_2),
        Some("HTTP/3" | "HTTP/3.0") => Ok(Version::HTTP_3),
        Some(other) => Err(OpaqueError::from_static_str(
            "fastcgi: unsupported SERVER_PROTOCOL value",
        )
        .context_str_field("value", other)),
        None => {
            tracing::debug!("fastcgi: SERVER_PROTOCOL missing, defaulting to HTTP/1.1");
            Ok(Version::HTTP_11)
        }
    }
}

/// Read a UTF-8 param by name. Returns `None` if absent or non-UTF8.
fn param_str<'a>(params: &'a [(Bytes, Bytes)], name: &[u8]) -> Option<&'a str> {
    params
        .iter()
        .find(|(n, _)| n.as_ref() == name)
        .and_then(|(_, v)| std::str::from_utf8(v).ok())
}

fn param_bytes<'a>(params: &'a [(Bytes, Bytes)], name: &[u8]) -> Option<&'a [u8]> {
    params
        .iter()
        .find(|(n, _)| n.as_ref() == name)
        .map(|(_, v)| v.as_ref())
}

/// Reconstruct an HTTP [`Request`] from FastCGI CGI environment variables,
/// streaming the FastCGI `stdin` directly into the HTTP body.
pub(super) async fn fastcgi_request_to_http(req: FastCgiRequest) -> Result<Request, BoxError> {
    let FastCgiRequest { params, stdin, .. } = req;

    let method: Method = if let Some(m) = param_str(&params, b"REQUEST_METHOD") {
        m.parse().context("fastcgi: parse REQUEST_METHOD")?
    } else {
        tracing::debug!("fastcgi: REQUEST_METHOD missing, defaulting to GET");
        Method::GET
    };

    // Prefer REQUEST_URI (raw URI as the web server received it) when present
    // — it round-trips path + query precisely, avoiding script/path-info
    // reconstruction ambiguity.
    let uri_str: String = if let Some(req_uri) = param_str(&params, b"REQUEST_URI") {
        req_uri.to_owned()
    } else {
        tracing::debug!(
            "fastcgi: REQUEST_URI absent, reconstructing URI from SCRIPT_NAME + PATH_INFO + QUERY_STRING"
        );
        let script_name = param_str(&params, b"SCRIPT_NAME").unwrap_or("/");
        let path_info = param_str(&params, b"PATH_INFO").unwrap_or("");
        let query = param_str(&params, b"QUERY_STRING").unwrap_or("");
        if query.is_empty() {
            format!("{script_name}{path_info}")
        } else {
            format!("{script_name}{path_info}?{query}")
        }
    };

    let version =
        parse_server_protocol(param_str(&params, b"SERVER_PROTOCOL")).context("fastcgi")?;

    let mut builder = Request::builder()
        .method(method)
        .uri(uri_str)
        .version(version);

    let mut have_host = false;

    for (name, value) in &params {
        let Ok(name_str) = std::str::from_utf8(name) else {
            continue;
        };
        if let Some(suffix) = name_str.strip_prefix("HTTP_") {
            let mut header_name = String::with_capacity(suffix.len());
            for ch in suffix.chars() {
                header_name.push(if ch == '_' {
                    '-'
                } else {
                    ch.to_ascii_lowercase()
                });
            }
            let Ok(hname) = HeaderName::from_bytes(header_name.as_bytes()) else {
                tracing::debug!(
                    cgi.name = %name_str,
                    "fastcgi: dropping HTTP_* param with invalid header name"
                );
                continue;
            };
            let Ok(hval) = HeaderValue::from_bytes(value) else {
                tracing::debug!(
                    header.name = %hname,
                    "fastcgi: dropping HTTP_* param with invalid header value"
                );
                continue;
            };
            if hname == header::HOST {
                have_host = true;
            }
            builder = builder.header(hname, hval);
        } else if name_str.eq_ignore_ascii_case("CONTENT_TYPE") {
            if let Ok(hval) = HeaderValue::from_bytes(value) {
                builder = builder.header(header::CONTENT_TYPE, hval);
            } else {
                tracing::debug!("fastcgi: dropping CONTENT_TYPE with invalid header value");
            }
        } else if name_str.eq_ignore_ascii_case("CONTENT_LENGTH")
            && let Ok(hval) = HeaderValue::from_bytes(value)
        {
            builder = builder.header(header::CONTENT_LENGTH, hval);
        }
    }

    // Only synthesise Host from SERVER_NAME / SERVER_PORT when HTTP_HOST was
    // not already supplied — otherwise we'd inject a duplicate.
    if !have_host && let Some(name_bytes) = param_bytes(&params, b"SERVER_NAME") {
        let host = match param_str(&params, b"SERVER_PORT")
            .filter(|&p| p != "80" && p != "443" && !p.is_empty())
        {
            Some(port) => {
                let mut h = BytesMut::with_capacity(name_bytes.len() + 1 + port.len());
                h.extend_from_slice(name_bytes);
                h.extend_from_slice(b":");
                h.extend_from_slice(port.as_bytes());
                h.freeze()
            }
            None => Bytes::copy_from_slice(name_bytes),
        };
        match HeaderValue::from_bytes(&host) {
            Ok(hval) => builder = builder.header(header::HOST, hval),
            Err(err) => tracing::debug!(
                ?err,
                host = %String::from_utf8_lossy(&host),
                "fastcgi: synthesised Host header is not a valid HeaderValue, dropping"
            ),
        }
    }

    // Stream FastCgiBody → http Body without collecting.
    let stream = ReaderStream::new(stdin);
    builder.body(Body::from_stream(stream)).map_err(Into::into)
}

// ─────────────────────────────────────────────────────────────────────────
// Outbound: HTTP response → FastCGI server response (stdout serialization)
// ─────────────────────────────────────────────────────────────────────────

/// Serialize an HTTP [`Response`] to CGI stdout format, streaming the body
/// through as a [`FastCgiBody`] (no buffering).
pub(super) async fn http_response_to_fastcgi(resp: Response) -> Result<FastCgiResponse, BoxError> {
    let (parts, body) = resp.into_parts();

    let status = parts.status;
    let reason = status.canonical_reason().unwrap_or("Unknown");

    // Build headers prefix in memory (always small).
    let mut header_buf = BytesMut::new();
    header_buf.extend_from_slice(b"Status: ");
    header_buf.extend_from_slice(status.as_str().as_bytes());
    header_buf.extend_from_slice(b" ");
    header_buf.extend_from_slice(reason.as_bytes());
    header_buf.extend_from_slice(b"\r\n");

    for (name, value) in &parts.headers {
        header_buf.extend_from_slice(name.as_str().as_bytes());
        header_buf.extend_from_slice(b": ");
        header_buf.extend_from_slice(value.as_bytes());
        header_buf.extend_from_slice(b"\r\n");
    }
    header_buf.extend_from_slice(b"\r\n");

    // Chain header buffer with the streaming body.
    let header_reader = std::io::Cursor::new(header_buf.freeze());
    let body_stream = body.into_data_stream().map_err(io_error);
    let body_reader = StreamReader::new(body_stream);
    let chained = tokio::io::AsyncReadExt::chain(header_reader, body_reader);

    Ok(FastCgiResponse::new(FastCgiBody::from_reader(chained)))
}

// ─────────────────────────────────────────────────────────────────────────
// Header/body split for CGI stdout
// ─────────────────────────────────────────────────────────────────────────

/// Split a CGI stdout buffer into `(headers_with_trailing_separator, body)`.
///
/// `pos` from `slice::windows(N).position(...)` is bounded by
/// `data.len() - N`, so the additions below never overflow on practical
/// inputs (a `&[u8]` has `len <= isize::MAX`).
pub(super) fn split_cgi_response(data: &[u8]) -> (&[u8], &[u8]) {
    if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
        return (&data[..pos + 2], &data[pos + 4..]);
    }
    if let Some(pos) = data.windows(2).position(|w| w == b"\n\n") {
        return (&data[..pos + 1], &data[pos + 2..]);
    }
    (data, b"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_core::bytes::Bytes;

    #[test]
    fn test_split_cgi_response_crlf() {
        let (h, b) = split_cgi_response(b"Status: 200 OK\r\nFoo: bar\r\n\r\nhello");
        assert_eq!(h, b"Status: 200 OK\r\nFoo: bar\r\n");
        assert_eq!(b, b"hello");
    }

    #[test]
    fn test_split_cgi_response_lf() {
        let (h, b) = split_cgi_response(b"Content-Type: text/plain\n\nhello");
        assert_eq!(h, b"Content-Type: text/plain\n");
        assert_eq!(b, b"hello");
    }

    #[test]
    fn test_fastcgi_response_to_http_status_and_headers() {
        let stdout =
            b"Status: 418 I'm a teapot\r\nContent-Type: text/plain\r\nX-Custom: yes\r\n\r\nhi";
        let resp = fastcgi_response_to_http(FastCgiClientResponse {
            stdout: Bytes::from_static(stdout),
            stderr: Bytes::new(),
            app_status: 0,
        });
        assert_eq!(resp.status(), StatusCode::IM_A_TEAPOT);
        assert_eq!(resp.headers().get("content-type").unwrap(), "text/plain");
        assert_eq!(resp.headers().get("x-custom").unwrap(), "yes");
    }

    #[test]
    fn test_fastcgi_response_to_http_defaults_to_200() {
        let stdout = b"Content-Type: text/plain\r\n\r\nhello";
        let resp = fastcgi_response_to_http(FastCgiClientResponse {
            stdout: Bytes::from_static(stdout),
            stderr: Bytes::new(),
            app_status: 0,
        });
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn test_fastcgi_response_to_http_drops_invalid_header_name() {
        // A space in the header name is invalid; HeaderName::from_bytes rejects it.
        let stdout = b"Bad Header: value\r\nGood-Header: ok\r\n\r\n";
        let resp = fastcgi_response_to_http(FastCgiClientResponse {
            stdout: Bytes::from_static(stdout),
            stderr: Bytes::new(),
            app_status: 0,
        });
        assert!(resp.headers().get("good-header").is_some());
    }

    #[test]
    fn test_parse_cgi_status_handles_reason_phrase_or_bare_code() {
        assert_eq!(parse_cgi_status(b"200 OK"), Some(StatusCode::OK));
        assert_eq!(parse_cgi_status(b"201"), Some(StatusCode::CREATED));
        assert_eq!(parse_cgi_status(b""), None);
        assert_eq!(parse_cgi_status(b"not a number"), None);
        assert_eq!(parse_cgi_status(b"9999"), None);
    }

    #[test]
    fn test_version_to_protocol_rejects_unknown() {
        assert_eq!(version_to_protocol(Version::HTTP_11).unwrap(), "HTTP/1.1");
        assert_eq!(version_to_protocol(Version::HTTP_10).unwrap(), "HTTP/1.0");
        assert_eq!(version_to_protocol(Version::HTTP_2).unwrap(), "HTTP/2");
        // HTTP_09 is a valid Version variant but we don't support it.
        version_to_protocol(Version::HTTP_09).unwrap_err();
    }

    #[test]
    fn test_parse_server_protocol_errors_on_unknown() {
        assert_eq!(
            parse_server_protocol(Some("HTTP/1.1")).unwrap(),
            Version::HTTP_11
        );
        assert_eq!(
            parse_server_protocol(Some("HTTP/2.0")).unwrap(),
            Version::HTTP_2
        );
        parse_server_protocol(Some("SPDY/3")).unwrap_err();
        // Absent → debug-log + default to HTTP/1.1 (legitimate behaviour).
        assert_eq!(parse_server_protocol(None).unwrap(), Version::HTTP_11);
    }

    #[tokio::test]
    async fn test_fastcgi_request_to_http_no_duplicate_host() {
        let params: Vec<(Bytes, Bytes)> = vec![
            (
                Bytes::from_static(b"REQUEST_METHOD"),
                Bytes::from_static(b"GET"),
            ),
            (Bytes::from_static(b"REQUEST_URI"), Bytes::from_static(b"/")),
            (
                Bytes::from_static(b"SERVER_NAME"),
                Bytes::from_static(b"example.com"),
            ),
            (
                Bytes::from_static(b"SERVER_PORT"),
                Bytes::from_static(b"443"),
            ),
            (
                Bytes::from_static(b"HTTP_HOST"),
                Bytes::from_static(b"explicit.example"),
            ),
        ];
        let req = FastCgiRequest {
            request_id: 1,
            role: crate::proto::Role::Responder,
            keep_conn: false,
            params,
            stdin: FastCgiBody::empty(),
            data: FastCgiBody::empty(),
        };
        let http_req = fastcgi_request_to_http(req).await.unwrap();
        let host_count = http_req.headers().get_all("host").iter().count();
        assert_eq!(host_count, 1, "must not duplicate Host header");
        assert_eq!(http_req.headers().get("host").unwrap(), "explicit.example");
    }

    #[tokio::test]
    async fn test_http_request_to_fastcgi_emits_required_vars() {
        let req = Request::builder()
            .method("POST")
            .uri("http://example.com/path?q=1")
            .header("host", "example.com")
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap();
        let fcgi = http_request_to_fastcgi(req).await.unwrap();
        let find = |k: &[u8]| -> Option<Bytes> {
            fcgi.params
                .iter()
                .find(|(n, _)| n.as_ref() == k)
                .map(|(_, v)| v.clone())
        };
        assert_eq!(find(b"REQUEST_METHOD").as_deref(), Some(b"POST".as_ref()));
        assert_eq!(
            find(b"GATEWAY_INTERFACE").as_deref(),
            Some(b"CGI/1.1".as_ref())
        );
        assert_eq!(find(b"REQUEST_URI").as_deref(), Some(b"/path?q=1".as_ref()));
        assert_eq!(find(b"QUERY_STRING").as_deref(), Some(b"q=1".as_ref()));
        assert_eq!(find(b"REDIRECT_STATUS").as_deref(), Some(b"200".as_ref()));
        assert_eq!(
            find(b"CONTENT_TYPE").as_deref(),
            Some(b"application/json".as_ref())
        );
        assert_eq!(
            find(b"SERVER_NAME").as_deref(),
            Some(b"example.com".as_ref())
        );
        // Host should NOT be forwarded as HTTP_HOST.
        assert!(find(b"HTTP_HOST").is_none());
    }

    #[tokio::test]
    async fn test_http_request_to_fastcgi_env_override_honored() {
        let req = Request::builder()
            .method("GET")
            .uri("http://example.com/")
            .header("host", "example.com")
            .body(Body::empty())
            .unwrap();
        req.extensions().insert(
            FastCgiHttpEnv::new()
                .with_redirect_status("403")
                .with_gateway_interface("CGI/1.0")
                .with_server_software("custom/1.0"),
        );
        let fcgi = http_request_to_fastcgi(req).await.unwrap();
        let find = |k: &[u8]| -> Option<Bytes> {
            fcgi.params
                .iter()
                .find(|(n, _)| n.as_ref() == k)
                .map(|(_, v)| v.clone())
        };
        assert_eq!(find(b"REDIRECT_STATUS").as_deref(), Some(b"403".as_ref()));
        assert_eq!(
            find(b"GATEWAY_INTERFACE").as_deref(),
            Some(b"CGI/1.0".as_ref())
        );
        assert_eq!(
            find(b"SERVER_SOFTWARE").as_deref(),
            Some(b"custom/1.0".as_ref())
        );
    }

    #[tokio::test]
    async fn test_http_request_to_fastcgi_always_emits_content_length() {
        // GET without a body: CL=0.
        let req = Request::builder()
            .method("GET")
            .uri("http://example.com/")
            .header("host", "example.com")
            .body(Body::empty())
            .unwrap();
        let fcgi = http_request_to_fastcgi(req).await.unwrap();
        let cl = fcgi
            .params
            .iter()
            .find(|(n, _)| n.as_ref() == b"CONTENT_LENGTH")
            .map(|(_, v)| v.clone());
        assert_eq!(cl.as_deref(), Some(b"0".as_ref()));

        // POST with explicit Content-Length: forwarded verbatim.
        let req = Request::builder()
            .method("POST")
            .uri("http://example.com/")
            .header("host", "example.com")
            .header("content-length", "9")
            .body(Body::from("name=rama"))
            .unwrap();
        let fcgi = http_request_to_fastcgi(req).await.unwrap();
        let cl = fcgi
            .params
            .iter()
            .find(|(n, _)| n.as_ref() == b"CONTENT_LENGTH")
            .map(|(_, v)| v.clone());
        assert_eq!(cl.as_deref(), Some(b"9".as_ref()));

        // POST without Content-Length (simulated chunked): CL=0 fallback.
        let req = Request::builder()
            .method("POST")
            .uri("http://example.com/")
            .header("host", "example.com")
            .body(Body::from("anything"))
            .unwrap();
        let fcgi = http_request_to_fastcgi(req).await.unwrap();
        let cl = fcgi
            .params
            .iter()
            .find(|(n, _)| n.as_ref() == b"CONTENT_LENGTH")
            .map(|(_, v)| v.clone());
        assert_eq!(
            cl.as_deref(),
            Some(b"0".as_ref()),
            "CONTENT_LENGTH must be present (even =0) for POST without Content-Length header"
        );
    }
}
