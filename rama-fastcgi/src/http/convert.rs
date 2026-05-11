//! Conversion helpers between HTTP and FastCGI types.
//!
//! Emits the de-facto FastCGI parameter set that nginx / Apache / php-fpm
//! expect — see `specifications/nginx_fastcgi_params.md` for the curated
//! contract. Bodies stream through (no buffering) in both directions on the
//! request side; the response side currently collects stdout into a bounded
//! buffer (capped by
//! [`ClientOptions::max_stdout_bytes`][crate::client::ClientOptions::max_stdout_bytes]).

use rama_core::bytes::{Bytes, BytesMut};
use rama_core::futures::TryStreamExt;
use tokio_util::io::{ReaderStream, StreamReader};

use rama_core::{error::BoxError, extensions::ExtensionsRef, telemetry::tracing};
use rama_http_types::{
    Body, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Version,
};
use rama_net::http::RequestContext;
use rama_net::stream::SocketInfo;

use crate::body::FastCgiBody;
use crate::client::{FastCgiClientRequest, FastCgiClientResponse};
use crate::server::{FastCgiRequest, FastCgiResponse};

pub(super) fn version_to_protocol(v: Version) -> &'static str {
    match v {
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_2 => "HTTP/2",
        Version::HTTP_3 => "HTTP/3",
        _ => "HTTP/1.1",
    }
}

/// Headers that must NOT become HTTP_* CGI variables (hop-by-hop per RFC 7230
/// §6.1) plus the ones that have dedicated CGI variables.
pub(super) const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "te",
    "trailer",
    "upgrade",
];

/// Build a [`FastCgiClientRequest`] from an HTTP request **without** buffering
/// the body. The request body is plumbed through as a [`FastCgiBody`] backed
/// by the original [`Body`] stream.
pub(super) async fn http_request_to_fastcgi(
    req: Request,
) -> Result<FastCgiClientRequest, BoxError> {
    let peer = req.extensions().get_ref::<SocketInfo>().cloned();

    // Best-effort RequestContext to recover scheme / authority. Failures are
    // non-fatal — we fall back to header-derived values.
    let req_ctx = RequestContext::try_from(&req).ok();

    let (parts, body) = req.into_parts();

    let method = parts.method.as_str().to_owned();
    let path = parts.uri.path().to_owned();
    let query = parts.uri.query().unwrap_or("").to_owned();
    let request_uri = if query.is_empty() {
        path.clone()
    } else {
        format!("{path}?{query}")
    };
    let protocol = version_to_protocol(parts.version).to_owned();

    let (server_name, server_port, is_https) = derive_server_info(&parts, req_ctx.as_ref());

    let content_length_header = parts
        .headers
        .get(rama_http_types::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    let mut params: Vec<(Bytes, Bytes)> = Vec::with_capacity(24);

    macro_rules! param {
        ($name:expr, $value:expr) => {
            params.push((Bytes::from_static($name), Bytes::from($value)));
        };
    }

    // ── Required CGI/1.1 variables (RFC 3875 §4) ─────────────────────────
    param!(b"GATEWAY_INTERFACE", "CGI/1.1".to_owned());
    param!(b"SERVER_PROTOCOL", protocol);
    param!(b"REQUEST_METHOD", method);

    // ── Script / path split. The default policy treats the entire URL
    //    path as SCRIPT_NAME with empty PATH_INFO; this matches modern
    //    framework routing. Sites that need traditional script-file/extra
    //    path splitting should layer a router on top of this connector.
    param!(b"SCRIPT_NAME", path.clone());
    param!(b"PATH_INFO", String::new());
    param!(b"QUERY_STRING", query);

    // ── nginx de-facto variables ─────────────────────────────────────────
    param!(b"REQUEST_URI", request_uri);
    param!(b"DOCUMENT_URI", path);
    param!(
        b"REQUEST_SCHEME",
        if is_https { "https" } else { "http" }.to_owned()
    );
    if is_https {
        param!(b"HTTPS", "on".to_owned());
    }
    // Required by php-fpm (with cgi.force_redirect=1, the default).
    param!(b"REDIRECT_STATUS", "200".to_owned());

    param!(b"SERVER_NAME", server_name);
    param!(b"SERVER_PORT", server_port);

    if let Some(p) = peer.as_ref() {
        let peer_addr = p.peer_addr();
        param!(b"REMOTE_ADDR", peer_addr.ip_addr.to_string());
        param!(b"REMOTE_PORT", peer_addr.port.to_string());
        if let Some(local) = p.local_addr() {
            param!(b"SERVER_ADDR", local.ip_addr.to_string());
        }
    }

    if let Some(cl) = content_length_header {
        param!(b"CONTENT_LENGTH", cl);
    } else {
        // Unknown body length (chunked etc) — CGI requires CONTENT_LENGTH to be
        // present per RFC 3875 §4.1.2 ("if and only if the request includes a
        // message-body"). Set 0 if the method is body-less, otherwise omit and
        // let the backend rely on EOF-on-STDIN.
        if !matches!(parts.method, Method::POST | Method::PUT | Method::PATCH) {
            param!(b"CONTENT_LENGTH", "0".to_owned());
        }
    }

    if let Some(ct) = parts.headers.get(rama_http_types::header::CONTENT_TYPE) {
        params.push((
            Bytes::from_static(b"CONTENT_TYPE"),
            Bytes::copy_from_slice(ct.as_bytes()),
        ));
    }

    // ── HTTP_* header mapping (RFC 3875 §4.1.18) ─────────────────────────
    for (name, value) in &parts.headers {
        let n = name.as_str();
        if n == "host" || n == "content-type" || n == "content-length" {
            continue;
        }
        if HOP_BY_HOP.contains(&n) {
            continue;
        }
        let mut cgi_name = String::with_capacity(5 + n.len());
        cgi_name.push_str("HTTP_");
        for ch in n.chars() {
            if ch == '-' {
                cgi_name.push('_');
            } else {
                cgi_name.push(ch.to_ascii_uppercase());
            }
        }
        params.push((
            Bytes::from(cgi_name),
            Bytes::copy_from_slice(value.as_bytes()),
        ));
    }

    // ── Body: stream into FastCgiBody (no .collect) ─────────────────────
    let body_stream = body.into_data_stream().map_err(io_error);
    let body_reader = StreamReader::new(body_stream);
    let stdin = FastCgiBody::from_reader(body_reader);

    Ok(FastCgiClientRequest::new(params).with_stdin(stdin))
}

fn io_error(e: BoxError) -> std::io::Error {
    std::io::Error::other(e)
}

fn derive_server_info(
    parts: &rama_http_types::request::Parts,
    req_ctx: Option<&RequestContext>,
) -> (String, String, bool) {
    let is_https = match req_ctx {
        Some(ctx) => ctx.protocol.is_secure(),
        None => parts
            .uri
            .scheme()
            .map(|s| s.as_str().eq_ignore_ascii_case("https"))
            .unwrap_or(false),
    };

    // Prefer RequestContext authority (already accounts for forwarded headers).
    if let Some(ctx) = req_ctx {
        let host = ctx.authority.host.to_string();
        let port = ctx
            .authority
            .port
            .or_else(|| ctx.protocol.default_port())
            .unwrap_or(if is_https { 443 } else { 80 });
        return (host, port.to_string(), is_https);
    }

    let host_val = parts
        .headers
        .get(rama_http_types::header::HOST)
        .and_then(|v| v.to_str().ok());

    if let Some(host) = host_val {
        if let Some(pos) = host.rfind(':') {
            return (host[..pos].to_owned(), host[pos + 1..].to_owned(), is_https);
        }
        return (
            host.to_owned(),
            if is_https { "443" } else { "80" }.to_owned(),
            is_https,
        );
    }

    (
        "localhost".to_owned(),
        if is_https { "443" } else { "80" }.to_owned(),
        is_https,
    )
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
            continue;
        };
        let raw_name = &line[..sep];
        let raw_value = trim_ascii(&line[sep + 1..]);
        if raw_name.eq_ignore_ascii_case(b"Status") {
            // Status: NNN [reason]
            if let Some(code) = std::str::from_utf8(raw_value)
                .ok()
                .and_then(|v| v.split(' ').next())
                && let Ok(s) = code.parse::<u16>()
                && let Ok(status) = StatusCode::from_u16(s)
            {
                builder = builder.status(status);
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
            tracing::debug!("fastcgi: dropping response header with invalid value");
            continue;
        };
        builder = builder.header(header_name, header_value);
    }

    builder
        .body(Body::from(Bytes::copy_from_slice(body_bytes)))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

/// Reconstruct an HTTP [`Request`] from FastCGI CGI environment variables,
/// streaming the FastCGI `stdin` directly into the HTTP body.
pub(super) async fn fastcgi_request_to_http(req: FastCgiRequest) -> Result<Request, BoxError> {
    let FastCgiRequest { params, stdin, .. } = req;

    let param = |name: &[u8]| -> Option<&str> {
        params
            .iter()
            .find(|(n, _)| n.as_ref() == name)
            .and_then(|(_, v)| std::str::from_utf8(v).ok())
    };
    let param_bytes = |name: &[u8]| -> Option<&[u8]> {
        params
            .iter()
            .find(|(n, _)| n.as_ref() == name)
            .map(|(_, v)| v.as_ref())
    };

    let method: Method = param(b"REQUEST_METHOD")
        .and_then(|m| m.parse().ok())
        .unwrap_or(Method::GET);

    // Prefer REQUEST_URI (raw URI as the web server received it) when present
    // — it round-trips path + query precisely, avoiding script/path-info
    // reconstruction ambiguity.
    let uri_str: String = if let Some(req_uri) = param(b"REQUEST_URI") {
        req_uri.to_owned()
    } else {
        let script_name = param(b"SCRIPT_NAME").unwrap_or("/");
        let path_info = param(b"PATH_INFO").unwrap_or("");
        let query = param(b"QUERY_STRING").unwrap_or("");
        if query.is_empty() {
            format!("{script_name}{path_info}")
        } else {
            format!("{script_name}{path_info}?{query}")
        }
    };

    let version = param(b"SERVER_PROTOCOL")
        .map(|v| match v {
            "HTTP/1.0" => Version::HTTP_10,
            "HTTP/2" | "HTTP/2.0" => Version::HTTP_2,
            "HTTP/3" | "HTTP/3.0" => Version::HTTP_3,
            _ => Version::HTTP_11,
        })
        .unwrap_or(Version::HTTP_11);

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
            let mut header = String::with_capacity(suffix.len());
            for ch in suffix.chars() {
                if ch == '_' {
                    header.push('-');
                } else {
                    header.push(ch.to_ascii_lowercase());
                }
            }
            let Ok(hname) = HeaderName::from_bytes(header.as_bytes()) else {
                continue;
            };
            let Ok(hval) = HeaderValue::from_bytes(value) else {
                continue;
            };
            if hname == rama_http_types::header::HOST {
                have_host = true;
            }
            builder = builder.header(hname, hval);
        } else if name_str.eq_ignore_ascii_case("CONTENT_TYPE") {
            if let Ok(hval) = HeaderValue::from_bytes(value) {
                builder = builder.header(rama_http_types::header::CONTENT_TYPE, hval);
            }
        } else if name_str.eq_ignore_ascii_case("CONTENT_LENGTH")
            && let Ok(hval) = HeaderValue::from_bytes(value)
        {
            builder = builder.header(rama_http_types::header::CONTENT_LENGTH, hval);
        }
    }

    // Only synthesise Host from SERVER_NAME / SERVER_PORT when HTTP_HOST was
    // not already supplied — otherwise we'd inject a duplicate.
    if !have_host && let Some(name_bytes) = param_bytes(b"SERVER_NAME") {
        let host = match param(b"SERVER_PORT").filter(|&p| p != "80" && p != "443" && !p.is_empty())
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
        if let Ok(hval) = HeaderValue::from_bytes(&host) {
            builder = builder.header(rama_http_types::header::HOST, hval);
        }
    }

    // Stream FastCgiBody → http Body without collecting.
    let stream = ReaderStream::new(stdin);
    builder
        .body(Body::from_stream(stream))
        .map_err(BoxError::from)
}

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

pub(super) fn split_cgi_response(data: &[u8]) -> (&[u8], &[u8]) {
    if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
        return (&data[..pos + 2], &data[pos + 4..]);
    }
    if let Some(pos) = data.windows(2).position(|w| w == b"\n\n") {
        return (&data[..pos + 1], &data[pos + 2..]);
    }
    (data, b"")
}

fn trim_ascii(mut s: &[u8]) -> &[u8] {
    while let Some((&first, rest)) = s.split_first() {
        if first.is_ascii_whitespace() {
            s = rest;
        } else {
            break;
        }
    }
    while let Some((&last, rest)) = s.split_last() {
        if last.is_ascii_whitespace() {
            s = rest;
        } else {
            break;
        }
    }
    s
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
}
