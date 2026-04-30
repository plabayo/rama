//! Conversion helpers between HTTP and FastCGI types.

use bytes::{Bytes, BytesMut};

use rama_core::{error::BoxError, extensions::ExtensionsRef};
use rama_http_types::{Body, Method, Request, Response, StatusCode, Version, body::util::BodyExt};
use rama_net::stream::SocketInfo;

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

// Headers that must NOT become HTTP_* CGI variables.
pub(super) const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "te",
    "trailer",
    "upgrade",
];

/// Build a [`FastCgiClientRequest`] from an HTTP request, collecting the body.
pub(super) async fn http_request_to_fastcgi(req: Request) -> Result<FastCgiClientRequest, BoxError> {
    let peer_addr = req
        .extensions()
        .get_ref::<SocketInfo>()
        .map(|s: &SocketInfo| s.peer_addr().to_string());

    let (parts, body) = req.into_parts();
    let stdin: Bytes = body.collect().await.map_err(BoxError::from)?.to_bytes();

    let method = parts.method.as_str().to_owned();
    let path = parts.uri.path().to_owned();
    let query = parts.uri.query().unwrap_or("").to_owned();
    let protocol = version_to_protocol(parts.version).to_owned();

    let host_val = parts
        .headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let (server_name, server_port) = if let Some(ref host) = host_val {
        if let Some(pos) = host.rfind(':') {
            (host[..pos].to_owned(), host[pos + 1..].to_owned())
        } else {
            (host.clone(), "80".to_owned())
        }
    } else {
        ("localhost".to_owned(), "80".to_owned())
    };

    let content_length = stdin.len().to_string();

    let mut params: Vec<(Bytes, Bytes)> = Vec::with_capacity(20);

    macro_rules! param {
        ($name:expr, $value:expr) => {
            params.push((Bytes::from_static($name), Bytes::from($value)));
        };
    }

    param!(b"REQUEST_METHOD", method);
    param!(b"SCRIPT_NAME", path);
    param!(b"PATH_INFO", String::new());
    param!(b"QUERY_STRING", query);
    param!(b"SERVER_PROTOCOL", protocol);
    param!(b"SERVER_NAME", server_name);
    param!(b"SERVER_PORT", server_port);
    param!(b"GATEWAY_INTERFACE", "FastCGI/1.0".to_owned());
    param!(b"CONTENT_LENGTH", content_length);

    if let Some(ct) = parts.headers.get("content-type") {
        params.push((
            Bytes::from_static(b"CONTENT_TYPE"),
            Bytes::copy_from_slice(ct.as_bytes()),
        ));
    }

    if let Some(addr) = peer_addr {
        param!(b"REMOTE_ADDR", addr);
    }

    for (name, value) in &parts.headers {
        let n = name.as_str();
        if n == "host" || n == "content-type" || n == "content-length" {
            continue;
        }
        if HOP_BY_HOP.contains(&n) {
            continue;
        }
        let cgi_name = format!("HTTP_{}", n.to_uppercase().replace('-', "_"));
        params.push((Bytes::from(cgi_name), Bytes::copy_from_slice(value.as_bytes())));
    }

    Ok(FastCgiClientRequest::new(params).with_stdin(stdin))
}

/// Parse a [`FastCgiClientResponse`] (CGI stdout) into an HTTP [`Response`].
pub(super) fn fastcgi_response_to_http(resp: FastCgiClientResponse) -> Response {
    let stdout = resp.stdout;
    let (header_bytes, body_bytes) = split_cgi_response(&stdout);

    let mut builder = Response::builder().status(StatusCode::OK);

    for line in header_bytes.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        if let Some(sep) = line.iter().position(|&b| b == b':') {
            let name = std::str::from_utf8(&line[..sep]).unwrap_or("").trim();
            let value = std::str::from_utf8(&line[sep + 1..]).unwrap_or("").trim();
            if name.eq_ignore_ascii_case("Status") {
                if let Some(code) = value.splitn(2, ' ').next() {
                    if let Ok(s) = code.parse::<u16>() {
                        builder = builder.status(s);
                    }
                }
            } else if !name.is_empty() {
                builder = builder.header(name, value);
            }
        }
    }

    builder
        .body(Body::from(Bytes::copy_from_slice(body_bytes)))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

/// Reconstruct an HTTP [`Request`] from FastCGI CGI environment variables.
///
/// Collects the streaming `FastCgiBody` stdin into memory before building the
/// HTTP request. Services that need true stdin streaming should implement
/// `Service<FastCgiRequest>` directly instead of using this adapter.
pub(super) async fn fastcgi_request_to_http(req: FastCgiRequest) -> Result<Request, BoxError> {
    let FastCgiRequest { params, stdin, .. } = req;

    let stdin_bytes = stdin.collect().await.map_err(BoxError::from)?;

    let param = |name: &[u8]| -> Option<&str> {
        params
            .iter()
            .find(|(n, _)| n.as_ref() == name)
            .and_then(|(_, v)| std::str::from_utf8(v).ok())
    };

    let method: Method = param(b"REQUEST_METHOD")
        .and_then(|m| m.parse().ok())
        .unwrap_or(Method::GET);

    let script_name = param(b"SCRIPT_NAME").unwrap_or("/");
    let path_info = param(b"PATH_INFO").unwrap_or("");
    let query = param(b"QUERY_STRING").unwrap_or("");

    let uri_str = if query.is_empty() {
        format!("{}{}", script_name, path_info)
    } else {
        format!("{}{}?{}", script_name, path_info, query)
    };

    let version = param(b"SERVER_PROTOCOL")
        .map(|v| match v {
            "HTTP/1.0" => Version::HTTP_10,
            "HTTP/2" | "HTTP/2.0" => Version::HTTP_2,
            _ => Version::HTTP_11,
        })
        .unwrap_or(Version::HTTP_11);

    let mut builder = Request::builder()
        .method(method)
        .uri(uri_str)
        .version(version);

    if let Some(name) = param(b"SERVER_NAME") {
        let host = match param(b"SERVER_PORT").filter(|&p| p != "80" && p != "443") {
            Some(port) => format!("{}:{}", name, port),
            None => name.to_owned(),
        };
        builder = builder.header("host", host.as_str());
    }

    for (name, value) in &params {
        let name_str = match std::str::from_utf8(name) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let value_str = match std::str::from_utf8(value) {
            Ok(s) => s,
            Err(_) => continue,
        };
        if let Some(suffix) = name_str.strip_prefix("HTTP_") {
            let header = suffix.to_lowercase().replace('_', "-");
            builder = builder.header(header.as_str(), value_str);
        } else if name_str.eq_ignore_ascii_case("CONTENT_TYPE") {
            builder = builder.header("content-type", value_str);
        } else if name_str.eq_ignore_ascii_case("CONTENT_LENGTH") {
            builder = builder.header("content-length", value_str);
        }
    }

    builder.body(Body::from(stdin_bytes)).map_err(BoxError::from)
}

/// Serialize an HTTP [`Response`] to CGI stdout format.
pub(super) async fn http_response_to_fastcgi(resp: Response) -> Result<FastCgiResponse, BoxError> {
    let (parts, body) = resp.into_parts();
    let body_bytes: Bytes = body.collect().await.map_err(BoxError::from)?.to_bytes();

    let status = parts.status;
    let reason = status.canonical_reason().unwrap_or("Unknown");
    let mut stdout = BytesMut::new();

    let status_line = format!("Status: {} {}\r\n", status.as_u16(), reason);
    stdout.extend_from_slice(status_line.as_bytes());

    for (name, value) in &parts.headers {
        stdout.extend_from_slice(name.as_str().as_bytes());
        stdout.extend_from_slice(b": ");
        stdout.extend_from_slice(value.as_bytes());
        stdout.extend_from_slice(b"\r\n");
    }

    stdout.extend_from_slice(b"\r\n");
    stdout.extend_from_slice(&body_bytes);

    Ok(FastCgiResponse::new(stdout.freeze()))
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
