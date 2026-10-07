use crate::{Body, Request, StreamingBody};
use rama_core::{bytes::Bytes, error::BoxError};
use rama_http_types::proto::{
    ext::Protocol,
    h2::{PseudoHeaderOrder, frame::Pseudo},
};
use rama_utils::fmt::try_format_into;
use tokio::io::{AsyncWrite, AsyncWriteExt};

/// Write an HTTP request to a writer in std http format.
pub async fn write_http_request<W, B>(
    w: &mut W,
    req: Request<B>,
    write_headers: bool,
    write_body: bool,
) -> Result<Request, BoxError>
where
    W: AsyncWrite + Unpin + Send + Sync + 'static,
    B: StreamingBody<Data = Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
{
    write_http_request_inner(w, req, write_headers, write_body, true).await
}

pub(crate) async fn write_http_request_streaming<W, B>(
    w: &mut W,
    req: Request<B>,
    write_headers: bool,
    write_body: bool,
) -> Result<(), BoxError>
where
    W: AsyncWrite + Unpin + Send + Sync + 'static,
    B: StreamingBody<Data = Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
{
    drop(write_http_request_inner(w, req, write_headers, write_body, false).await?);
    Ok(())
}

async fn write_http_request_inner<W, B>(
    w: &mut W,
    req: Request<B>,
    write_headers: bool,
    write_body: bool,
    retain_body: bool,
) -> Result<Request, BoxError>
where
    W: AsyncWrite + Unpin + Send + Sync + 'static,
    B: StreamingBody<Data = Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
{
    let (mut parts, body) = req.into_parts();

    if write_headers {
        let mut line = String::new();
        try_format_into(
            &mut line,
            format_args!(
                "{} {} {:?}\r\n",
                parts.method,
                parts.uri.request_target(),
                parts.version
            ),
        )?;
        w.write_all(line.as_bytes()).await?;

        if let Some(pseudo_headers) = parts.extensions.get_ref::<PseudoHeaderOrder>() {
            // Pseudo-header values as `Pseudo::request` derives them, not the raw URI parts.
            let pseudo = Pseudo::request(
                parts.method.clone(),
                &parts.uri,
                parts.extensions.get_ref::<Protocol>().cloned(),
            );
            for header in pseudo_headers.iter() {
                if let Some(value) = pseudo.value(header) {
                    try_format_into(&mut line, format_args!("[{header}: {value}]\r\n"))?;
                    w.write_all(line.as_bytes()).await?;
                }
            }
        }

        super::write_http1_header_map(w, &mut parts.headers, parts.version, &mut line).await?;
    }

    let body = if retain_body {
        super::write_http1_body(w, body, write_body).await?
    } else {
        super::write_http1_body_streaming(w, body, write_body).await?;
        Body::empty()
    };

    let req = Request::from_parts(parts, body);
    Ok(req)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Body, Method, Version};
    use rama_core::extensions::ExtensionsRef as _;
    use rama_http_types::proto::h2::PseudoHeader;

    #[tokio::test]
    async fn pseudo_headers_show_what_is_sent() {
        for (method, uri, protocol, expected) in [
            (
                Method::GET,
                "https://u:p@example.com/a?b=c",
                None,
                "[:method: GET]\r\n[:scheme: https]\r\n[:authority: example.com]\r\n[:path: /a?b=c]\r\n",
            ),
            (
                Method::CONNECT,
                "wss://example.com/chat?x=1",
                Some(Protocol::WEBSOCKET),
                "[:method: CONNECT]\r\n[:scheme: https]\r\n[:authority: example.com]\r\n[:path: /chat?x=1]\r\n[:protocol: websocket]\r\n",
            ),
            (
                Method::CONNECT,
                "ws://example.com",
                Some(Protocol::WEBSOCKET),
                "[:method: CONNECT]\r\n[:scheme: http]\r\n[:authority: example.com]\r\n[:path: /]\r\n[:protocol: websocket]\r\n",
            ),
            (
                Method::CONNECT,
                "https://example.com:443/",
                None,
                "[:method: CONNECT]\r\n[:authority: example.com:443]\r\n",
            ),
            (
                Method::OPTIONS,
                "https://example.com",
                None,
                "[:method: OPTIONS]\r\n[:scheme: https]\r\n[:authority: example.com]\r\n[:path: *]\r\n",
            ),
            (
                Method::GET,
                "foo://example.com",
                None,
                "[:method: GET]\r\n[:scheme: foo]\r\n[:authority: example.com]\r\n[:path: ]\r\n",
            ),
            (
                Method::GET,
                "foo://example.com?q",
                None,
                "[:method: GET]\r\n[:scheme: foo]\r\n[:authority: example.com]\r\n[:path: /?q]\r\n",
            ),
        ] {
            let req = Request::builder()
                .method(method)
                .uri(uri)
                .version(Version::HTTP_2)
                .body(Body::empty())
                .unwrap();
            req.extensions().insert(PseudoHeaderOrder::from_iter([
                PseudoHeader::Method,
                PseudoHeader::Scheme,
                PseudoHeader::Authority,
                PseudoHeader::Path,
                PseudoHeader::Protocol,
            ]));
            if let Some(protocol) = protocol {
                req.extensions().insert(protocol);
            }

            let mut buf = Vec::new();
            write_http_request(&mut buf, req, true, false)
                .await
                .unwrap();
            let written = std::str::from_utf8(&buf).unwrap();
            let (_, rest) = written.split_once("\r\n").unwrap();
            assert_eq!(rest, expected, "{uri}");
        }
    }

    #[tokio::test]
    async fn test_write_http_request_get() {
        let mut buf = Vec::new();
        let req = Request::builder()
            .method("GET")
            .uri("http://example.com")
            .body(Body::empty())
            .unwrap();

        write_http_request(&mut buf, req, true, true).await.unwrap();

        let req = String::from_utf8(buf).unwrap();
        assert_eq!(req, "GET / HTTP/1.1\r\n\r\n");
    }

    #[tokio::test]
    async fn test_write_http_request_get_with_headers() {
        let mut buf = Vec::new();
        let req = Request::builder()
            .method("GET")
            .uri("http://example.com")
            .header("content-type", "text/plain")
            .header("user-agent", "test/0")
            .body(Body::empty())
            .unwrap();

        write_http_request(&mut buf, req, true, true).await.unwrap();

        let req = String::from_utf8(buf).unwrap();
        assert_eq!(
            req,
            "GET / HTTP/1.1\r\ncontent-type: text/plain\r\nuser-agent: test/0\r\n\r\n"
        );
    }

    #[tokio::test]
    async fn test_write_http_request_get_with_headers_and_query() {
        let mut buf = Vec::new();
        let req = Request::builder()
            .method("GET")
            .uri("http://example.com?foo=bar")
            .header("content-type", "text/plain")
            .header("user-agent", "test/0")
            .body(Body::empty())
            .unwrap();

        write_http_request(&mut buf, req, true, true).await.unwrap();

        let req = String::from_utf8(buf).unwrap();
        assert_eq!(
            req,
            "GET /?foo=bar HTTP/1.1\r\ncontent-type: text/plain\r\nuser-agent: test/0\r\n\r\n"
        );
    }

    #[tokio::test]
    async fn test_write_http_request_post_with_headers_and_body() {
        let mut buf = Vec::new();
        let req = Request::builder()
            .method("POST")
            .uri("http://example.com")
            .header("content-type", "text/plain")
            .header("user-agent", "test/0")
            .body(Body::from("hello"))
            .unwrap();

        write_http_request(&mut buf, req, true, true).await.unwrap();

        let req = String::from_utf8(buf).unwrap();
        assert_eq!(
            req,
            "POST / HTTP/1.1\r\ncontent-type: text/plain\r\nuser-agent: test/0\r\n\r\nhello"
        );
    }

    #[tokio::test]
    async fn streaming_writer_writes_request_body() {
        let mut buf = Vec::new();
        let req = Request::builder()
            .method("POST")
            .uri("http://example.com")
            .body(Body::from("streamed"))
            .unwrap();

        write_http_request_streaming(&mut buf, req, false, true)
            .await
            .unwrap();

        assert_eq!(buf, b"\r\nstreamed");
    }
}
