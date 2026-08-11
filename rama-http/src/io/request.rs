use crate::{Body, Request, StreamingBody};
use rama_core::{bytes::Bytes, error::BoxError};
use rama_http_types::proto::h2::{PseudoHeader, PseudoHeaderOrder};
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
            for header in pseudo_headers.iter() {
                match header {
                    PseudoHeader::Method => {
                        try_format_into(
                            &mut line,
                            format_args!("[{}: {}]\r\n", header, parts.method),
                        )?;
                        w.write_all(line.as_bytes()).await?;
                    }
                    PseudoHeader::Scheme => {
                        try_format_into(
                            &mut line,
                            format_args!(
                                "[{}: {}]\r\n",
                                header,
                                parts.uri.scheme_str().unwrap_or("?")
                            ),
                        )?;
                        w.write_all(line.as_bytes()).await?;
                    }
                    PseudoHeader::Authority => {
                        match parts.uri.authority() {
                            Some(authority) => {
                                try_format_into(
                                    &mut line,
                                    format_args!("[{header}: {authority}]\r\n"),
                                )?;
                            }
                            None => {
                                try_format_into(&mut line, format_args!("[{header}: ?]\r\n"))?;
                            }
                        }
                        w.write_all(line.as_bytes()).await?;
                    }
                    PseudoHeader::Path => {
                        try_format_into(
                            &mut line,
                            format_args!("[{}: {}]\r\n", header, parts.uri.path_or_root()),
                        )?;
                        w.write_all(line.as_bytes()).await?;
                    }
                    PseudoHeader::Protocol | PseudoHeader::Status => (), // not expected in request
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
    use crate::Body;

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
