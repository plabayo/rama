use crate::{Request, StreamingBody};
use rama_core::{bytes::Bytes, error::BoxError};
use rama_http_types::proto::h2::{PseudoHeader, PseudoHeaderOrder};
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
    let (mut parts, body) = req.into_parts();

    if write_headers {
        w.write_all(
            format!(
                "{} {}{} {:?}\r\n",
                parts.method,
                parts
                    .uri
                    .path()
                    .map(|p| p.as_raw_str())
                    .filter(|p| !p.is_empty())
                    .unwrap_or("/"),
                parts
                    .uri
                    .query()
                    .map(|q| format!("?{}", q.as_raw_str()))
                    .unwrap_or_default(),
                parts.version
            )
            .as_bytes(),
        )
        .await?;

        if let Some(pseudo_headers) = parts.extensions.get_ref::<PseudoHeaderOrder>() {
            for header in pseudo_headers.iter() {
                match header {
                    PseudoHeader::Method => {
                        w.write_all(format!("[{}: {}]\r\n", header, parts.method).as_bytes())
                            .await?;
                    }
                    PseudoHeader::Scheme => {
                        w.write_all(
                            format!(
                                "[{}: {}]\r\n",
                                header,
                                parts.uri.scheme().map(|s| s.as_str()).unwrap_or("?")
                            )
                            .as_bytes(),
                        )
                        .await?;
                    }
                    PseudoHeader::Authority => {
                        w.write_all(
                            format!(
                                "[{}: {}]\r\n",
                                header,
                                parts
                                    .uri
                                    .authority()
                                    .map(|a| a.to_string())
                                    .unwrap_or_else(|| "?".to_owned())
                            )
                            .as_bytes(),
                        )
                        .await?;
                    }
                    PseudoHeader::Path => {
                        w.write_all(
                            format!(
                                "[{}: {}]\r\n",
                                header,
                                parts
                                    .uri
                                    .path()
                                    .map(|p| p.as_raw_str())
                                    .filter(|p| !p.is_empty())
                                    .unwrap_or("/")
                            )
                            .as_bytes(),
                        )
                        .await?;
                    }
                    PseudoHeader::Protocol | PseudoHeader::Status => (), // not expected in request
                }
            }
        }

        super::write_http1_header_map(w, &mut parts.headers, &parts.extensions, parts.version)
            .await?;
    }

    let body = super::write_http1_body(w, body, write_body).await?;

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
}
