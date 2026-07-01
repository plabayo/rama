use crate::{Response, StreamingBody};
use rama_core::{bytes::Bytes, error::BoxError};
use rama_http_types::proto::h2::{PseudoHeader, PseudoHeaderOrder};
use tokio::io::{AsyncWrite, AsyncWriteExt};

/// Write an HTTP response to a writer in std http format.
pub async fn write_http_response<W, B>(
    w: &mut W,
    res: Response<B>,
    write_headers: bool,
    write_body: bool,
) -> Result<Response, BoxError>
where
    W: AsyncWrite + Unpin + Send + Sync + 'static,
    B: StreamingBody<Data = Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
{
    let (mut parts, body) = res.into_parts();

    if write_headers {
        w.write_all(
            format!(
                "{:?} {}{}\r\n",
                parts.version,
                parts.status.as_u16(),
                parts
                    .status
                    .canonical_reason()
                    .map(|r| format!(" {r}"))
                    .unwrap_or_default(),
            )
            .as_bytes(),
        )
        .await?;

        if let Some(pseudo_headers) = parts.extensions.get_ref::<PseudoHeaderOrder>() {
            for header in pseudo_headers.iter() {
                match header {
                    PseudoHeader::Method
                    | PseudoHeader::Scheme
                    | PseudoHeader::Authority
                    | PseudoHeader::Path
                    | PseudoHeader::Protocol => (), // not expected in response
                    PseudoHeader::Status => {
                        w.write_all(
                            format!(
                                "[{}: {} {}]\r\n",
                                header,
                                parts.status.as_u16(),
                                parts
                                    .status
                                    .canonical_reason()
                                    .map(|r| format!(" {r}"))
                                    .unwrap_or_default(),
                            )
                            .as_bytes(),
                        )
                        .await?;
                    }
                }
            }
        }

        super::write_http1_header_map(w, &mut parts.headers, parts.version).await?;
    }

    let body = super::write_http1_body(w, body, write_body).await?;

    let req = Response::from_parts(parts, body);
    Ok(req)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Body;

    #[tokio::test]
    async fn test_write_response_ok() {
        let mut buf = Vec::new();
        let res = Response::builder().status(200).body(Body::empty()).unwrap();

        write_http_response(&mut buf, res, true, true)
            .await
            .unwrap();

        let res = String::from_utf8(buf).unwrap();
        assert_eq!(res, "HTTP/1.1 200 OK\r\n\r\n");
    }

    #[tokio::test]
    async fn test_write_response_redirect() {
        let mut buf = Vec::new();
        let res = Response::builder()
            .status(301)
            .header("location", "http://example.com")
            .header("server", "test/0")
            .body(Body::empty())
            .unwrap();

        write_http_response(&mut buf, res, true, true)
            .await
            .unwrap();

        let res = String::from_utf8(buf).unwrap();
        assert_eq!(
            res,
            "HTTP/1.1 301 Moved Permanently\r\nlocation: http://example.com\r\nserver: test/0\r\n\r\n"
        );
    }

    #[tokio::test]
    async fn test_write_response_with_headers_and_body() {
        let mut buf = Vec::new();
        let res = Response::builder()
            .status(200)
            .header("content-type", "text/plain")
            .header("server", "test/0")
            .body(Body::from("hello"))
            .unwrap();

        write_http_response(&mut buf, res, true, true)
            .await
            .unwrap();

        let res = String::from_utf8(buf).unwrap();
        assert_eq!(
            res,
            "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\nserver: test/0\r\n\r\nhello"
        );
    }
}
