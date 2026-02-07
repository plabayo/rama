use crate::{Body, Response, StreamingBody, body::util::BodyExt};
use rama_core::{
    bytes::Bytes,
    error::{BoxError, ErrorContext as _},
};
use rama_http_types::proto::{
    h1::Http1HeaderMap,
    h2::{PseudoHeader, PseudoHeaderOrder},
};
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

        if let Some(pseudo_headers) = parts.extensions.get::<PseudoHeaderOrder>() {
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

        let header_map = Http1HeaderMap::new(parts.headers, Some(&parts.extensions));
        // put a clone of this data back into parts as we don't really want to consume it, just trace it
        parts.headers = header_map.clone().consume(&mut parts.extensions);

        for (name, value) in header_map {
            match parts.version {
                rama_http_types::Version::HTTP_2 | rama_http_types::Version::HTTP_3 => {
                    // write lower-case for H2/H3
                    w.write_all(
                        format!("{}: {}\r\n", name.header_name().as_str(), value.to_str()?)
                            .as_bytes(),
                    )
                    .await?;
                }
                _ => {
                    w.write_all(format!("{}: {}\r\n", name, value.to_str()?).as_bytes())
                        .await?;
                }
            }
        }
    }

    let body = if write_body {
        let body = body.collect().await.into_box_error()?.to_bytes();
        w.write_all(b"\r\n").await?;
        if !body.is_empty() {
            w.write_all(body.as_ref()).await?;
        }
        Body::from(body)
    } else {
        Body::new(body)
    };

    let req = Response::from_parts(parts, body);
    Ok(req)
}

#[cfg(test)]
mod tests {
    use super::*;

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
