use crate::{
    Body, Request,
    dep::{http_body, http_body_util::BodyExt},
};
use rama_core::{bytes::Bytes, error::BoxError};
use rama_http_types::proto::{
    h1::Http1HeaderMap,
    h2::{PseudoHeader, PseudoHeaderOrder},
};
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
    B: http_body::Body<Data = Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
{
    let (mut parts, body) = req.into_parts();

    if write_headers {
        w.write_all(
            format!(
                "{} {}{} {:?}\r\n",
                parts.method,
                parts.uri.path(),
                parts
                    .uri
                    .query()
                    .map(|q| format!("?{q}"))
                    .unwrap_or_default(),
                parts.version
            )
            .as_bytes(),
        )
        .await?;

        if let Some(pseudo_headers) = parts.extensions.get::<PseudoHeaderOrder>() {
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
                                parts.uri.scheme_str().unwrap_or("?")
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
                                parts.uri.authority().map(|a| a.as_str()).unwrap_or("?")
                            )
                            .as_bytes(),
                        )
                        .await?;
                    }
                    PseudoHeader::Path => {
                        w.write_all(format!("[{}: {}]\r\n", header, parts.uri.path()).as_bytes())
                            .await?;
                    }
                    PseudoHeader::Protocol => (), // TODO: move ext h2 protocol out of h2 proto core once we need this info
                    PseudoHeader::Status => (),   // not expected in request
                }
            }
        }

        let header_map = Http1HeaderMap::new(parts.headers, Some(&mut parts.extensions));
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
        let body = body.collect().await.map_err(Into::into)?.to_bytes();
        w.write_all(b"\r\n").await?;
        if !body.is_empty() {
            w.write_all(body.as_ref()).await?;
        }
        Body::from(body)
    } else {
        Body::new(body)
    };

    let req = Request::from_parts(parts, body);
    Ok(req)
}

#[cfg(test)]
mod tests {
    use super::*;

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
