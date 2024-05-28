use crate::{
    error::BoxError,
    http::{
        dep::{http_body, http_body_util::BodyExt},
        Body, Request,
    },
};
use bytes::Bytes;
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
    B: http_body::Body<Data = Bytes> + Send + Sync + 'static,
    B::Error: std::error::Error + Send + Sync,
{
    let (parts, body) = req.into_parts();

    w.write_all(
        format!(
            "{} {} {:?}\r\n",
            parts.method,
            parts.uri.path(),
            parts.version
        )
        .as_bytes(),
    )
    .await?;

    if write_headers {
        for (key, value) in parts.headers.iter() {
            w.write_all(format!("{}: {}\r\n", key, value.to_str()?).as_bytes())
                .await?;
        }
    }

    let body = if write_body {
        let body = body.collect().await?.to_bytes();
        w.write_all(b"\r\n").await?;
        if !body.is_empty() {
            w.write_all(body.as_ref()).await?;
            w.write_all(b"\r\n").await?;
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
            "POST / HTTP/1.1\r\ncontent-type: text/plain\r\nuser-agent: test/0\r\n\r\nhello\r\n"
        );
    }
}
