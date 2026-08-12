use crate::{Body, Response, StreamingBody};
use rama_core::{bytes::Bytes, error::BoxError};
use rama_http_types::proto::h2::{PseudoHeader, PseudoHeaderOrder};
use rama_utils::fmt::try_format_into;
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
    write_http_response_inner(w, res, write_headers, write_body, true).await
}

pub(crate) async fn write_http_response_streaming<W, B>(
    w: &mut W,
    res: Response<B>,
    write_headers: bool,
    write_body: bool,
) -> Result<(), BoxError>
where
    W: AsyncWrite + Unpin + Send + Sync + 'static,
    B: StreamingBody<Data = Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
{
    drop(write_http_response_inner(w, res, write_headers, write_body, false).await?);
    Ok(())
}

async fn write_http_response_inner<W, B>(
    w: &mut W,
    res: Response<B>,
    write_headers: bool,
    write_body: bool,
    retain_body: bool,
) -> Result<Response, BoxError>
where
    W: AsyncWrite + Unpin + Send + Sync + 'static,
    B: StreamingBody<Data = Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
{
    let (mut parts, body) = res.into_parts();

    if write_headers {
        let mut line = String::new();
        match parts.status.canonical_reason() {
            Some(reason) => {
                try_format_into(
                    &mut line,
                    format_args!("{:?} {} {reason}\r\n", parts.version, parts.status.as_u16()),
                )?;
            }
            None => {
                try_format_into(
                    &mut line,
                    format_args!("{:?} {}\r\n", parts.version, parts.status.as_u16()),
                )?;
            }
        }
        w.write_all(line.as_bytes()).await?;

        if let Some(pseudo_headers) = parts.extensions.get_ref::<PseudoHeaderOrder>() {
            for header in pseudo_headers.iter() {
                match header {
                    PseudoHeader::Method
                    | PseudoHeader::Scheme
                    | PseudoHeader::Authority
                    | PseudoHeader::Path
                    | PseudoHeader::Protocol => (), // not expected in response
                    PseudoHeader::Status => {
                        // Preserve the historical textual pseudo-header output,
                        // including its extra space before the reason phrase.
                        match parts.status.canonical_reason() {
                            Some(reason) => {
                                try_format_into(
                                    &mut line,
                                    format_args!(
                                        "[{}: {}  {reason}]\r\n",
                                        header,
                                        parts.status.as_u16()
                                    ),
                                )?;
                            }
                            None => {
                                try_format_into(
                                    &mut line,
                                    format_args!("[{}: {} ]\r\n", header, parts.status.as_u16()),
                                )?;
                            }
                        }
                        w.write_all(line.as_bytes()).await?;
                    }
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

    let req = Response::from_parts(parts, body);
    Ok(req)
}

#[cfg(test)]
mod tests {
    use std::{convert::Infallible, time::Duration};

    use rama_core::futures::stream;
    use tokio::io::AsyncReadExt as _;

    use super::*;
    use crate::Body;

    #[tokio::test]
    async fn streaming_writer_emits_chunks_before_end_of_stream() {
        let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
        let stream = stream::unfold(receiver, |mut receiver| async move {
            receiver.recv().await.map(|item| (item, receiver))
        });
        let response = Response::new(Body::from_stream(stream));
        let (mut writer, mut reader) = tokio::io::duplex(64);
        let write = tokio::spawn(async move {
            write_http_response_streaming(&mut writer, response, false, true)
                .await
                .unwrap();
        });

        sender
            .send(Ok::<_, Infallible>(Bytes::from_static(b"first")))
            .unwrap();
        let mut first = [0; 7];
        tokio::time::timeout(Duration::from_secs(1), reader.read_exact(&mut first))
            .await
            .expect("the first chunk should be written before end-of-stream")
            .unwrap();
        assert_eq!(&first, b"\r\nfirst");

        sender.send(Ok(Bytes::from_static(b"second"))).unwrap();
        drop(sender);
        let mut second = [0; 6];
        reader.read_exact(&mut second).await.unwrap();
        assert_eq!(&second, b"second");
        write.await.unwrap();
    }

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

    #[tokio::test]
    async fn writes_opaque_header_value_bytes() {
        let mut buf = Vec::new();
        let response = Response::builder()
            .status(200)
            .header("x-first", "kept")
            .header("x-opaque", crate::HeaderValue::from_bytes(&[0x80]).unwrap())
            .body(Body::empty())
            .unwrap();

        write_http_response(&mut buf, response, true, true)
            .await
            .unwrap();

        assert_eq!(
            buf,
            b"HTTP/1.1 200 OK\r\nx-first: kept\r\nx-opaque: \x80\r\n\r\n"
        );
    }

    #[tokio::test]
    async fn lowercases_opaque_header_names_for_http2() {
        let mut buf = Vec::new();
        let response = Response::builder()
            .version(crate::Version::HTTP_2)
            .status(200)
            .header("X-Opaque", crate::HeaderValue::from_bytes(&[0x80]).unwrap())
            .body(Body::empty())
            .unwrap();

        write_http_response(&mut buf, response, true, true)
            .await
            .unwrap();

        assert_eq!(buf, b"HTTP/2.0 200 OK\r\nx-opaque: \x80\r\n\r\n");
    }
}
