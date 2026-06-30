//! http I/O utilities, e.g. writing http requests/responses in std http format.

use crate::{Body, HeaderMap, StreamingBody, body::util::BodyExt};
use rama_core::bytes::Bytes;
use rama_core::error::{BoxError, ErrorContext as _};
use rama_core::extensions::Extensions;
use rama_http_types::Version;
use tokio::io::{AsyncWrite, AsyncWriteExt};

mod request;
#[doc(inline)]
pub use request::write_http_request;

mod response;
#[doc(inline)]
pub use response::write_http_response;

pub mod upgrade;

/// Write the request/response `headers` (combined with `extensions` into an
/// [`HeaderMap`]) to `w` in std HTTP/1 wire format — lower-cased names for
/// H2/H3, original casing otherwise. The map is reconstructed back into
/// `*headers` so callers can keep tracing it after this consumes it.
///
/// Shared by [`write_http_request`] and [`write_http_response`].
pub(crate) async fn write_http1_header_map<W>(
    w: &mut W,
    headers: &mut HeaderMap,
    _extensions: &Extensions,
    version: Version,
) -> Result<(), BoxError>
where
    W: AsyncWrite + Unpin + Send + Sync + 'static,
{
    let header_map = std::mem::take(headers);
    // put a clone of this data back into headers as we don't really want to
    // consume it, just trace it
    *headers = header_map.clone();

    for (name, value) in header_map.into_ordered_iter() {
        match version {
            Version::HTTP_2 | Version::HTTP_3 => {
                // write lower-case for H2/H3
                let mut line = Vec::new();
                name.write_lowercase(&mut line);
                line.extend_from_slice(b": ");
                line.extend_from_slice(value.to_str()?.as_bytes());
                line.extend_from_slice(b"\r\n");
                w.write_all(&line).await?;
            }
            _ => {
                w.write_all(format!("{}: {}\r\n", name, value.to_str()?).as_bytes())
                    .await?;
            }
        }
    }

    Ok(())
}

/// Collect `body`; when `write_body` is set, write the CRLF separator and the
/// buffered bytes to `w` and return a [`Body`] that re-emits them. When unset,
/// return the body untouched (headers-only writes). Shared by
/// [`write_http_request`] and [`write_http_response`].
pub(crate) async fn write_http1_body<W, B>(
    w: &mut W,
    body: B,
    write_body: bool,
) -> Result<Body, BoxError>
where
    W: AsyncWrite + Unpin + Send + Sync + 'static,
    B: StreamingBody<Data = Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
{
    Ok(if write_body {
        let body = body.collect().await.into_box_error()?.to_bytes();
        w.write_all(b"\r\n").await?;
        if !body.is_empty() {
            w.write_all(body.as_ref()).await?;
        }
        Body::from(body)
    } else {
        Body::new(body)
    })
}
