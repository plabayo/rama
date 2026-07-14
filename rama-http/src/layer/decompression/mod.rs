//! Middleware that decompresses request and response bodies.
//!
//! # Examples
//!
//! #### Request
//! ```rust
//! use std::{error::Error, io::Write};
//!
//! use rama_core::bytes::{Bytes, BytesMut};
//! use flate2::{write::GzEncoder, Compression};
//!
//! use rama_http::{Body, header, HeaderValue, Request, Response};
//! use rama_core::service::service_fn;
//! use rama_core::{Service, Layer};
//! use rama_http::layer::decompression::{DecompressionBody, RequestDecompressionLayer};
//! use rama_http::body::util::BodyExt;
//! use rama_core::error::BoxError;
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), BoxError> {
//! // A request encoded with gzip coming from some HTTP client.
//! let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
//! encoder.write_all(b"Hello?")?;
//! let request = Request::builder()
//!     .header(header::CONTENT_ENCODING, "gzip")
//!     .body(Body::from(encoder.finish()?))?;
//!
//! // Our HTTP server
//! let mut server = (
//!     // Automatically decompress request bodies.
//!     RequestDecompressionLayer::new(),
//! ).into_layer(service_fn(handler));
//!
//! // Send the request, with the gzip encoded body, to our server.
//! let _response = server.serve(request).await?;
//!
//! // Handler receives request whose body is decoded when read
//! async fn handler(mut req: Request<DecompressionBody<Body>>) -> Result<Response, BoxError>{
//!     let data = req.into_body().collect().await?.to_bytes();
//!     assert_eq!(&data[..], b"Hello?");
//!     Ok(Response::new(Body::from("Hello, World!")))
//! }
//! # Ok(())
//! # }
//! ```
//!
//! #### Response
//!
//! ```rust
//! use std::convert::Infallible;
//!
//! use rama_core::bytes::{Bytes, BytesMut};
//!
//! use rama_http::{Body, Request, Response};
//! use rama_core::service::service_fn;
//! use rama_core::{Service, Layer};
//! use rama_http::layer::{compression::Compression, decompression::DecompressionLayer};
//! use rama_http::body::util::BodyExt;
//! use rama_core::error::BoxError;
//!
//! #
//! # #[tokio::main]
//! # async fn main() -> Result<(), BoxError> {
//! # async fn handle(req: Request) -> Result<Response, Infallible> {
//! #     let body = Body::from("Hello, World!");
//! #     Ok(Response::new(body))
//! # }
//!
//! // Some opaque service that applies compression.
//! let service = Compression::new(service_fn(handle));
//!
//! // Our HTTP client.
//! let mut client = (
//!     // Automatically decompress response bodies.
//!     DecompressionLayer::new(),
//! ).into_layer(service);
//!
//! // Call the service.
//! //
//! // `DecompressionLayer` takes care of setting `Accept-Encoding`.
//! let request = Request::new(Body::default());
//!
//! let response = client
//!     .serve(request)
//!     .await?;
//!
//! // Read the body
//! let body = response.into_body();
//! let bytes = body.collect().await?.to_bytes().to_vec();
//! let body = String::from_utf8(bytes).map_err(Into::<BoxError>::into)?;
//!
//! assert_eq!(body, "Hello, World!");
//! #
//! # Ok(())
//! # }
//! ```

mod request;

use rama_core::extensions::Extension;

pub(crate) mod body;
mod layer;
mod service;

/// Marker extension inserted into a response when [`Decompression`] unwraps a
/// compressed response body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Extension)]
#[extension(tags(http))]
pub enum DecompressedFrom {
    Gzip,
    Deflate,
    Brotli,
    Zstd,
}

#[doc(inline)]
pub use self::{
    body::DecompressionBody,
    layer::DecompressionLayer,
    service::{Decompression, DefaultDecompressionMatcher},
};

#[doc(inline)]
pub use self::request::layer::RequestDecompressionLayer;
#[doc(inline)]
pub use self::request::service::RequestDecompression;

#[cfg(test)]
mod tests {
    use super::*;

    use std::convert::Infallible;
    use std::io::Write;
    use std::time::Duration;

    use crate::layer::compression::Compression;
    use crate::{Body, HeaderMap, HeaderName, Request, Response, body::util::BodyExt};
    use rama_core::error::ErrorContext;
    use rama_core::extensions::ExtensionsRef;
    use rama_core::futures::{StreamExt as _, stream};
    use rama_core::matcher::service::MatcherServicePair;
    use rama_core::service::service_fn;
    use rama_core::{Service, bytes::Bytes};

    use rama_http_types::{BodyExtractExt, header};

    #[tokio::test]
    async fn works() {
        let client = Decompression::new(Compression::new(service_fn(handle)));

        let req = Request::builder()
            .header("accept-encoding", "gzip")
            .body(Body::empty())
            .unwrap();
        let res = client.serve(req).await.unwrap();

        assert_eq!(
            res.extensions().get_ref::<DecompressedFrom>(),
            Some(&DecompressedFrom::Gzip)
        );

        // read the body, it will be decompressed automatically
        let body = res.into_body();
        let collected = body.collect().await.unwrap();
        let decompressed_data = String::from_utf8(collected.to_bytes().to_vec()).unwrap();

        assert_eq!(
            decompressed_data,
            "Hello, World! Hello, World! Hello, World!"
        );
    }

    async fn handle(_req: Request<Body>) -> Result<Response<Body>, Infallible> {
        let mut trailers = HeaderMap::new();
        trailers.insert(HeaderName::from_static("foo"), "bar".parse().unwrap());
        let body = Body::from("Hello, World! Hello, World! Hello, World!");
        Ok(Response::builder().body(body).unwrap())
    }

    #[tokio::test]
    async fn decompress_multi_zstd() {
        let client = Decompression::new(service_fn(handle_multi_zstd));

        let req = Request::builder()
            .header("accept-encoding", "zstd")
            .body(Body::empty())
            .unwrap();
        let res = client.serve(req).await.unwrap();

        // read the body, it will be decompressed automatically
        let body = res.into_body();
        let decompressed_data =
            String::from_utf8(body.collect().await.unwrap().to_bytes().to_vec()).unwrap();

        assert_eq!(decompressed_data, "Hello, World!");
    }

    async fn handle_multi_zstd(_req: Request<Body>) -> Result<Response<Body>, Infallible> {
        let mut buf = Vec::new();
        let mut enc1 = zstd::Encoder::new(&mut buf, Default::default()).unwrap();
        enc1.write_all(b"Hello, ").unwrap();
        enc1.finish().unwrap();

        let mut enc2 = zstd::Encoder::new(&mut buf, Default::default()).unwrap();
        enc2.write_all(b"World!").unwrap();
        enc2.finish().unwrap();

        let mut res = Response::new(Body::from(buf));
        res.headers_mut()
            .insert("content-encoding", "zstd".parse().unwrap());
        Ok(res)
    }

    #[tokio::test]
    async fn decompress_empty() {
        let client = Decompression::new(Compression::new(service_fn(handle_empty)));

        let req = Request::builder()
            .header("accept-encoding", "gzip")
            .body(Body::empty())
            .unwrap();
        let res = client.serve(req).await.unwrap();

        let decompressed_data = res.try_into_string().await.unwrap();

        assert_eq!(decompressed_data, "");
    }

    async fn handle_empty(_req: Request<Body>) -> Result<Response<Body>, Infallible> {
        let mut res = Response::new(Body::empty());
        res.headers_mut()
            .insert("content-encoding", "gzip".parse().unwrap());
        Ok(res)
    }

    #[tokio::test]
    async fn decompress_empty_with_trailers() {
        let client = Decompression::new(Compression::new(service_fn(handle_empty_with_trailers)));
        let req = Request::builder()
            .header("accept-encoding", "gzip")
            .body(Body::empty())
            .unwrap();
        let res = client.serve(req).await.unwrap();
        let body = res.into_body();
        let collected = body.collect().await.unwrap();
        let trailers = collected.trailers().cloned().unwrap(); // TODO
        let decompressed_data = String::from_utf8(collected.to_bytes().to_vec()).unwrap();
        assert_eq!(decompressed_data, "");
        assert_eq!(trailers["foo"], "bar");
    }

    async fn handle_empty_with_trailers(_req: Request<Body>) -> Result<Response<Body>, Infallible> {
        let mut trailers = HeaderMap::new();
        trailers.insert(HeaderName::from_static("foo"), "bar".parse().unwrap());
        let body = Body::empty().with_trailer_headers(trailers);
        Ok(Response::builder()
            .header("content-encoding", "gzip")
            .body(body)
            .unwrap())
    }

    #[tokio::test]
    async fn does_not_insert_accept_encoding_when_disabled() {
        let client = Decompression::new(service_fn(|req: Request<Body>| async move {
            assert!(!req.headers().contains_key(header::ACCEPT_ENCODING));
            Ok::<_, Infallible>(Response::new(Body::empty()))
        }))
        .with_insert_accept_encoding_header(false);

        let req = Request::new(Body::empty());
        _ = client.serve(req).await.unwrap();
    }

    // A long, mildly-varied plaintext so the brotli stream spans multiple chunks
    // (guarantees the decoder yields some output before the truncation errors).
    fn long_plaintext() -> String {
        (0..4000)
            .map(|i| format!("line {i}: the quick brown fox\n"))
            .collect()
    }

    // Corrupt a run of bytes in the middle of a valid brotli stream: the decoder
    // produces output for the valid prefix, then hits an invalid block and errors
    // with InvalidData (the real "brotli error" case — a clean tail-truncation
    // instead hits brotli's UnexpectedEof clean-EOF path and would NOT error).
    fn corrupt_brotli(plaintext: &str) -> Vec<u8> {
        let mut full = Vec::new();
        {
            let mut w = brotli::CompressorWriter::new(&mut full, 4096, 5, 22);
            w.write_all(plaintext.as_bytes()).unwrap();
        } // drop finishes the stream
        let n = full.len();
        let start = n / 3;
        let end = (start + n / 4).min(n);
        for b in &mut full[start..end] {
            *b ^= 0xFF;
        }
        full
    }

    async fn collect_truncated_br(
        tolerate: bool,
    ) -> Result<rama_core::bytes::Bytes, rama_core::error::BoxError> {
        let body = corrupt_brotli(&long_plaintext());
        let client = Decompression::new(service_fn(move |_req: Request<Body>| {
            let body = body.clone();
            async move {
                Ok::<_, Infallible>(
                    Response::builder()
                        .header(header::CONTENT_ENCODING, "br")
                        .body(Body::from(body))
                        .unwrap(),
                )
            }
        }))
        .with_tolerate_decode_errors(tolerate);
        let req = Request::builder()
            .header("accept-encoding", "br")
            .body(Body::empty())
            .unwrap();
        let res = client.serve(req).await.unwrap();
        res.into_body()
            .collect()
            .await
            .map(|c| c.to_bytes())
            .into_box_error()
    }

    #[tokio::test]
    async fn truncated_brotli_with_tolerance_ends_cleanly() {
        let collected = collect_truncated_br(true).await;
        assert!(
            collected.is_ok(),
            "tolerant decode must end the stream cleanly, not error"
        );
        let bytes = collected.unwrap();
        // The salvaged output must be a clean prefix of the original (no garbage
        // from the corrupt block); it may be empty if the decoder had not flushed
        // output before the corruption — the load-bearing property is that the
        // stream ENDS rather than ABORTS.
        assert!(
            long_plaintext().as_bytes().starts_with(&bytes),
            "decoded bytes must be a clean prefix of the original plaintext (len={})",
            bytes.len()
        );
    }

    #[tokio::test]
    async fn truncated_brotli_without_tolerance_still_errors() {
        // Regression guard: the default (strict) behavior must be unchanged.
        assert!(
            collect_truncated_br(false).await.is_err(),
            "strict decode must surface the truncation as an error"
        );
    }

    #[tokio::test]
    async fn response_matcher_can_disable_decompression() {
        let client = Decompression::new(Compression::new(service_fn(handle)))
            .with_matcher(MatcherServicePair(true, MatcherServicePair(false, ())));

        let req = Request::builder()
            .header("accept-encoding", "gzip")
            .body(Body::empty())
            .unwrap();
        let res = client.serve(req).await.unwrap();

        assert!(res.extensions().get_ref::<DecompressedFrom>().is_none());
        assert_eq!(res.headers().get(header::CONTENT_ENCODING).unwrap(), "gzip");

        let compressed = res.into_body().collect().await.unwrap().to_bytes();
        assert_ne!(
            std::str::from_utf8(&compressed).unwrap_or_default(),
            "Hello, World! Hello, World! Hello, World!"
        );
    }

    #[tokio::test]
    async fn brotli_rejects_extra_data_without_waiting_for_end_of_body() {
        let mut compressed = Vec::new();
        {
            let mut encoder = brotli::CompressorWriter::new(&mut compressed, 4096, 5, 20);
            encoder.write_all(b"Hello, World!").unwrap();
        }

        let svc = service_fn(move |_req: Request<Body>| {
            let compressed = compressed.clone();
            async move {
                let stream = stream::iter([
                    Ok::<_, Infallible>(Bytes::from(compressed)),
                    Ok(Bytes::from_static(b"extra")),
                ])
                .chain(stream::pending());

                Ok::<_, Infallible>(
                    Response::builder()
                        .header("content-encoding", "br")
                        .body(Body::from_stream(stream))
                        .unwrap(),
                )
            }
        });
        let client = Decompression::new(svc);

        let res = client.serve(Request::new(Body::empty())).await.unwrap();

        let result = tokio::time::timeout(Duration::from_secs(1), res.into_body().collect())
            .await
            .expect("extra data should produce an error without waiting for the body to end");
        _ = result.unwrap_err();
    }
}
