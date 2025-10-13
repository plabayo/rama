use crate::layer::compression::CompressionLevel;
use rama_core::Layer;

use super::CompressAdaptService;

/// Layer which tracks the original 'Accept-Encoding' header and compares
/// it with the server 'Content-Encoding' header, to adapt the response if needed.
///
/// See [`CompressAdaptService`] for more information.
#[derive(Clone, Debug, Default)]
pub struct CompressAdaptLayer {
    quality: CompressionLevel,
}

impl<S> Layer<S> for CompressAdaptLayer {
    type Service = CompressAdaptService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        CompressAdaptService {
            inner,
            quality: self.quality,
        }
    }
}

impl CompressAdaptLayer {
    /// Creates a new [`CompressAdaptLayer`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the compression quality.
    #[must_use]
    pub fn quality(mut self, quality: CompressionLevel) -> Self {
        self.quality = quality;
        self
    }

    /// Sets the compression quality.
    pub fn set_quality(&mut self, quality: CompressionLevel) -> &mut Self {
        self.quality = quality;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::layer::compression::CompressionLayer;
    use crate::layer::set_header::SetResponseHeaderLayer;
    use crate::{Body, Request, Response, body::util::BodyExt, header::ACCEPT_ENCODING};
    use rama_core::Service;
    use rama_core::service::service_fn;
    use rama_core::stream::io::ReaderStream;
    use rama_http_types::HeaderValue;
    use std::convert::Infallible;
    use tokio::fs::File;
    use zstd::zstd_safe::WriteBuf;

    async fn handle(_req: Request) -> Result<Response, Infallible> {
        // Open the file.
        let file = File::open("Cargo.toml").await.expect("file missing");
        // Convert the file into a `Stream`.
        let stream = ReaderStream::new(file);
        // Convert the `Stream` into a `Body`.
        let body = Body::from_stream(stream);
        // Create response.
        Ok(Response::new(body))
    }

    #[tokio::test]
    async fn compress_adapter_no_action_required_no_encoding_server()
    -> Result<(), rama_core::error::BoxError> {
        let service = (
            CompressAdaptLayer::default(),
            SetResponseHeaderLayer::overriding(
                ACCEPT_ENCODING,
                HeaderValue::from_static("gzip, deflate, br"),
            ),
        )
            .into_layer(service_fn(handle));

        let request = Request::builder()
            .header(ACCEPT_ENCODING, "deflate")
            .body(Body::empty())?;

        let response = service.serve(request).await?;

        assert!(!response.headers().contains_key("content-encoding"));

        let body = response.into_body();
        let bytes = body.collect().await.unwrap().to_bytes();

        assert!(find_subsequence(bytes.as_slice(), b"rama-http").is_some());

        Ok(())
    }

    #[tokio::test]
    async fn compress_adapter_no_action_required_no_encoding_client()
    -> Result<(), rama_core::error::BoxError> {
        let service = (
            CompressAdaptLayer::default(),
            CompressionLayer::new()
                .quality(CompressionLevel::Best)
                .br(false)
                .gzip(false),
        )
            .into_layer(service_fn(handle));

        let request = Request::builder().body(Body::empty())?;

        let response = service.serve(request).await?;

        assert!(!response.headers().contains_key("content-encoding"));

        let body = response.into_body();
        let bytes = body.collect().await.unwrap().to_bytes();

        assert!(find_subsequence(bytes.as_slice(), b"rama-http").is_some());

        Ok(())
    }

    #[tokio::test]
    async fn compress_adapter_no_action_required_compatible_encoding()
    -> Result<(), rama_core::error::BoxError> {
        let service = (
            CompressAdaptLayer::default(),
            SetResponseHeaderLayer::overriding(
                ACCEPT_ENCODING,
                HeaderValue::from_static("deflate"),
            ),
            CompressionLayer::new()
                .quality(CompressionLevel::Best)
                .br(false)
                .gzip(false),
        )
            .into_layer(service_fn(handle));

        let request = Request::builder()
            .header(ACCEPT_ENCODING, "deflate")
            .body(Body::empty())?;

        let response = service.serve(request).await?;

        assert_eq!(response.headers()["content-encoding"], "deflate");

        let body = response.into_body();
        let bytes = body.collect().await.unwrap().to_bytes();

        assert!(find_subsequence(bytes.as_slice(), b"rama-http").is_none());

        Ok(())
    }

    #[tokio::test]
    async fn compress_adapter_no_action_required_no_compatible_encoding()
    -> Result<(), rama_core::error::BoxError> {
        let service = (
            CompressAdaptLayer::default(),
            SetResponseHeaderLayer::overriding(
                ACCEPT_ENCODING,
                HeaderValue::from_static("gzip, br"),
            ),
            CompressionLayer::new()
                .quality(CompressionLevel::Best)
                .br(false)
                .gzip(false),
        )
            .into_layer(service_fn(handle));

        let request = Request::builder()
            .header(ACCEPT_ENCODING, "gzip")
            .body(Body::empty())?;

        let response = service.serve(request).await?;

        assert!(!response.headers().contains_key("content-encoding"));

        let body = response.into_body();
        let bytes = body.collect().await.unwrap().to_bytes();

        assert!(find_subsequence(bytes.as_slice(), b"rama-http").is_some());

        Ok(())
    }

    #[tokio::test]
    async fn compress_adapter_decompression_and_recompression()
    -> Result<(), rama_core::error::BoxError> {
        let service = (
            CompressAdaptLayer::default(),
            SetResponseHeaderLayer::overriding(ACCEPT_ENCODING, HeaderValue::from_static("gzip")),
            CompressionLayer::new()
                .quality(CompressionLevel::Best)
                .br(false),
        )
            .into_layer(service_fn(handle));

        let request = Request::builder()
            .header(ACCEPT_ENCODING, "deflate")
            .body(Body::empty())?;

        let response = service.serve(request).await?;

        assert_eq!(response.headers()["content-encoding"], "deflate");

        let body = response.into_body();
        let bytes = body.collect().await.unwrap().to_bytes();

        assert!(find_subsequence(bytes.as_slice(), b"rama-http").is_none());

        Ok(())
    }

    #[tokio::test]
    async fn compress_adapter_decompression_only() -> Result<(), rama_core::error::BoxError> {
        let service = (
            CompressAdaptLayer::default(),
            SetResponseHeaderLayer::overriding(ACCEPT_ENCODING, HeaderValue::from_static("gzip")),
            CompressionLayer::new()
                .quality(CompressionLevel::Best)
                .br(false),
        )
            .into_layer(service_fn(handle));

        let request = Request::builder().body(Body::empty())?;

        let response = service.serve(request).await?;

        assert!(!response.headers().contains_key("content-encoding"));

        let body = response.into_body();
        let bytes = body.collect().await.unwrap().to_bytes();

        assert!(find_subsequence(bytes.as_slice(), b"rama-http").is_some());

        Ok(())
    }

    fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack
            .windows(needle.len())
            .position(|window| window == needle)
    }
}
