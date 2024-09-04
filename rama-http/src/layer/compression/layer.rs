use super::predicate::DefaultPredicate;
use super::{Compression, Predicate};
use crate::layer::util::compression::{AcceptEncoding, CompressionLevel};
use rama_core::Layer;

/// Compress response bodies of the underlying service.
///
/// This uses the `Accept-Encoding` header to pick an appropriate encoding and adds the
/// `Content-Encoding` header to responses.
///
/// See the [module docs](crate::layer::compression) for more details.
#[derive(Clone, Debug, Default)]
pub struct CompressionLayer<P = DefaultPredicate> {
    accept: AcceptEncoding,
    predicate: P,
    quality: CompressionLevel,
}

impl<S, P> Layer<S> for CompressionLayer<P>
where
    P: Predicate,
{
    type Service = Compression<S, P>;

    fn layer(&self, inner: S) -> Self::Service {
        Compression {
            inner,
            accept: self.accept,
            predicate: self.predicate.clone(),
            quality: self.quality,
        }
    }
}

impl CompressionLayer {
    /// Creates a new [`CompressionLayer`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets whether to enable the gzip encoding.
    pub fn gzip(mut self, enable: bool) -> Self {
        self.accept.set_gzip(enable);
        self
    }

    /// Sets whether to enable the gzip encoding.
    pub fn set_gzip(&mut self, enable: bool) -> &mut Self {
        self.accept.set_gzip(enable);
        self
    }

    /// Sets whether to enable the Deflate encoding.
    pub fn deflate(mut self, enable: bool) -> Self {
        self.accept.set_deflate(enable);
        self
    }

    /// Sets whether to enable the Deflate encoding.
    pub fn set_deflate(&mut self, enable: bool) -> &mut Self {
        self.accept.set_deflate(enable);
        self
    }

    /// Sets whether to enable the Brotli encoding.
    pub fn br(mut self, enable: bool) -> Self {
        self.accept.set_br(enable);
        self
    }

    /// Sets whether to enable the Brotli encoding.
    pub fn set_br(&mut self, enable: bool) -> &mut Self {
        self.accept.set_br(enable);
        self
    }

    /// Sets whether to enable the Zstd encoding.
    pub fn zstd(mut self, enable: bool) -> Self {
        self.accept.set_zstd(enable);
        self
    }

    /// Sets whether to enable the Zstd encoding.
    pub fn set_zstd(&mut self, enable: bool) -> &mut Self {
        self.accept.set_zstd(enable);
        self
    }

    /// Sets the compression quality.
    pub fn quality(mut self, quality: CompressionLevel) -> Self {
        self.quality = quality;
        self
    }

    /// Sets the compression quality.
    pub fn set_quality(&mut self, quality: CompressionLevel) -> &mut Self {
        self.quality = quality;
        self
    }

    /// Replace the current compression predicate.
    ///
    /// See [`Compression::compress_when`] for more details.
    pub fn compress_when<C>(self, predicate: C) -> CompressionLayer<C>
    where
        C: Predicate,
    {
        CompressionLayer {
            accept: self.accept,
            predicate,
            quality: self.quality,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::dep::http_body_util::BodyExt;
    use crate::{header::ACCEPT_ENCODING, Body, Request, Response};
    use rama_core::service::service_fn;
    use rama_core::{Context, Service};
    use std::convert::Infallible;
    use tokio::fs::File;
    use tokio_util::io::ReaderStream;

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
    async fn accept_encoding_configuration_works() -> Result<(), rama_core::error::BoxError> {
        let deflate_only_layer = CompressionLayer::new()
            .quality(CompressionLevel::Best)
            .br(false)
            .gzip(false);

        // Compress responses based on the `Accept-Encoding` header.
        let service = deflate_only_layer.layer(service_fn(handle));

        // Call the service with the deflate only layer
        let request = Request::builder()
            .header(ACCEPT_ENCODING, "gzip, deflate, br")
            .body(Body::empty())?;

        let response = service.serve(Context::default(), request).await?;

        assert_eq!(response.headers()["content-encoding"], "deflate");

        // Read the body
        let body = response.into_body();
        let bytes = body.collect().await.unwrap().to_bytes();

        let deflate_bytes_len = bytes.len();

        let br_only_layer = CompressionLayer::new()
            .quality(CompressionLevel::Best)
            .gzip(false)
            .deflate(false);

        // Compress responses based on the `Accept-Encoding` header.
        let service = br_only_layer.layer(service_fn(handle));

        // Call the service with the br only layer
        let request = Request::builder()
            .header(ACCEPT_ENCODING, "gzip, deflate, br")
            .body(Body::empty())?;

        let response = service.serve(Context::default(), request).await?;

        assert_eq!(response.headers()["content-encoding"], "br");

        // Read the body
        let body = response.into_body();
        let bytes = body.collect().await.unwrap().to_bytes();

        let br_byte_length = bytes.len();

        // check the corresponding algorithms are actually used
        // br should compresses better than deflate
        assert!(br_byte_length < deflate_bytes_len);

        Ok(())
    }
}
