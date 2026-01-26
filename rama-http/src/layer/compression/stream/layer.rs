use super::StreamCompression;
use crate::headers::encoding::AcceptEncoding;
use crate::layer::compression::Predicate;
use crate::layer::compression::predicate::DefaultStreamPredicate;
use crate::layer::util::compression::CompressionLevel;
use rama_core::Layer;

/// Compress response bodies of the underlying service.
///
/// This uses the `Accept-Encoding` header to pick an appropriate encoding and adds the
/// `Content-Encoding` header to responses.
///
/// See the [module docs](crate::layer::compression) for more details.
#[derive(Clone, Debug, Default)]
pub struct StreamCompressionLayer<P = DefaultStreamPredicate> {
    accept: AcceptEncoding,
    predicate: P,
    quality: CompressionLevel,
}

impl<S, P> Layer<S> for StreamCompressionLayer<P>
where
    P: Predicate,
{
    type Service = StreamCompression<S, P>;

    fn layer(&self, inner: S) -> Self::Service {
        StreamCompression {
            inner,
            accept: self.accept,
            predicate: self.predicate.clone(),
            quality: self.quality,
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        StreamCompression {
            inner,
            accept: self.accept,
            predicate: self.predicate,
            quality: self.quality,
        }
    }
}

impl StreamCompressionLayer {
    /// Creates a new [`StreamCompressionLayer`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    rama_utils::macros::generate_set_and_with! {
        /// Sets whether to enable the gzip encoding.
        pub fn gzip(mut self, enable: bool) -> Self {
            self.accept.set_gzip(enable);
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Sets whether to enable the Deflate encoding.
        pub fn deflate(mut self, enable: bool) -> Self {
            self.accept.set_deflate(enable);
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Sets whether to enable the Brotli encoding.
        pub fn br(mut self, enable: bool) -> Self {
            self.accept.set_br(enable);
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Sets whether to enable the Zstd encoding.
        pub fn zstd(mut self, enable: bool) -> Self {
            self.accept.set_zstd(enable);
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Sets the compression quality.
        pub fn quality(mut self, quality: CompressionLevel) -> Self {
            self.quality = quality;
            self
        }
    }

    /// Replace the current compression predicate.
    pub fn with_compress_predicate<C>(self, predicate: C) -> StreamCompressionLayer<C>
    where
        C: Predicate,
    {
        StreamCompressionLayer {
            accept: self.accept,
            predicate,
            quality: self.quality,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{Request, Response, body::util::BodyExt, header::ACCEPT_ENCODING};
    use rama_core::Service;
    use rama_core::service::service_fn;
    use rama_core::stream::io::ReaderStream;
    use rama_http_types::Body;
    use std::convert::Infallible;
    use tokio::fs::File;

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
        let deflate_only_layer = StreamCompressionLayer::new()
            .with_quality(CompressionLevel::Best)
            .with_br(false)
            .with_gzip(false);

        // Compress responses based on the `Accept-Encoding` header.
        let service = deflate_only_layer.into_layer(service_fn(handle));

        // Call the service with the deflate only layer
        let request = Request::builder()
            .header(ACCEPT_ENCODING, "gzip, deflate, br")
            .body(Body::empty())?;

        let response = service.serve(request).await?;

        assert_eq!(response.headers()["content-encoding"], "deflate");

        // Read the body
        let body = response.into_body();
        let bytes = body.collect().await.unwrap().to_bytes();

        let deflate_bytes_len = bytes.len();

        let br_only_layer = StreamCompressionLayer::new()
            .with_quality(CompressionLevel::Best)
            .with_gzip(false)
            .with_deflate(false);

        // Compress responses based on the `Accept-Encoding` header.
        let service = br_only_layer.into_layer(service_fn(handle));

        // Call the service with the br only layer
        let request = Request::builder()
            .header(ACCEPT_ENCODING, "gzip, deflate, br")
            .body(Body::empty())?;

        let response = service.serve(request).await?;

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

    #[tokio::test]
    async fn zstd_is_web_safe() -> Result<(), rama_core::error::BoxError> {
        // Test ensuring that zstd compression will not exceed an 8MiB window size; browsers do not
        // accept responses using 16MiB+ window sizes.

        async fn zeroes(_req: Request<Body>) -> Result<Response<Body>, Infallible> {
            Ok(Response::new(Body::from(vec![0u8; 18_874_368])))
        }
        // zstd will (I believe) lower its window size if a larger one isn't beneficial and
        // it knows the size of the input; use an 18MiB body to ensure it would want a
        // >=16MiB window (though it might not be able to see the input size here).

        let zstd_layer = StreamCompressionLayer::new()
            .with_quality(CompressionLevel::Best)
            .with_br(false)
            .with_deflate(false)
            .with_gzip(false);

        let service = zstd_layer.into_layer(service_fn(zeroes));

        let request = Request::builder()
            .header(ACCEPT_ENCODING, "zstd")
            .body(Body::empty())?;

        let response = service.serve(request).await?;

        assert_eq!(response.headers()["content-encoding"], "zstd");

        let body = response.into_body();
        let bytes = body.collect().await?.to_bytes();
        let mut dec = zstd::Decoder::new(&*bytes)?;
        dec.window_log_max(23)?; // Limit window size accepted by decoder to 2 ^ 23 bytes (8MiB)

        std::io::copy(&mut dec, &mut std::io::sink())?;

        Ok(())
    }
}
