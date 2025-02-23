use super::Decompression;
use rama_core::Layer;
use rama_http_types::headers::encoding::AcceptEncoding;

/// Decompresses response bodies of the underlying service.
///
/// This adds the `Accept-Encoding` header to requests and transparently decompresses response
/// bodies based on the `Content-Encoding` header.
///
/// See the [module docs](crate::layer::decompression) for more details.
#[derive(Debug, Default, Clone)]
pub struct DecompressionLayer {
    accept: AcceptEncoding,
    only_if_requested: bool,
}

impl<S> Layer<S> for DecompressionLayer {
    type Service = Decompression<S>;

    fn layer(&self, service: S) -> Self::Service {
        Decompression {
            inner: service,
            accept: self.accept,
            only_if_requested: self.only_if_requested,
        }
    }
}

impl DecompressionLayer {
    /// Creates a new `DecompressionLayer`.
    pub fn new() -> Self {
        Default::default()
    }

    /// Sets whether to request the gzip encoding.
    pub fn gzip(mut self, enable: bool) -> Self {
        self.accept.set_gzip(enable);
        self
    }

    /// Sets whether to request the gzip encoding.
    pub fn set_gzip(&mut self, enable: bool) -> &mut Self {
        self.accept.set_gzip(enable);
        self
    }

    /// Sets whether to request the Deflate encoding.
    pub fn deflate(mut self, enable: bool) -> Self {
        self.accept.set_deflate(enable);
        self
    }

    /// Sets whether to request the Deflate encoding.
    pub fn set_deflate(&mut self, enable: bool) -> &mut Self {
        self.accept.set_deflate(enable);
        self
    }

    /// Sets whether to request the Brotli encoding.
    pub fn br(mut self, enable: bool) -> Self {
        self.accept.set_br(enable);
        self
    }

    /// Sets whether to request the Brotli encoding.
    pub fn set_br(&mut self, enable: bool) -> &mut Self {
        self.accept.set_br(enable);
        self
    }

    /// Sets whether to request the Zstd encoding.
    pub fn zstd(mut self, enable: bool) -> Self {
        self.accept.set_zstd(enable);
        self
    }

    /// Sets whether to request the Zstd encoding.
    pub fn set_zstd(&mut self, enable: bool) -> &mut Self {
        self.accept.set_zstd(enable);
        self
    }

    /// Sets whether to only decompress bodies if it is requested
    /// via the response extension or request context.
    ///
    /// A request is made using the [`rama_http_types::compression::DecompressIfPossible`] marker type.
    pub fn only_if_requested(mut self, enable: bool) -> Self {
        self.only_if_requested = enable;
        self
    }

    /// Sets whether to only decompress bodies if it is requested
    /// via the response extension or request context.
    ///
    /// A request is made using the [`rama_http_types::compression::DecompressIfPossible`] marker type.
    pub fn set_only_if_requested(&mut self, enable: bool) -> &mut Self {
        self.only_if_requested = enable;
        self
    }
}
