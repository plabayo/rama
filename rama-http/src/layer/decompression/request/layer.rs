use super::service::RequestDecompression;
use crate::headers::encoding::AcceptEncoding;
use rama_core::Layer;

/// Decompresses request bodies and calls its underlying service.
///
/// Transparently decompresses request bodies based on the `Content-Encoding` header.
/// When the encoding in the `Content-Encoding` header is not accepted an `Unsupported Media Type`
/// status code will be returned with the accepted encodings in the `Accept-Encoding` header.
///
/// Enabling pass-through of unaccepted encodings will not return an `Unsupported Media Type`. But
/// will call the underlying service with the unmodified request if the encoding is not supported.
/// This is disabled by default.
///
/// See the [module docs](crate::layer::decompression) for more details.
#[derive(Debug, Default, Clone)]
pub struct RequestDecompressionLayer {
    accept: AcceptEncoding,
    pass_through_unaccepted: bool,
}

impl<S> Layer<S> for RequestDecompressionLayer {
    type Service = RequestDecompression<S>;

    fn layer(&self, service: S) -> Self::Service {
        RequestDecompression {
            inner: service,
            accept: self.accept,
            pass_through_unaccepted: self.pass_through_unaccepted,
        }
    }
}

impl RequestDecompressionLayer {
    /// Creates a new `RequestDecompressionLayer`.
    #[must_use]
    pub fn new() -> Self {
        Default::default()
    }

    rama_utils::macros::generate_set_and_with! {
        /// Sets whether to support gzip encoding.
        pub fn gzip(mut self, enable: bool) -> Self {
            self.accept.set_gzip(enable);
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Sets whether to support Deflate encoding.
        pub fn deflate(mut self, enable: bool) -> Self {
            self.accept.set_deflate(enable);
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Sets whether to support Brotli encoding.
        pub fn br(mut self, enable: bool) -> Self {
            self.accept.set_br(enable);
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Sets whether to support Zstd encoding.
        pub fn zstd(mut self, enable: bool) -> Self {
            self.accept.set_zstd(enable);
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Sets whether to pass through the request even when the encoding is not supported.
        pub fn pass_through_unaccepted(mut self, enable: bool) -> Self {
            self.pass_through_unaccepted = enable;
            self
        }
    }
}
