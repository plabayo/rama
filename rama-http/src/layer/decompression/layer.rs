use super::{Decompression, service::DefaultDecompressionMatcher};
use crate::headers::encoding::AcceptEncoding;
use rama_core::Layer;

/// Decompresses response bodies of the underlying service.
///
/// This adds the `Accept-Encoding` header to requests and transparently decompresses response
/// bodies based on the `Content-Encoding` header.
///
/// See the [module docs](crate::layer::decompression) for more details.
#[derive(Debug, Clone)]
pub struct DecompressionLayer<M = DefaultDecompressionMatcher> {
    accept: AcceptEncoding,
    insert_accept_encoding_header: bool,
    matcher: M,
}

impl<M: Default> Default for DecompressionLayer<M> {
    fn default() -> Self {
        Self {
            accept: Default::default(),
            insert_accept_encoding_header: true,
            matcher: Default::default(),
        }
    }
}

impl<S, M> Layer<S> for DecompressionLayer<M>
where
    M: Clone,
{
    type Service = Decompression<S, M>;

    fn layer(&self, service: S) -> Self::Service {
        Decompression {
            inner: service,
            accept: self.accept,
            insert_accept_encoding_header: self.insert_accept_encoding_header,
            matcher: self.matcher.clone(),
        }
    }
}

impl DecompressionLayer {
    /// Creates a new `DecompressionLayer`.
    #[must_use]
    pub fn new() -> Self {
        Default::default()
    }
}

impl<M> DecompressionLayer<M> {
    rama_utils::macros::generate_set_and_with! {
        /// Sets whether the layer inserts `Accept-Encoding` into requests when it is absent.
        ///
        /// By default it is `true`.
        pub fn insert_accept_encoding_header(mut self, insert: bool) -> Self {
            self.insert_accept_encoding_header = insert;
            self
        }
    }

    /// Replaces the request/response decompression matcher.
    ///
    /// The default matcher [`DefaultDecompressionMatcher`]
    /// matches any response which has a response payload to be decompressed.
    pub fn with_matcher<T>(self, matcher: T) -> DecompressionLayer<T> {
        DecompressionLayer {
            accept: self.accept,
            insert_accept_encoding_header: self.insert_accept_encoding_header,
            matcher,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Sets whether to request the gzip encoding.
        pub fn gzip(mut self, enable: bool) -> Self {
            self.accept.set_gzip(enable);
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Sets whether to request the Deflate encoding.
        pub fn deflate(mut self, enable: bool) -> Self {
            self.accept.set_deflate(enable);
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Sets whether to request the Brotli encoding.
        pub fn br(mut self, enable: bool) -> Self {
            self.accept.set_br(enable);
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Sets whether to request the Zstd encoding.
        pub fn zstd(mut self, enable: bool) -> Self {
            self.accept.set_zstd(enable);
            self
        }
    }
}
