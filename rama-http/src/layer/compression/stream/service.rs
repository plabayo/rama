use super::CompressionLevel;
use super::body::StreamCompressionBody;
use crate::HeaderValue;
use crate::StreamingBody;
use crate::headers::encoding::{AcceptEncoding, Encoding};
use crate::layer::compression::predicate::{DefaultStreamPredicate, Predicate};
use crate::{Request, Response, header};
use rama_core::Service;
use rama_core::telemetry::tracing;
use rama_http_headers::HeaderMapExt;
use rama_http_headers::TransferEncoding;
use rama_utils::macros::define_inner_service_accessors;
use rama_utils::str::submatch_ignore_ascii_case;

/// Compress response bodies of the underlying service.
///
/// This uses the `Accept-Encoding` header to pick an appropriate encoding and adds the
/// `Content-Encoding` header to responses.
///
/// See the [module docs](super::StreamCompression) for more details.
#[derive(Debug, Clone)]
pub struct StreamCompression<S, P = DefaultStreamPredicate> {
    pub(crate) inner: S,
    pub(crate) accept: AcceptEncoding,
    pub(crate) predicate: P,
    pub(crate) quality: CompressionLevel,
}

impl<S> StreamCompression<S, DefaultStreamPredicate> {
    /// Creates a new `StreamCompression` wrapping the `service`.
    pub fn new(service: S) -> Self {
        Self {
            inner: service,
            accept: AcceptEncoding::default(),
            predicate: DefaultStreamPredicate::default(),
            quality: CompressionLevel::default(),
        }
    }
}

impl<S, P> StreamCompression<S, P> {
    define_inner_service_accessors!();

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
        /// Sets the StreamCompression quality.
        pub fn quality(mut self, quality: CompressionLevel) -> Self {
            self.quality = quality;
            self
        }
    }

    /// Replace the current StreamCompression predicate.
    ///
    /// Predicates are used to determine whether a response should be compressed or not.
    ///
    /// The default predicate is [`DefaultPredicate`]. See its documentation for more
    /// details on which responses it wont compress.
    ///
    /// [`DefaultPredicate`]: crate::layer::compression::DefaultPredicate
    #[must_use]
    pub fn with_compress_predicate<C>(self, predicate: C) -> StreamCompression<S, C>
    where
        C: Predicate,
    {
        StreamCompression {
            inner: self.inner,
            accept: self.accept,
            predicate,
            quality: self.quality,
        }
    }
}

impl<ReqBody, ResBody, S, P> Service<Request<ReqBody>> for StreamCompression<S, P>
where
    S: Service<Request<ReqBody>, Output = Response<ResBody>>,
    ResBody: StreamingBody<Data: Send + 'static, Error: Send + 'static> + Send + 'static,
    P: Predicate + Send + Sync + 'static,
    ReqBody: Send + 'static,
{
    type Output = Response<StreamCompressionBody<ResBody>>;
    type Error = S::Error;

    #[allow(unreachable_code, unused_mut, unused_variables, unreachable_patterns)]
    async fn serve(&self, req: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        let encoding = Encoding::from_accept_encoding_headers(req.headers(), self.accept);

        let res = self.inner.serve(req).await?;

        // never recompress responses that are already compressed
        let should_compress = !res.headers().contains_key(header::CONTENT_ENCODING)
            // never compress responses that are ranges
            && !res.headers().contains_key(header::CONTENT_RANGE)
            && self.predicate.should_compress(&res);

        let (mut parts, body) = res.into_parts();

        if should_compress
            && !parts.headers.get_all(header::VARY).iter().any(|value| {
                submatch_ignore_ascii_case(
                    value.as_bytes(),
                    header::ACCEPT_ENCODING.as_str().as_bytes(),
                )
            })
        {
            parts
                .headers
                .append(header::VARY, header::ACCEPT_ENCODING.into());
        }

        let always_flush = parts
            .headers
            .get("x-accel-buffering")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.eq_ignore_ascii_case("no"))
            || is_streaming_content_type(&parts.headers)
            || is_chunked_encoding(&parts.headers);

        tracing::trace!(
            "should_compress = {should_compress}; always_flush = {always_flush}; encoding = {encoding}"
        );

        let body = match (should_compress, encoding) {
            // if StreamCompression is _not_ supported or the client doesn't accept it
            (false, _) | (_, Encoding::Identity) => {
                return Ok(Response::from_parts(
                    parts,
                    StreamCompressionBody::identity(body),
                ));
            }

            (true, Encoding::Gzip) => StreamCompressionBody::gzip(body, self.quality, always_flush),
            (true, Encoding::Deflate) => {
                StreamCompressionBody::deflate(body, self.quality, always_flush)
            }
            (true, Encoding::Brotli) => {
                StreamCompressionBody::brotli(body, self.quality, always_flush)
            }
            (true, Encoding::Zstd) => StreamCompressionBody::zstd(body, self.quality, always_flush),
        };

        parts.headers.remove(header::ACCEPT_RANGES);
        parts.headers.remove(header::CONTENT_LENGTH);

        parts
            .headers
            .insert(header::CONTENT_ENCODING, HeaderValue::from(encoding));

        let res = Response::from_parts(parts, body);
        Ok(res)
    }
}

fn is_streaming_content_type(headers: &header::HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("text/event-stream") || ct.starts_with("application/grpc"))
}

fn is_chunked_encoding(headers: &header::HeaderMap) -> bool {
    !headers.contains_key(header::CONTENT_LENGTH)
        || headers
            .typed_get::<TransferEncoding>()
            .map(|te| te.is_chunked())
            .unwrap_or_default()
}
