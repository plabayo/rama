#![expect(
    clippy::allow_attributes,
    reason = "macro-generated `#[allow]` attributes whose underlying lints fire only for some expansions"
)]

use super::CompressionLevel;
use super::body::StreamCompressionBody;
use crate::HeaderValue;
use crate::StreamingBody;
use crate::headers::encoding::{
    AcceptEncoding, Encoding, maybe_preferred_encoding_with_wildcard,
    parse_accept_encoding_headers, parse_accept_encoding_wildcard_quality,
};
use crate::layer::compression::predicate::{DefaultStreamPredicate, Predicate, PreferredEncoding};
use crate::layer::remove_header::remove_payload_metadata_headers;
use crate::{Request, Response, StatusCode, header};
use rama_core::Service;
use rama_core::extensions::ExtensionsRef;
use rama_core::telemetry::tracing;
use rama_http_headers::HeaderMapExt;
use rama_http_headers::TransferEncoding;
use rama_http_headers::specifier::{Quality, QualityValue};
use rama_http_types::Method;
use rama_utils::collections::smallvec::SmallVec;
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
    pub(crate) enforce_not_acceptable: bool,
}

impl<S> StreamCompression<S, DefaultStreamPredicate> {
    /// Creates a new `StreamCompression` wrapping the `service`.
    pub fn new(service: S) -> Self {
        Self {
            inner: service,
            accept: AcceptEncoding::default(),
            predicate: DefaultStreamPredicate::default(),
            quality: CompressionLevel::default(),
            enforce_not_acceptable: true,
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

    rama_utils::macros::generate_set_and_with! {
        /// Sets whether to respond with `406 Not Acceptable` when the client's
        /// `Accept-Encoding` header rejects every available representation
        /// (e.g. `*;q=0` or a lone `identity;q=0`), as recommended by RFC 9110 §12.5.3.
        ///
        /// Enabled by default. Disable to opt out and instead fall back to sending an
        /// uncompressed (identity) response regardless of the client's stated preference.
        pub fn enforce_not_acceptable(mut self, enable: bool) -> Self {
            self.enforce_not_acceptable = enable;
            self
        }
    }

    /// Replace the current StreamCompression predicate.
    ///
    /// Predicates are used to determine whether a response should be compressed or not.
    ///
    /// The default predicate is [`DefaultPredicate`]. See its documentation for more
    /// details on which responses it won't compress.
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
            enforce_not_acceptable: self.enforce_not_acceptable,
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
        let accepted_encodings: SmallVec<[QualityValue<Encoding>; 4]> =
            parse_accept_encoding_headers(req.headers(), self.accept).collect();
        let wildcard_quality = parse_accept_encoding_wildcard_quality(req.headers());
        let req_method = req.method().clone();

        let mut res = self.inner.serve(req).await?;

        // RFC 9110 §9.3.2 (HEAD) / §9.3.6 (CONNECT) and the body-prohibiting status codes
        // (1xx Informational, 204 No Content, 205 Reset Content, 304 Not Modified) mean there
        // is no representation body to encode (or to reject for the client).
        let body_allowed = !matches!(req_method, Method::HEAD | Method::CONNECT)
            && !matches!(res.status().as_u16(), 100..=199 | 204 | 205 | 304);

        let should_compress = body_allowed
            // never recompress responses that are already compressed
            && !res.headers().contains_key(header::CONTENT_ENCODING)
            // never compress responses that are ranges
            && !res.headers().contains_key(header::CONTENT_RANGE)
            && self.predicate.should_compress(&mut res);

        let negotiated = negotiate_response_encoding(
            &accepted_encodings,
            wildcard_quality,
            self.accept,
            res.extensions().get_ref::<PreferredEncoding>().copied(),
        );

        // RFC 9110 §12.5.3: when the client's `Accept-Encoding` rejects every available
        // representation (e.g. `*;q=0` or a lone `identity;q=0`), respond 406 Not Acceptable.
        // This can be opted out of, in which case we fall back to an identity response.
        let encoding = match negotiated {
            Some(encoding) => encoding,
            None if self.enforce_not_acceptable && body_allowed => {
                let (mut parts, body) = res.into_parts();
                parts.status = StatusCode::NOT_ACCEPTABLE;
                ensure_vary_accept_encoding(&mut parts.headers);
                return Ok(Response::from_parts(
                    parts,
                    StreamCompressionBody::identity(body),
                ));
            }
            None => Encoding::Identity,
        };

        let (mut parts, body) = res.into_parts();

        if should_compress {
            ensure_vary_accept_encoding(&mut parts.headers);
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

        remove_payload_metadata_headers(&mut parts.headers);

        parts
            .headers
            .insert(header::CONTENT_ENCODING, HeaderValue::from(encoding));

        let res = Response::from_parts(parts, body);
        Ok(res)
    }
}

/// Picks the response encoding, returning `None` when the client's `Accept-Encoding` rejects
/// every available representation (406 Not Acceptable per RFC 9110 §12.5.3).
fn negotiate_response_encoding(
    accepted_encodings: &[QualityValue<Encoding>],
    wildcard_quality: Option<Quality>,
    supported: AcceptEncoding,
    preferred: Option<PreferredEncoding>,
) -> Option<Encoding> {
    if let Some(preferred) = preferred.map(PreferredEncoding::as_encoding)
        && accepted_encodings
            .iter()
            .any(|qval| qval.value == preferred && qval.quality.as_u16() > 0)
    {
        return Some(preferred);
    }

    maybe_preferred_encoding_with_wildcard(accepted_encodings, wildcard_quality, supported)
}

/// Appends `Vary: accept-encoding` unless an equivalent value is already present.
fn ensure_vary_accept_encoding(headers: &mut header::HeaderMap) {
    if !headers.get_all(header::VARY).iter().any(|value| {
        submatch_ignore_ascii_case(
            value.as_bytes(),
            header::ACCEPT_ENCODING.as_str().as_bytes(),
        )
    }) {
        headers.append(header::VARY, header::ACCEPT_ENCODING.into());
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
