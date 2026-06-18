#![expect(
    clippy::allow_attributes,
    reason = "macro-generated `#[allow]` attributes whose underlying lints fire only for some expansions"
)]

use super::CompressionBody;
use super::CompressionLevel;
use super::body::BodyInner;
use super::predicate::{DefaultPredicate, Predicate, PreferredEncoding};
use crate::headers::encoding::{
    AcceptEncoding, Encoding, maybe_preferred_encoding_with_wildcard,
    parse_accept_encoding_headers, parse_accept_encoding_wildcard_quality,
};
use crate::layer::remove_header::remove_payload_metadata_headers;
use crate::layer::util::compression::WrapBody;
use crate::{Request, Response, StatusCode, header};
use rama_core::Service;
use rama_core::extensions::ExtensionsRef;
use rama_http_headers::specifier::{Quality, QualityValue};
use rama_http_types::HeaderValue;
use rama_http_types::Method;
use rama_http_types::StreamingBody;
use rama_utils::collections::smallvec::SmallVec;
use rama_utils::macros::define_inner_service_accessors;
use rama_utils::str::submatch_ignore_ascii_case;

/// Compress response bodies of the underlying service.
///
/// This uses the `Accept-Encoding` header to pick an appropriate encoding and adds the
/// `Content-Encoding` header to responses.
///
/// See the [module docs](crate::layer::compression) for more details.
#[derive(Debug, Clone)]
pub struct Compression<S, P = DefaultPredicate> {
    pub(crate) inner: S,
    pub(crate) accept: AcceptEncoding,
    pub(crate) predicate: P,
    pub(crate) respect_content_encoding_if_possible: bool,
    pub(crate) quality: CompressionLevel,
    pub(crate) enforce_not_acceptable: bool,
}

impl<S> Compression<S, DefaultPredicate> {
    /// Creates a new `Compression` wrapping the `service`.
    pub fn new(service: S) -> Self {
        Self {
            inner: service,
            accept: AcceptEncoding::default(),
            predicate: DefaultPredicate::default(),
            respect_content_encoding_if_possible: false,
            quality: CompressionLevel::default(),
            enforce_not_acceptable: true,
        }
    }
}

impl<S, P> Compression<S, P> {
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
        /// Sets the compression quality.
        pub fn quality(mut self, quality: CompressionLevel) -> Self {
            self.quality = quality;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Allow responses with content-encoding.
        ///
        /// Useful in case your stack uses that response header as preference.
        /// Not something you want for regular servers or proxies however,
        /// or most use cases for that matter.
        pub fn respect_content_encoding_if_possible(mut self) -> Self {
            self.respect_content_encoding_if_possible = true;
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

    /// Replace the current compression predicate.
    ///
    /// Predicates are used to determine whether a response should be compressed or not.
    ///
    /// The default predicate is [`DefaultPredicate`]. See its documentation for more
    /// details on which responses it wont compress.
    ///
    /// # Changing the compression predicate
    ///
    /// ```
    /// use rama_utils::str::arcstr::arcstr;
    /// use rama_http::layer::compression::{
    ///     Compression,
    ///     predicate::{Predicate, NotForContentType, DefaultPredicate},
    /// };
    /// use rama_core::service::service_fn;
    ///
    /// // Placeholder service_fn
    /// let service = service_fn(async |_: ()| {
    ///     Ok::<_, std::io::Error>(rama_http::Response::new(()))
    /// });
    ///
    /// // build our custom compression predicate
    /// // its recommended to still include `DefaultPredicate` as part of
    /// // custom predicates
    /// let predicate = DefaultPredicate::new()
    ///     // don't compress responses who's `content-type` starts with `application/json`
    ///     .and(NotForContentType::new(arcstr!("application/json")));
    ///
    /// let service = Compression::new(service).with_compress_predicate(predicate);
    /// ```
    ///
    /// See [`predicate`](super::predicate) for more utilities for building compression predicates.
    ///
    /// Responses that are already compressed (ie have a `content-encoding` header) will _never_ be
    /// recompressed, regardless what they predicate says.
    #[must_use]
    pub fn with_compress_predicate<C>(self, predicate: C) -> Compression<S, C>
    where
        C: Predicate,
    {
        Compression {
            inner: self.inner,
            accept: self.accept,
            predicate,
            respect_content_encoding_if_possible: self.respect_content_encoding_if_possible,
            quality: self.quality,
            enforce_not_acceptable: self.enforce_not_acceptable,
        }
    }
}

impl<ReqBody, ResBody, S, P> Service<Request<ReqBody>> for Compression<S, P>
where
    S: Service<Request<ReqBody>, Output = Response<ResBody>>,
    ResBody: StreamingBody<Data: Send + 'static, Error: Send + 'static> + Send + 'static,
    P: Predicate + Send + Sync + 'static,
    ReqBody: Send + 'static,
{
    type Output = Response<CompressionBody<ResBody>>;
    type Error = S::Error;

    #[allow(unreachable_code, unused_mut, unused_variables, unreachable_patterns)]
    async fn serve(&self, req: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        let accepted_encodings: SmallVec<[QualityValue<Encoding>; 4]> =
            parse_accept_encoding_headers(req.headers(), self.accept).collect();
        let wildcard_quality = parse_accept_encoding_wildcard_quality(req.headers());
        let req_method = req.method().clone();

        let mut res = self.inner.serve(req).await?;
        let mut respected_encoding = None;

        // RFC 9110 §9.3.2 (HEAD) / §9.3.6 (CONNECT) and the body-prohibiting status codes
        // (1xx Informational, 204 No Content, 205 Reset Content, 304 Not Modified) mean there
        // is no representation body to encode (or to reject for the client).
        let body_allowed = !matches!(req_method, Method::HEAD | Method::CONNECT)
            && !matches!(res.status().as_u16(), 100..=199 | 204 | 205 | 304);

        let should_compress = body_allowed &&
            //never compress responses that are ranges
            !res.headers().contains_key(header::CONTENT_RANGE) &&
            self.predicate.should_compress(&mut res) &&
            if self.respect_content_encoding_if_possible {
                respected_encoding = Encoding::maybe_from_content_encoding_header(res.headers(), self.accept);
                true
            } else {
                // unless requested do not recompress responses that are already compressed
                !res.headers().contains_key(header::CONTENT_ENCODING)
            };

        let negotiated = negotiate_response_encoding(
            &accepted_encodings,
            wildcard_quality,
            self.accept,
            respected_encoding,
            res.extensions().get_ref::<PreferredEncoding>().copied(),
        );

        // RFC 9110 §12.5.3: when the client's `Accept-Encoding` rejects every available
        // representation (e.g. `*;q=0` or a lone `identity;q=0`), respond 406 Not Acceptable.
        // This can be opted out of, in which case we fall back to an identity response.
        let selected_encoding = match negotiated {
            Some(encoding) => encoding,
            None if self.enforce_not_acceptable && body_allowed => {
                let (mut parts, body) = res.into_parts();
                parts.status = StatusCode::NOT_ACCEPTABLE;
                ensure_vary_accept_encoding(&mut parts.headers);
                return Ok(Response::from_parts(
                    parts,
                    CompressionBody::new(BodyInner::identity(body)),
                ));
            }
            None => Encoding::Identity,
        };

        let (mut parts, body) = res.into_parts();

        if should_compress {
            ensure_vary_accept_encoding(&mut parts.headers);
        }

        let body = match (should_compress, selected_encoding) {
            // if compression is _not_ supported or the client doesn't accept it
            (false, _) | (_, Encoding::Identity) => {
                return Ok(Response::from_parts(
                    parts,
                    CompressionBody::new(BodyInner::identity(body)),
                ));
            }

            (_, Encoding::Gzip) => {
                CompressionBody::new(BodyInner::gzip(WrapBody::new(body, self.quality)))
            }
            (_, Encoding::Deflate) => {
                CompressionBody::new(BodyInner::deflate(WrapBody::new(body, self.quality)))
            }
            (_, Encoding::Brotli) => {
                CompressionBody::new(BodyInner::brotli(WrapBody::new(body, self.quality)))
            }
            (_, Encoding::Zstd) => {
                CompressionBody::new(BodyInner::zstd(WrapBody::new(body, self.quality)))
            }
            #[allow(unreachable_patterns)]
            (true, _) => {
                // This should never happen because the `AcceptEncoding` struct which is used to determine
                // `self.encoding` will only enable the different compression algorithms if the
                // corresponding crate feature has been enabled. This means
                // Encoding::[Gzip|Brotli|Deflate] should be impossible at this point without the
                // features enabled.
                //
                // The match arm is still required though because the `fs` feature uses the
                // Encoding struct independently and requires no compression logic to be enabled.
                // This means a combination of an individual compression feature and `fs` will fail
                // to compile without this branch even though it will never be reached.
                //
                // To safeguard against refactors that changes this relationship or other bugs the
                // server will return an uncompressed response instead of panicking since that could
                // become a ddos attack vector.
                return Ok(Response::from_parts(
                    parts,
                    CompressionBody::new(BodyInner::identity(body)),
                ));
            }
        };

        remove_payload_metadata_headers(&mut parts.headers);

        parts.headers.insert(
            header::CONTENT_ENCODING,
            HeaderValue::from(selected_encoding),
        );

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
    respected: Option<Encoding>,
    preferred: Option<PreferredEncoding>,
) -> Option<Encoding> {
    if let Some(respected) = respected
        && accepted_encodings
            .iter()
            .any(|qval| qval.value == respected && qval.quality.as_u16() > 0)
    {
        return Some(respected);
    }

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
fn ensure_vary_accept_encoding(headers: &mut rama_http_types::HeaderMap) {
    if !headers.get_all(header::VARY).iter().any(|value| {
        submatch_ignore_ascii_case(
            value.as_bytes(),
            header::ACCEPT_ENCODING.as_str().as_bytes(),
        )
    }) {
        headers.append(header::VARY, header::ACCEPT_ENCODING.into());
    }
}
