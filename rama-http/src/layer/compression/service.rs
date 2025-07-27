use super::CompressionBody;
use super::CompressionLevel;
use super::body::BodyInner;
use super::predicate::{DefaultPredicate, Predicate};
use crate::dep::http_body::Body;
use crate::headers::encoding::{AcceptEncoding, Encoding};
use crate::layer::util::compression::WrapBody;
use crate::{Request, Response, header};
use rama_core::{Context, Service};
use rama_http_types::HeaderValue;
use rama_utils::macros::define_inner_service_accessors;
use rama_utils::str::submatch_ignore_ascii_case;

/// Compress response bodies of the underlying service.
///
/// This uses the `Accept-Encoding` header to pick an appropriate encoding and adds the
/// `Content-Encoding` header to responses.
///
/// See the [module docs](crate::layer::compression) for more details.
pub struct Compression<S, P = DefaultPredicate> {
    pub(crate) inner: S,
    pub(crate) accept: AcceptEncoding,
    pub(crate) predicate: P,
    pub(crate) quality: CompressionLevel,
}

impl<S, P> std::fmt::Debug for Compression<S, P>
where
    S: std::fmt::Debug,
    P: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Compression")
            .field("inner", &self.inner)
            .field("accept", &self.accept)
            .field("predicate", &self.predicate)
            .field("quality", &self.quality)
            .finish()
    }
}

impl<S, P> Clone for Compression<S, P>
where
    S: Clone,
    P: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            accept: self.accept,
            predicate: self.predicate.clone(),
            quality: self.quality,
        }
    }
}

impl<S> Compression<S, DefaultPredicate> {
    /// Creates a new `Compression` wrapping the `service`.
    pub fn new(service: S) -> Self {
        Self {
            inner: service,
            accept: AcceptEncoding::default(),
            predicate: DefaultPredicate::default(),
            quality: CompressionLevel::default(),
        }
    }
}

impl<S, P> Compression<S, P> {
    define_inner_service_accessors!();

    /// Sets whether to enable the gzip encoding.
    #[must_use]
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
    #[must_use]
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
    #[must_use]
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
    #[must_use]
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
    ///     .and(NotForContentType::new("application/json"));
    ///
    /// let service = Compression::new(service).compress_when(predicate);
    /// ```
    ///
    /// See [`predicate`](super::predicate) for more utilities for building compression predicates.
    ///
    /// Responses that are already compressed (ie have a `content-encoding` header) will _never_ be
    /// recompressed, regardless what they predicate says.
    #[must_use]
    pub fn compress_when<C>(self, predicate: C) -> Compression<S, C>
    where
        C: Predicate,
    {
        Compression {
            inner: self.inner,
            accept: self.accept,
            predicate,
            quality: self.quality,
        }
    }
}

impl<ReqBody, ResBody, S, P, State> Service<State, Request<ReqBody>> for Compression<S, P>
where
    S: Service<State, Request<ReqBody>, Response = Response<ResBody>>,
    ResBody: Body<Data: Send + 'static, Error: Send + 'static> + Send + 'static,
    P: Predicate + Send + Sync + 'static,
    ReqBody: Send + 'static,
    State: Clone + Send + Sync + 'static,
{
    type Response = Response<CompressionBody<ResBody>>;
    type Error = S::Error;

    #[allow(unreachable_code, unused_mut, unused_variables, unreachable_patterns)]
    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request<ReqBody>,
    ) -> Result<Self::Response, Self::Error> {
        let encoding = Encoding::from_accept_encoding_headers(req.headers(), self.accept);

        let res = self.inner.serve(ctx, req).await?;

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

        let body = match (should_compress, encoding) {
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

        parts.headers.remove(header::ACCEPT_RANGES);
        parts.headers.remove(header::CONTENT_LENGTH);

        parts
            .headers
            .insert(header::CONTENT_ENCODING, HeaderValue::from(encoding));

        let res = Response::from_parts(parts, body);
        Ok(res)
    }
}
