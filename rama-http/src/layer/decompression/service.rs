use super::{DecompressedFrom, DecompressionBody, body::BodyInner};
use crate::headers::encoding::{AcceptEncoding, SupportedEncodings};
use crate::layer::remove_header::remove_payload_metadata_headers;
use crate::layer::util::compression::{CompressionLevel, WrapBody};
use crate::{
    Request, Response, StreamingBody,
    header::{self, ACCEPT_ENCODING},
};
use rama_core::error::{BoxError, ErrorContext as _};
use rama_core::{
    Service,
    matcher::service::{ServiceMatch, ServiceMatcher},
};
use rama_utils::macros::define_inner_service_accessors;
use std::convert::Infallible;

/// Decompresses response bodies of the underlying service.
///
/// This adds the `Accept-Encoding` header to requests and transparently decompresses response
/// bodies based on the `Content-Encoding` header.
///
/// See the [module docs](crate::layer::decompression) for more details.
#[derive(Debug, Clone)]
pub struct Decompression<S, M = DefaultDecompressionMatcher> {
    pub(crate) inner: S,
    pub(crate) accept: AcceptEncoding,
    pub(crate) insert_accept_encoding_header: bool,
    pub(crate) matcher: M,
}

impl<S> Decompression<S> {
    /// Creates a new `Decompression` wrapping the `service`.
    pub fn new(service: S) -> Self {
        Self {
            inner: service,
            accept: AcceptEncoding::default(),
            insert_accept_encoding_header: true,
            matcher: DefaultDecompressionMatcher,
        }
    }
}

impl<S, M> Decompression<S, M> {
    define_inner_service_accessors!();

    rama_utils::macros::generate_set_and_with! {
        /// Sets whether the layer inserts `Accept-Encoding` into requests when it is absent.
        ///
        /// When disabled, the request header is forwarded as-is and the layer only advertises
        /// supported encodings if the request already contains an `Accept-Encoding` header.
        pub fn insert_accept_encoding_header(mut self, insert: bool) -> Self {
            self.insert_accept_encoding_header = insert;
            self
        }
    }

    /// Replaces the request/response decompression matcher.
    ///
    /// The matcher runs at request time and may select a second matcher to evaluate the response
    /// after the inner service returns. If no response matcher is selected or if the selected
    /// response matcher does not match, the response is left compressed even when Rama supports
    /// decompressing it.
    pub fn with_matcher<T>(self, matcher: T) -> Decompression<S, T> {
        Decompression {
            inner: self.inner,
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

#[derive(Debug, Clone, Copy, Default)]
/// Default request-time matcher for decompression.
///
/// It always enables a response-time decompression evaluation.
pub struct DefaultDecompressionMatcher;

#[derive(Debug, Clone, Copy, Default)]
/// Default response-time matcher for decompression.
///
/// It always allows response decompression when Rama supports the advertised encoding.
pub struct DefaultResponseDecompressionMatcher;

impl<ReqBody> ServiceMatcher<Request<ReqBody>> for DefaultDecompressionMatcher
where
    ReqBody: Send + 'static,
{
    type Service = DefaultResponseDecompressionMatcher;
    type Error = Infallible;
    type ModifiedInput = Request<ReqBody>;

    async fn match_service(
        &self,
        input: Request<ReqBody>,
    ) -> Result<ServiceMatch<Self::ModifiedInput, Self::Service>, Self::Error> {
        Ok(ServiceMatch {
            input,
            service: Some(DefaultResponseDecompressionMatcher),
        })
    }
}

impl<ResBody> ServiceMatcher<Response<ResBody>> for DefaultResponseDecompressionMatcher
where
    ResBody: Send + 'static,
{
    type Service = ();
    type Error = Infallible;
    type ModifiedInput = Response<ResBody>;

    async fn match_service(
        &self,
        input: Response<ResBody>,
    ) -> Result<ServiceMatch<Self::ModifiedInput, Self::Service>, Self::Error> {
        Ok(ServiceMatch {
            input,
            service: Some(()),
        })
    }
}

impl<S, M, ReqBody, ResBody> Service<Request<ReqBody>> for Decompression<S, M>
where
    S: Service<Request<ReqBody>, Output = Response<ResBody>, Error: Into<BoxError>>,
    M: ServiceMatcher<
            Request<ReqBody>,
            ModifiedInput = Request<ReqBody>,
            Service: ServiceMatcher<
                Response<ResBody>,
                ModifiedInput = Response<ResBody>,
                Service = (),
                Error: Into<BoxError>,
            >,
            Error: Into<BoxError>,
        >,
    ReqBody: Send + 'static,
    ResBody: StreamingBody<Data: Send + 'static, Error: Send + 'static> + Send + 'static,
{
    type Output = Response<DecompressionBody<ResBody>>;
    type Error = BoxError;

    async fn serve(&self, req: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        let ServiceMatch {
            input: mut req,
            service: maybe_response_matcher,
        } = self
            .matcher
            .match_service(req)
            .await
            .context("decompression matcher: request")?;

        if self.insert_accept_encoding_header
            && let header::Entry::Vacant(entry) = req.headers_mut().entry(ACCEPT_ENCODING)
            && let Some(accept) = self.accept.maybe_to_header_value()
        {
            entry.insert(accept);
        }

        let res = self.inner.serve(req).await.context("inner::serve")?;

        let ServiceMatch {
            input: res,
            service: should_decompress,
        } = if let Some(response_matcher) = maybe_response_matcher {
            response_matcher
                .into_match_service(res)
                .await
                .context("decompression matcher: response")?
        } else {
            ServiceMatch {
                input: res,
                service: None,
            }
        };

        let (mut parts, body) = res.into_parts();

        let res = if should_decompress.is_some()
            && let header::Entry::Occupied(entry) = parts.headers.entry(header::CONTENT_ENCODING)
        {
            let maybe_marker = match entry.get().as_bytes() {
                b"gzip" if self.accept.gzip() => Some(DecompressedFrom::Gzip),
                b"deflate" if self.accept.deflate() => Some(DecompressedFrom::Deflate),
                b"br" if self.accept.br() => Some(DecompressedFrom::Brotli),
                b"zstd" if self.accept.zstd() => Some(DecompressedFrom::Zstd),
                _ => None,
            };

            let Some(marker) = maybe_marker else {
                return Ok(Response::from_parts(
                    parts,
                    DecompressionBody::new(BodyInner::identity(body)),
                ));
            };

            let body =
                match marker {
                    DecompressedFrom::Gzip => DecompressionBody::new(BodyInner::gzip(
                        WrapBody::new(body, CompressionLevel::default()),
                    )),
                    DecompressedFrom::Deflate => DecompressionBody::new(BodyInner::deflate(
                        WrapBody::new(body, CompressionLevel::default()),
                    )),
                    DecompressedFrom::Brotli => DecompressionBody::new(BodyInner::brotli(
                        WrapBody::new(body, CompressionLevel::default()),
                    )),
                    DecompressedFrom::Zstd => DecompressionBody::new(BodyInner::zstd(
                        WrapBody::new(body, CompressionLevel::default()),
                    )),
                };

            entry.remove();
            remove_payload_metadata_headers(&mut parts.headers);
            parts.extensions.insert(marker);

            Response::from_parts(parts, body)
        } else {
            Response::from_parts(parts, DecompressionBody::new(BodyInner::identity(body)))
        };

        Ok(res)
    }
}
