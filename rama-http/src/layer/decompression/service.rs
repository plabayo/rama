use std::fmt;

use super::{DecompressionBody, body::BodyInner};
use crate::dep::http_body::Body;
use crate::headers::encoding::{AcceptEncoding, SupportedEncodings};
use crate::layer::util::compression::{CompressionLevel, WrapBody};
use crate::{
    Request, Response,
    header::{self, ACCEPT_ENCODING},
};
use rama_core::{Context, Service};
use rama_utils::macros::define_inner_service_accessors;

/// Decompresses response bodies of the underlying service.
///
/// This adds the `Accept-Encoding` header to requests and transparently decompresses response
/// bodies based on the `Content-Encoding` header.
///
/// See the [module docs](crate::layer::decompression) for more details.
pub struct Decompression<S> {
    pub(crate) inner: S,
    pub(crate) accept: AcceptEncoding,
}

impl<S> Decompression<S> {
    /// Creates a new `Decompression` wrapping the `service`.
    pub fn new(service: S) -> Self {
        Self {
            inner: service,
            accept: AcceptEncoding::default(),
        }
    }

    define_inner_service_accessors!();

    /// Sets whether to request the gzip encoding.
    #[must_use]
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
    #[must_use]
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
    #[must_use]
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
    #[must_use]
    pub fn zstd(mut self, enable: bool) -> Self {
        self.accept.set_zstd(enable);
        self
    }

    /// Sets whether to request the Zstd encoding.
    pub fn set_zstd(&mut self, enable: bool) -> &mut Self {
        self.accept.set_zstd(enable);
        self
    }
}

impl<S: fmt::Debug> fmt::Debug for Decompression<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Decompression")
            .field("inner", &self.inner)
            .field("accept", &self.accept)
            .finish()
    }
}

impl<S: Clone> Clone for Decompression<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            accept: self.accept,
        }
    }
}

impl<S, State, ReqBody, ResBody> Service<State, Request<ReqBody>> for Decompression<S>
where
    S: Service<State, Request<ReqBody>, Response = Response<ResBody>>,
    State: Clone + Send + Sync + 'static,
    ReqBody: Send + 'static,
    ResBody: Body<Data: Send + 'static, Error: Send + 'static> + Send + 'static,
{
    type Response = Response<DecompressionBody<ResBody>>;
    type Error = S::Error;

    async fn serve(
        &self,
        ctx: Context<State>,
        mut req: Request<ReqBody>,
    ) -> Result<Self::Response, Self::Error> {
        if let header::Entry::Vacant(entry) = req.headers_mut().entry(ACCEPT_ENCODING) {
            if let Some(accept) = self.accept.maybe_to_header_value() {
                entry.insert(accept);
            }
        }

        let res = self.inner.serve(ctx, req).await?;

        let (mut parts, body) = res.into_parts();

        let res =
            if let header::Entry::Occupied(entry) = parts.headers.entry(header::CONTENT_ENCODING) {
                let body = match entry.get().as_bytes() {
                    b"gzip" if self.accept.gzip() => DecompressionBody::new(BodyInner::gzip(
                        WrapBody::new(body, CompressionLevel::default()),
                    )),

                    b"deflate" if self.accept.deflate() => DecompressionBody::new(
                        BodyInner::deflate(WrapBody::new(body, CompressionLevel::default())),
                    ),

                    b"br" if self.accept.br() => DecompressionBody::new(BodyInner::brotli(
                        WrapBody::new(body, CompressionLevel::default()),
                    )),

                    b"zstd" if self.accept.zstd() => DecompressionBody::new(BodyInner::zstd(
                        WrapBody::new(body, CompressionLevel::default()),
                    )),

                    _ => {
                        return Ok(Response::from_parts(
                            parts,
                            DecompressionBody::new(BodyInner::identity(body)),
                        ));
                    }
                };

                entry.remove();
                parts.headers.remove(header::CONTENT_LENGTH);

                Response::from_parts(parts, body)
            } else {
                Response::from_parts(parts, DecompressionBody::new(BodyInner::identity(body)))
            };

        Ok(res)
    }
}
