use super::{body::BodyInner, DecompressionBody};
use crate::http::dep::http_body::Body;
use crate::http::layer::util::{
    compression::{AcceptEncoding, CompressionLevel, WrapBody},
    content_encoding::SupportedEncodings,
};
use crate::http::{
    header::{self, ACCEPT_ENCODING},
    Request, Response,
};
use crate::service::{Context, Service};

/// Decompresses response bodies of the underlying service.
///
/// This adds the `Accept-Encoding` header to requests and transparently decompresses response
/// bodies based on the `Content-Encoding` header.
///
/// See the [module docs](crate::http::layer::decompression) for more details.
#[derive(Debug, Clone)]
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
    pub fn gzip(mut self, enable: bool) -> Self {
        self.accept.set_gzip(enable);
        self
    }

    /// Sets whether to request the Deflate encoding.
    pub fn deflate(mut self, enable: bool) -> Self {
        self.accept.set_deflate(enable);
        self
    }

    /// Sets whether to request the Brotli encoding.
    pub fn br(mut self, enable: bool) -> Self {
        self.accept.set_br(enable);
        self
    }

    /// Sets whether to request the Zstd encoding.
    pub fn zstd(mut self, enable: bool) -> Self {
        self.accept.set_zstd(enable);
        self
    }

    /// Disables the gzip encoding.
    pub fn no_gzip(mut self) -> Self {
        self.accept.set_gzip(false);
        self
    }

    /// Disables the Deflate encoding.
    pub fn no_deflate(mut self) -> Self {
        self.accept.set_deflate(false);
        self
    }

    /// Disables the Brotli encoding.
    pub fn no_br(mut self) -> Self {
        self.accept.set_br(false);
        self
    }

    /// Disables the Zstd encoding.
    pub fn no_zstd(mut self) -> Self {
        self.accept.set_zstd(false);
        self
    }
}

impl<S, State, ReqBody, ResBody> Service<State, Request<ReqBody>> for Decompression<S>
where
    S: Service<State, Request<ReqBody>, Response = Response<ResBody>>,
    State: Send + Sync + 'static,
    ReqBody: Send + 'static,
    ResBody: Body + Send + 'static,
    ResBody::Data: Send + 'static,
    ResBody::Error: Send + 'static,
{
    type Response = Response<DecompressionBody<ResBody>>;
    type Error = S::Error;

    async fn serve(
        &self,
        ctx: Context<State>,
        mut req: Request<ReqBody>,
    ) -> Result<Self::Response, Self::Error> {
        if let header::Entry::Vacant(entry) = req.headers_mut().entry(ACCEPT_ENCODING) {
            if let Some(accept) = self.accept.to_header_value() {
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
                        ))
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
