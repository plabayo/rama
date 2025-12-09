use super::{DecompressionBody, body::BodyInner};
use crate::headers::encoding::{AcceptEncoding, SupportedEncodings};
use crate::layer::util::compression::{CompressionLevel, WrapBody};
use crate::{
    Request, Response, StreamingBody,
    header::{self, ACCEPT_ENCODING},
};
use rama_core::Service;
use rama_utils::macros::define_inner_service_accessors;

/// Decompresses response bodies of the underlying service.
///
/// This adds the `Accept-Encoding` header to requests and transparently decompresses response
/// bodies based on the `Content-Encoding` header.
///
/// See the [module docs](crate::layer::decompression) for more details.
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

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for Decompression<S>
where
    S: Service<Request<ReqBody>, Output = Response<ResBody>>,
    ReqBody: Send + 'static,
    ResBody: StreamingBody<Data: Send + 'static, Error: Send + 'static> + Send + 'static,
{
    type Output = Response<DecompressionBody<ResBody>>;
    type Error = S::Error;

    async fn serve(&self, mut req: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        if let header::Entry::Vacant(entry) = req.headers_mut().entry(ACCEPT_ENCODING)
            && let Some(accept) = self.accept.maybe_to_header_value()
        {
            entry.insert(accept);
        }

        let res = self.inner.serve(req).await?;

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
