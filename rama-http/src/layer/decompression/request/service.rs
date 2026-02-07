use crate::StreamingBody;
use crate::headers::encoding::{AcceptEncoding, SupportedEncodings};
use crate::layer::{
    decompression::DecompressionBody,
    decompression::body::BodyInner,
    util::compression::{CompressionLevel, WrapBody},
};
use crate::{HeaderValue, Request, Response, StatusCode, header};
use rama_core::Service;
use rama_core::bytes::Bytes;
use rama_core::error::{BoxError, ErrorContext as _};
use rama_http_types::Body;
use rama_utils::macros::define_inner_service_accessors;

/// Decompresses request bodies and calls its underlying service.
///
/// Transparently decompresses request bodies based on the `Content-Encoding` header.
/// When the encoding in the `Content-Encoding` header is not accepted an `Unsupported Media Type`
/// status code will be returned with the accepted encodings in the `Accept-Encoding` header.
///
/// Enabling pass-through of unaccepted encodings will not return an `Unsupported Media Type` but
/// will call the underlying service with the unmodified request if the encoding is not supported.
/// This is disabled by default.
///
/// See the [module docs](crate::layer::decompression) for more details.
#[derive(Debug, Clone)]
pub struct RequestDecompression<S> {
    pub(super) inner: S,
    pub(super) accept: AcceptEncoding,
    pub(super) pass_through_unaccepted: bool,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for RequestDecompression<S>
where
    S: Service<
            Request<DecompressionBody<ReqBody>>,
            Output = Response<ResBody>,
            Error: Into<BoxError>,
        >,
    ReqBody: StreamingBody + Send + 'static,
    ResBody: StreamingBody<Data = Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
{
    type Output = Response;
    type Error = BoxError;

    async fn serve(&self, req: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        let (mut parts, body) = req.into_parts();

        let body =
            if let header::Entry::Occupied(entry) = parts.headers.entry(header::CONTENT_ENCODING) {
                match entry.get().as_bytes() {
                    b"gzip" if self.accept.gzip() => {
                        entry.remove();
                        parts.headers.remove(header::CONTENT_LENGTH);
                        BodyInner::gzip(WrapBody::new(body, CompressionLevel::default()))
                    }
                    b"deflate" if self.accept.deflate() => {
                        entry.remove();
                        parts.headers.remove(header::CONTENT_LENGTH);
                        BodyInner::deflate(WrapBody::new(body, CompressionLevel::default()))
                    }
                    b"br" if self.accept.br() => {
                        entry.remove();
                        parts.headers.remove(header::CONTENT_LENGTH);
                        BodyInner::brotli(WrapBody::new(body, CompressionLevel::default()))
                    }
                    b"zstd" if self.accept.zstd() => {
                        entry.remove();
                        parts.headers.remove(header::CONTENT_LENGTH);
                        BodyInner::zstd(WrapBody::new(body, CompressionLevel::default()))
                    }
                    b"identity" => BodyInner::identity(body),
                    _ if self.pass_through_unaccepted => BodyInner::identity(body),
                    _ => return unsupported_encoding(self.accept),
                }
            } else {
                BodyInner::identity(body)
            };
        let body = DecompressionBody::new(body);
        let req = Request::from_parts(parts, body);
        self.inner
            .serve(req)
            .await
            .map(|res| res.map(Body::new))
            .into_box_error()
    }
}

fn unsupported_encoding(accept: AcceptEncoding) -> Result<Response, BoxError> {
    let res = Response::builder()
        .header(
            header::ACCEPT_ENCODING,
            accept
                .maybe_to_header_value()
                .unwrap_or(HeaderValue::from_static("identity")),
        )
        .status(StatusCode::UNSUPPORTED_MEDIA_TYPE)
        .body(Body::empty())?;
    Ok(res)
}

impl<S> RequestDecompression<S> {
    /// Creates a new `RequestDecompression` wrapping the `service`.
    pub fn new(service: S) -> Self {
        Self {
            inner: service,
            accept: AcceptEncoding::default(),
            pass_through_unaccepted: false,
        }
    }

    define_inner_service_accessors!();

    rama_utils::macros::generate_set_and_with! {
        /// Passes through the request even when the encoding is not supported.
        ///
        /// By default pass-through is disabled.
        pub fn pass_through_unaccepted(mut self, enabled: bool) -> Self {
            self.pass_through_unaccepted = enabled;
            self
        }
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
}
