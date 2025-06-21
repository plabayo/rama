use crate::headers::encoding::{Encoding, parse_accept_encoding_headers};
use crate::layer::{
    compression::{self, CompressionBody, CompressionLevel},
    decompression::{self, DecompressionBody},
    util::compression::WrapBody,
};
use rama_core::telemetry::tracing;
use rama_core::{Context, Service, error::BoxError};
use rama_http_types::{
    HeaderValue, Request, Response,
    dep::http_body::Body,
    header::{CONTENT_ENCODING, CONTENT_LENGTH},
};
use rama_utils::macros::define_inner_service_accessors;

/// Service which tracks the original 'Accept-Encoding' header and compares
/// it with the server 'Content-Encoding' header, to adapt the response if needed.
///
/// ## Example
///
/// `Accept-Encoding: gzip` and `Content-Encoding: zstd` will result in:
///
/// ```text
/// compress_gzip(decompress_zstd(body))
/// ```
pub struct CompressAdaptService<S> {
    pub(crate) inner: S,
    pub(crate) quality: CompressionLevel,
}

impl<S> std::fmt::Debug for CompressAdaptService<S>
where
    S: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompressAdaptService")
            .field("inner", &self.inner)
            .field("quality", &self.quality)
            .finish()
    }
}

impl<S> Clone for CompressAdaptService<S>
where
    S: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            quality: self.quality,
        }
    }
}

impl<S> CompressAdaptService<S> {
    /// Creates a new `CompressAdaptService` wrapping the `service`.
    pub fn new(service: S) -> CompressAdaptService<S> {
        Self {
            inner: service,
            quality: CompressionLevel::default(),
        }
    }
}

impl<S> CompressAdaptService<S> {
    define_inner_service_accessors!();

    /// Sets the compression quality.
    pub fn quality(mut self, quality: CompressionLevel) -> Self {
        self.quality = quality;
        self
    }

    /// Sets the compression quality.
    pub fn set_quality(&mut self, quality: CompressionLevel) -> &mut Self {
        self.quality = quality;
        self
    }
}

impl<ReqBody, ResBody, S, State> Service<State, Request<ReqBody>> for CompressAdaptService<S>
where
    S: Service<State, Request<ReqBody>, Response = Response<ResBody>>,
    ResBody:
        Body<Data: Send + 'static, Error: Into<BoxError> + Send + Sync + 'static> + Send + 'static,
    ReqBody: Send + 'static,
    State: Clone + Send + Sync + 'static,
{
    type Response = Response<CompressionBody<DecompressionBody<ResBody>>>;
    type Error = S::Error;

    #[allow(unreachable_code, unused_mut, unused_variables, unreachable_patterns)]
    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request<ReqBody>,
    ) -> Result<Self::Response, Self::Error> {
        let requested_encoding =
            parse_accept_encoding_headers(req.headers(), true).collect::<Vec<_>>();

        let res = self.inner.serve(ctx, req).await?;
        let (mut parts, body) = res.into_parts();

        match Encoding::maybe_from_content_encoding_header(&parts.headers, true) {
            Some(server_encoding)
                if !requested_encoding
                    .iter()
                    .any(|qv| qv.value == server_encoding) =>
            {
                tracing::trace!(
                    http.response_content_encoding = %server_encoding,
                    "server encoded not supported by requested client encoding, decompressing"
                );
                let decompress_body = DecompressionBody::new(match server_encoding {
                    Encoding::Identity => decompression::body::BodyInner::identity(body),
                    Encoding::Deflate => decompression::body::BodyInner::deflate(WrapBody::new(
                        body,
                        CompressionLevel::default(),
                    )),
                    Encoding::Gzip => decompression::body::BodyInner::gzip(WrapBody::new(
                        body,
                        CompressionLevel::default(),
                    )),
                    Encoding::Brotli => decompression::body::BodyInner::brotli(WrapBody::new(
                        body,
                        CompressionLevel::default(),
                    )),
                    Encoding::Zstd => decompression::body::BodyInner::zstd(WrapBody::new(
                        body,
                        CompressionLevel::default(),
                    )),
                });

                parts.headers.remove(CONTENT_LENGTH);
                parts.headers.remove(CONTENT_ENCODING);

                let final_body = match Encoding::maybe_preferred_encoding(
                    requested_encoding.into_iter(),
                ) {
                    Some(client_encoding) => {
                        tracing::trace!(
                            http.response_content_encoding = %server_encoding,
                            http.request_content_encoding = %client_encoding,
                            "re-encode decompressed response body into preferred client encoding"
                        );
                        parts
                            .headers
                            .insert(CONTENT_ENCODING, HeaderValue::from(client_encoding));
                        match client_encoding {
                            Encoding::Identity => CompressionBody::new(
                                compression::body::BodyInner::identity(decompress_body),
                            ),
                            Encoding::Deflate => {
                                CompressionBody::new(compression::body::BodyInner::deflate(
                                    WrapBody::new(decompress_body, self.quality),
                                ))
                            }
                            Encoding::Gzip => {
                                CompressionBody::new(compression::body::BodyInner::gzip(
                                    WrapBody::new(decompress_body, self.quality),
                                ))
                            }
                            Encoding::Brotli => {
                                CompressionBody::new(compression::body::BodyInner::brotli(
                                    WrapBody::new(decompress_body, self.quality),
                                ))
                            }
                            Encoding::Zstd => {
                                CompressionBody::new(compression::body::BodyInner::zstd(
                                    WrapBody::new(decompress_body, self.quality),
                                ))
                            }
                        }
                    }
                    None => CompressionBody::new(compression::body::BodyInner::identity(
                        decompress_body,
                    )),
                };

                Ok(Response::from_parts(parts, final_body))
            }
            _ => {
                tracing::trace!("no action required for server response encoding");
                let body = CompressionBody::new(compression::body::BodyInner::identity(
                    DecompressionBody::new(decompression::body::BodyInner::identity(body)),
                ));
                Ok(Response::from_parts(parts, body))
            }
        }
    }
}
