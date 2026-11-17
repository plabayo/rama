use rama_core::error::{BoxError, ErrorContext};
use rama_core::{Layer, Service, extensions::ExtensionsRef};
use rama_http::headers::{ContentType, HeaderMapExt as _};
use rama_http::layer::version_adapter::adapt_request_version;
use rama_http_types::{Request, Response, Version};
use rama_utils::macros::{define_inner_service_accessors, generate_set_and_with};

use super::GrpcWebCall;
use crate::codec::DEFAULT_MAX_RECV_MESSAGE_SIZE;

/// Layer implementing the grpc-web protocol for clients.
#[derive(Debug, Clone)]
pub struct GrpcWebClientLayer {
    max_frame_size: usize,
}

impl Default for GrpcWebClientLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl GrpcWebClientLayer {
    /// Create a new grpc-web for clients layer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            max_frame_size: DEFAULT_MAX_RECV_MESSAGE_SIZE,
        }
    }

    generate_set_and_with! {
        /// Set the largest payload, in bytes, of one response frame.
        ///
        /// It bounds what one frame may make the client buffer before the codec's own
        /// message limit applies, so raise it together with the client's maximum decoding
        /// message size. Defaults to 4 MiB, the default maximum decoding message size.
        pub fn max_frame_size(mut self, max_frame_size: usize) -> Self {
            self.max_frame_size = max_frame_size;
            self
        }
    }
}

impl<S> Layer<S> for GrpcWebClientLayer {
    type Service = GrpcWebClientService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        GrpcWebClientService::new(inner).with_max_frame_size(self.max_frame_size)
    }
}

/// A [`Service`] that wraps some inner http service that will
/// coerce requests coming from `rama-grpc` clients into proper
/// `grpc-web` requests.
#[derive(Debug, Clone, ExtensionsRef)]
pub struct GrpcWebClientService<S> {
    inner: S,
    max_frame_size: usize,
}

impl<S> GrpcWebClientService<S> {
    define_inner_service_accessors!();

    /// Create a new grpc-web for clients service.
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            max_frame_size: DEFAULT_MAX_RECV_MESSAGE_SIZE,
        }
    }

    generate_set_and_with! {
        /// Set the largest payload, in bytes, of one response frame.
        ///
        /// It bounds what one frame may make the client buffer before the codec's own
        /// message limit applies, so raise it together with the client's maximum decoding
        /// message size. Defaults to 4 MiB, the default maximum decoding message size.
        pub fn max_frame_size(mut self, max_frame_size: usize) -> Self {
            self.max_frame_size = max_frame_size;
            self
        }
    }
}

impl<S, B1, B2> Service<Request<B1>> for GrpcWebClientService<S>
where
    S: Service<Request<GrpcWebCall<B1>>, Output = Response<B2>, Error: Into<BoxError>>,
    B1: Send + 'static,
    B2: Send + 'static,
{
    type Output = Response<GrpcWebCall<B2>>;
    type Error = BoxError;

    async fn serve(&self, mut req: Request<B1>) -> Result<Self::Output, Self::Error> {
        adapt_request_version(&mut req, Version::HTTP_11)?;

        req.headers_mut().typed_insert(ContentType::grpc_web());

        let req = req.map(GrpcWebCall::client_request);

        let resp = self.inner.serve(req).await.into_box_error()?;
        let max_frame_size = self.max_frame_size;
        Ok(resp.map(|body| GrpcWebCall::client_response(body, max_frame_size)))
    }
}
