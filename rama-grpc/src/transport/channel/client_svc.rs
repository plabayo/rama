use rama_core::{
    Service,
    error::BoxError,
    extensions::{Extensions, ExtensionsMut, ExtensionsRef, InputExtensions},
    telemetry::tracing,
};
use rama_http::{Request, Response, StreamingBody, Version, conn::TargetHttpVersion};
use rama_http_core::client::conn::http2;

/// Internal grpc sender used to send the actual requests.
pub struct GrpcClientService<Body> {
    pub(super) sender: http2::SendRequest<Body>,
    pub(super) extensions: Extensions,
}

impl<Body> Service<Request<Body>> for GrpcClientService<Body>
where
    Body: StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Unpin + Send + 'static,
{
    type Output = Response;
    type Error = BoxError;

    async fn serve(&self, mut req: Request<Body>) -> Result<Self::Output, Self::Error> {
        if req.version() != Version::HTTP_2 {
            // TODO: do we really need to do this?
            tracing::debug!(
                "coercing request' and target version to H2.1 (was: {:?})",
                req.version()
            );
            req.extensions_mut()
                .insert(TargetHttpVersion(Version::HTTP_2));
            *req.version_mut() = Version::HTTP_2;
        }

        let req_extensions = req.extensions().clone();

        let mut sender = self.sender.clone();
        sender.ready().await?;
        let mut resp = sender.send_request(req).await?;

        resp.extensions_mut()
            .insert(InputExtensions(req_extensions));

        Ok(resp.map(rama_http_types::Body::new))
    }
}

impl<B> ExtensionsRef for GrpcClientService<B> {
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl<B> ExtensionsMut for GrpcClientService<B> {
    fn extensions_mut(&mut self) -> &mut Extensions {
        &mut self.extensions
    }
}
