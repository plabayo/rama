use crate::{
    Request, Response, StatusCode, layer::upgrade::UpgradeResponse,
    service::web::response::IntoResponse as _,
};
use rama_core::{Service, extensions::Extensions, telemetry::tracing};
use rama_net::{ConnectorTargetInputExt, Protocol, client::ConnectorTarget};

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
/// A default [`Service`] which responds on an http (proxy) connect with
/// a default http response.
///
/// It can also be used for other HTTP connect purposes,
/// but that is not what the service is intended for.
pub struct DefaultHttpProxyConnectReplyService;

impl DefaultHttpProxyConnectReplyService {
    #[inline(always)]
    #[must_use]
    /// Create a new [`DefaultHttpProxyConnectReplyService`].
    pub fn new() -> Self {
        Self
    }
}

impl<Body> Service<Request<Body>> for DefaultHttpProxyConnectReplyService
where
    Body: Send + 'static,
{
    type Output = UpgradeResponse<Request<Body>, Response>;
    type Error = Response;

    async fn serve(&self, req: Request<Body>) -> Result<Self::Output, Self::Error> {
        let extensions = Extensions::new();

        if let Some(authority) = req.connector_target_with_default_port(Protocol::HTTP_DEFAULT_PORT)
        {
            tracing::info!(
                server.address = %authority.host,
                server.port = authority.port,
                "accept CONNECT: insert proxy (connector) target into extensions",
            );
            extensions.insert(ConnectorTarget(authority));
        } else {
            tracing::error!("http proxy, error extracting connector target");
            return Err(StatusCode::BAD_REQUEST.into_response());
        }

        Ok(UpgradeResponse {
            request: req,
            response: StatusCode::OK.into_response(),
            extensions,
        })
    }
}
