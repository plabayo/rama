use crate::{
    Request, Response, StatusCode, layer::upgrade::UpgradeResponse,
    service::web::response::IntoResponse as _,
};
use rama_core::{Service, extensions::Extensions, telemetry::tracing};
use rama_net::{ConnectorTargetInputExt, Protocol, client::ConnectorTarget};

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
/// A lazy [`Service`] which acknowledges an HTTP (proxy) CONNECT request
/// without first establishing the egress connection.
///
/// This is appropriate when the upgraded application stream must be observed
/// before egress can be selected or constructed, such as application-aware
/// routing for a custom tunneled protocol. It deliberately means that a
/// successful CONNECT response does not confirm egress reachability.
///
/// For an ordinary HTTP proxy, including MITM where the CONNECT authority is
/// the target, use [`EagerHttpProxyConnector`](super::EagerHttpProxyConnector)
/// so the client receives a successful response only after the egress
/// connection has been established.
pub struct LazyHttpProxyConnectReplyService;

impl LazyHttpProxyConnectReplyService {
    #[inline(always)]
    #[must_use]
    /// Create a new [`LazyHttpProxyConnectReplyService`].
    pub fn new() -> Self {
        Self
    }
}

impl<Body> Service<Request<Body>> for LazyHttpProxyConnectReplyService
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
