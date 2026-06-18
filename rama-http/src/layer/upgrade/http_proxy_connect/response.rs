use crate::{
    Request, Response, StatusCode, layer::upgrade::UpgradeResponse,
    service::web::response::IntoResponse as _,
};
use rama_core::{Service, extensions::Extensions, telemetry::tracing};
use rama_http_types::RequestContext;
use rama_net::proxy::ProxyTarget;

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
/// A default [`Service`] which responds on an http (proxy) connect with
/// a default http response and which injects
/// the destination address as the proxy target.
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

        match RequestContext::try_from(&req).map(|ctx| ctx.host_with_port()) {
            Ok(authority) => {
                tracing::info!(
                    server.address = %authority.host,
                    server.port = authority.port,
                    "accept CONNECT: insert proxy target into extensions",
                );
                extensions.insert(ProxyTarget(authority));
            }
            Err(err) => {
                tracing::error!("error extracting authority: {err:?}");
                return Err(StatusCode::BAD_REQUEST.into_response());
            }
        }
        Ok(UpgradeResponse {
            request: req,
            response: StatusCode::OK.into_response(),
            extensions,
        })
    }
}
