use rama_core::{Service, extensions::ExtensionsMut as _, telemetry::tracing};
use rama_http::{Request, Response, StatusCode, service::web::response::IntoResponse as _};
use rama_net::{http::RequestContext, proxy::ProxyTarget};

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
    type Output = (Response, Request<Body>);
    type Error = Response;

    async fn serve(&self, mut req: Request<Body>) -> Result<Self::Output, Self::Error> {
        match RequestContext::try_from(&req).map(|ctx| ctx.host_with_port()) {
            Ok(authority) => {
                tracing::info!(
                    server.address = %authority.host,
                    server.port = authority.port,
                    "accept CONNECT (lazy): insert proxy target into extensions",
                );
                req.extensions_mut().insert(ProxyTarget(authority));
            }
            Err(err) => {
                tracing::error!("error extracting authority: {err:?}");
                return Err(StatusCode::BAD_REQUEST.into_response());
            }
        }

        Ok((StatusCode::OK.into_response(), req))
    }
}
