//! The credential `--proxy-auth` requires on every proxy ingress.

use std::convert::Infallible;

use rama::{
    Layer as _, Service,
    http::{
        Body, Request, Response, StatusCode, layer::proxy_auth::ProxyAuthLayer,
        service::web::response::IntoResponse as _,
    },
    net::{address::SocketAddress, user::Basic},
    service::service_fn,
    telemetry::tracing,
};

use super::request_targets_dashboard;

/// `inner` behind `credential`: a request without it gets 407, and the credential is removed
/// before the request goes on. The inspector dashboard keeps its own token instead.
pub(super) fn require_proxy_auth<S>(
    inner: S,
    credential: Option<Basic>,
    dashboard: Option<SocketAddress>,
) -> impl Service<Request, Output = Response, Error = Infallible> + Clone
where
    S: Service<Request, Output = Response, Error = Infallible> + Clone,
{
    let guarded =
        credential.map(|credential| ProxyAuthLayer::new(credential).into_layer(inner.clone()));
    service_fn(move |request: Request| {
        let inner = inner.clone();
        let guarded = guarded.clone();
        async move {
            let is_dashboard =
                dashboard.is_some_and(|address| request_targets_dashboard(&request, address));
            match guarded {
                Some(guarded) if !is_dashboard => match guarded.serve(request).await {
                    Ok(response) => Ok(response.map(Body::new)),
                    Err(error) => {
                        tracing::debug!(%error, "proxy authentication failed");
                        Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response())
                    }
                },
                _ => inner.serve(request).await,
            }
        }
    })
}
