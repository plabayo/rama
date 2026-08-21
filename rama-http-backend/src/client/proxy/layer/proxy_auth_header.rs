use rama_core::extensions::ExtensionsRef;
use rama_core::telemetry::tracing;
use rama_core::{Layer, Service};
use rama_http_headers::{HeaderMapExt, ProxyAuthorization};
use rama_http_types::Request;
use rama_net::{Protocol, ProtocolInputExt, client::ProxyRoute, user::ProxyCredential};

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
/// A [`Layer`] which will set the http auth header
/// in case there is a proxied [`ProxyRoute`] in the [`Extensions`].
///
/// Compose [`rama_net::client::ProxyRoutesLayer`] after every route-selection
/// layer and immediately before middleware such as this one. That boundary
/// materializes the middleware-visible [`ProxyRoute`] while retaining any
/// ordered fallback plan for the connector.
///
/// [`Extensions`]: rama_core::extensions::Extensions
pub struct SetProxyAuthHttpHeaderLayer;

impl SetProxyAuthHttpHeaderLayer {
    /// Create a new [`SetProxyAuthHttpHeaderLayer`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl<S> Layer<S> for SetProxyAuthHttpHeaderLayer {
    type Service = SetProxyAuthHttpHeaderService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SetProxyAuthHttpHeaderService::new(inner)
    }
}

/// A [`Service`] wwhich will set the http auth header
/// in case there is a proxied [`ProxyRoute`] in the [`Extensions`].
///
/// [`Extensions`]: rama_core::extensions::Extensions
#[derive(Debug, Clone)]
pub struct SetProxyAuthHttpHeaderService<S> {
    inner: S,
}

impl<S> SetProxyAuthHttpHeaderService<S> {
    /// Create a new [`SetProxyAuthHttpHeaderService`].
    pub const fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S, Body> Service<Request<Body>> for SetProxyAuthHttpHeaderService<S>
where
    S: Service<Request<Body>>,
    Body: Send + 'static,
{
    type Output = S::Output;
    type Error = S::Error;

    fn serve(
        &self,
        mut req: Request<Body>,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + '_ {
        let destination_is_secure = req.protocol().is_some_and(Protocol::is_secure)
            || (req.uri().scheme().is_none() && req.uri().authority().is_some());
        if let Some(pa) = req
            .extensions()
            .get_ref::<ProxyRoute>()
            .and_then(ProxyRoute::proxy_address)
            && pa
                .protocol
                .as_ref()
                .is_none_or(|protocol| *protocol == Protocol::HTTP || *protocol == Protocol::HTTPS)
            && !destination_is_secure
            && let Some(credential) = pa.credential.clone()
        {
            match credential {
                ProxyCredential::Basic(basic) => {
                    tracing::trace!("inserted proxy Basic credentials into HTTP proxy request");
                    req.headers_mut().typed_insert(ProxyAuthorization(basic))
                }
                ProxyCredential::Bearer(bearer) => {
                    tracing::trace!("inserted proxy Bearer credentials into HTTP proxy request");
                    req.headers_mut().typed_insert(ProxyAuthorization(bearer))
                }
            }
        }

        self.inner.serve(req)
    }
}

#[cfg(test)]
mod tests {
    use core::convert::Infallible;

    use rama_core::service::service_fn;
    use rama_http_types::header::PROXY_AUTHORIZATION;
    use rama_net::{
        address::ProxyAddress,
        client::{ProxyRoutes, ProxyRoutesLayer},
        user::{Basic, ProxyCredential},
    };

    use super::*;

    fn authenticated_proxy(protocol: &str) -> ProxyRoute {
        let mut address: ProxyAddress = format!("{protocol}://proxy.example:8080").parse().unwrap();
        address.credential = Some(ProxyCredential::Basic(
            Basic::try_from("user:password").unwrap(),
        ));
        ProxyRoute::Proxy(address)
    }

    async fn sends_proxy_authorization(request: Request<()>) -> bool {
        ProxyRoutesLayer::new()
            .into_layer(SetProxyAuthHttpHeaderLayer::new().into_layer(service_fn(
                |request: Request<()>| async move {
                    Ok::<_, Infallible>(request.headers().contains_key(PROXY_AUTHORIZATION))
                },
            )))
            .serve(request)
            .await
            .unwrap()
    }

    async fn observe_proxy_authorization(
        layer: ProxyRoutesLayer,
        request: Request<()>,
    ) -> (bool, ProxyRoute) {
        layer
            .into_layer(SetProxyAuthHttpHeaderLayer::new().into_layer(service_fn(
                |request: Request<()>| async move {
                    Ok::<_, Infallible>((
                        request.headers().contains_key(PROXY_AUTHORIZATION),
                        request
                            .extensions()
                            .get_ref::<ProxyRoute>()
                            .cloned()
                            .expect("materialized proxy route"),
                    ))
                },
            )))
            .serve(request)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn singleton_route_plan_supplies_http_proxy_credentials() {
        let request = Request::builder()
            .uri("http://origin.example/")
            .body(())
            .unwrap();
        request
            .extensions()
            .insert(ProxyRoutes::from(authenticated_proxy("http")));

        assert!(sends_proxy_authorization(request).await);
    }

    #[tokio::test]
    async fn authoritative_direct_plan_suppresses_stale_singular_credentials() {
        let request = Request::builder()
            .uri("http://origin.example/")
            .body(())
            .unwrap();
        request.extensions().insert(authenticated_proxy("http"));
        request
            .extensions()
            .insert(ProxyRoutes::from(ProxyRoute::Direct));

        assert!(!sends_proxy_authorization(request).await);
    }

    #[tokio::test]
    async fn socks_and_secure_destinations_never_receive_the_http_header() {
        let socks = Request::builder()
            .uri("http://origin.example/")
            .body(())
            .unwrap();
        socks.extensions().insert(authenticated_proxy("socks5"));
        assert!(!sends_proxy_authorization(socks).await);

        let secure = Request::builder()
            .uri("https://origin.example/")
            .body(())
            .unwrap();
        secure.extensions().insert(authenticated_proxy("http"));
        assert!(!sends_proxy_authorization(secure).await);

        for authority in ["origin.example:443", "origin.example:8443"] {
            let authority_form = Request::builder()
                .uri(rama_net::uri::Uri::parse_authority_form(authority).unwrap())
                .body(())
                .unwrap();
            authority_form
                .extensions()
                .insert(authenticated_proxy("http"));
            assert!(
                !sends_proxy_authorization(authority_form).await,
                "{authority}"
            );
        }
    }

    #[tokio::test]
    async fn multi_route_credentials_are_not_exposed_to_http_middleware() {
        let request = Request::builder()
            .uri("http://origin.example/")
            .body(())
            .unwrap();
        request.extensions().insert(ProxyRoutes::new([
            authenticated_proxy("http"),
            ProxyRoute::Direct,
        ]));

        assert!(!sends_proxy_authorization(request).await);
    }

    #[tokio::test]
    async fn configured_routes_are_resolved_before_authentication() {
        let request = Request::builder()
            .uri("http://origin.example/")
            .body(())
            .unwrap();
        request
            .extensions()
            .insert(ProxyRoutes::from(authenticated_proxy("http")));
        let (authenticated, route) =
            observe_proxy_authorization(ProxyRoutesLayer::with_routes(ProxyRoute::Direct), request)
                .await;
        assert!(authenticated);
        assert!(route.proxy_address().is_some());

        let request = Request::builder()
            .uri("http://origin.example/")
            .body(())
            .unwrap();
        request
            .extensions()
            .insert(ProxyRoutes::from(authenticated_proxy("http")));
        let (authenticated, route) = observe_proxy_authorization(
            ProxyRoutesLayer::with_routes(ProxyRoute::Direct).with_overwrite(true),
            request,
        )
        .await;
        assert!(!authenticated);
        assert_eq!(route, ProxyRoute::Direct);
    }
}
