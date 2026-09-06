//! Authentication policy for established HTTP forward-proxy connections.

use rama_core::{
    Layer, Service,
    error::BoxError,
    extensions::{Egress, Extensions, ExtensionsRef},
    telemetry::tracing,
};
use rama_http_headers::{HeaderMapExt, ProxyAuthorization};
use rama_http_types::{Request, Response, StatusCode};
use rama_net::{client::EstablishedProxyRoute, user::ProxyCredential};
use std::fmt;

use super::remove_header::remove_proxy_auth_request_headers;

/// An established HTTP forward proxy requires authentication.
///
/// Returned when [`HttpForwardProxyLayer::with_isolate_auth_error`] is enabled
/// and the proxy responds with `407 Proxy Authentication Required`. The proxy's
/// response headers and body are discarded.
#[derive(Debug, Clone, Copy)]
pub struct HttpForwardProxyAuthRequired;

impl fmt::Display for HttpForwardProxyAuthRequired {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HTTP forward proxy authentication required")
    }
}

impl std::error::Error for HttpForwardProxyAuthRequired {}

/// HTTP middleware for requests sent directly to an HTTP forward proxy.
///
/// The layer resolves [`EstablishedProxyRoute`] from the wrapped connection.
/// The wrapped connection's extensions, including an absent route, take
/// precedence over all request metadata. This lets
/// the layer distinguish a real forward-proxy connection from direct, SOCKS,
/// and HTTP CONNECT-tunneled connections after route fallback and pool lookup
/// have completed.
///
/// Configured Basic or Bearer credentials are inserted by default. Call
/// [`Self::with_proxy_auth`] with `false` to disable insertion. Caller-provided
/// `Proxy-Authorization` headers are always stripped on direct, SOCKS,
/// CONNECT-tunneled, or unclassified connections, even with insertion disabled.
/// Manual authentication is preserved only on established HTTP forward routes.
/// A proxy-generated `407` response is exposed by default for ordinary HTTP
/// clients; intermediary clients can enable [`Self::with_isolate_auth_error`] to turn it into
/// [`HttpForwardProxyAuthRequired`] before any proxy response headers or body
/// reach their downstream peer.
///
/// Custom proxy connectors must publish [`EstablishedProxyRoute`] in their
/// established connection extensions. Missing metadata or a forward route
/// with a non-HTTP proxy protocol disables forward-proxy behavior and never
/// falls back to request-side routes or credentials.
#[derive(Debug, Clone)]
pub struct HttpForwardProxyLayer {
    proxy_auth: bool,
    isolate_auth_error: bool,
}

impl Default for HttpForwardProxyLayer {
    fn default() -> Self {
        Self {
            proxy_auth: true,
            isolate_auth_error: false,
        }
    }
}

impl HttpForwardProxyLayer {
    /// Create a layer which inserts configured proxy credentials and exposes
    /// proxy-generated `407` responses.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    rama_utils::macros::generate_set_and_with! {
        /// Enable or disable preemptive Basic or Bearer authentication for HTTP
        /// forward-proxy requests.
        ///
        /// This controls insertion only. Caller-provided `Proxy-Authorization`
        /// is preserved on established HTTP forward routes and always stripped
        /// on every other route, including connections without route metadata.
        pub fn proxy_auth(mut self, enabled: bool) -> Self {
            self.proxy_auth = enabled;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Enable or disable isolation of a forward proxy's `407` response.
        ///
        /// When enabled, the response is dropped and
        /// [`HttpForwardProxyAuthRequired`] is returned. This is intended for
        /// intermediary services which must not expose one proxy hop's challenge
        /// to a different downstream proxy client.
        pub fn isolate_auth_error(mut self, enabled: bool) -> Self {
            self.isolate_auth_error = enabled;
            self
        }
    }
}

impl<S> Layer<S> for HttpForwardProxyLayer {
    type Service = HttpForwardProxyService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        HttpForwardProxyService {
            inner,
            proxy_auth: self.proxy_auth,
            isolate_auth_error: self.isolate_auth_error,
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        HttpForwardProxyService {
            inner,
            proxy_auth: self.proxy_auth,
            isolate_auth_error: self.isolate_auth_error,
        }
    }
}

/// Service produced by [`HttpForwardProxyLayer`].
#[derive(Debug, Clone)]
pub struct HttpForwardProxyService<S> {
    inner: S,
    proxy_auth: bool,
    isolate_auth_error: bool,
}

impl<S> HttpForwardProxyService<S> {
    /// Create a forward-proxy policy service around an established HTTP
    /// connection.
    #[must_use]
    pub const fn new(inner: S) -> Self {
        Self {
            inner,
            proxy_auth: true,
            isolate_auth_error: false,
        }
    }

    rama_utils::macros::define_inner_service_accessors!();
}

impl<S: ExtensionsRef> ExtensionsRef for HttpForwardProxyService<S> {
    fn extensions(&self) -> &Extensions {
        self.inner.extensions()
    }
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for HttpForwardProxyService<S>
where
    S: Service<Request<ReqBody>, Output = Response<ResBody>> + ExtensionsRef,
    S::Error: Into<BoxError>,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
{
    type Output = Response<ResBody>;
    type Error = BoxError;

    async fn serve(&self, mut req: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        // Only the physical connection is authoritative here. A route or a
        // request-provided marker describes intent, not what fallback and pool
        // selection actually established.
        let inner_extensions = self.inner.extensions();
        let http_proxy = inner_extensions
            .get_ref::<EstablishedProxyRoute>()
            .filter(|route| route.is_http_forward())
            .and_then(EstablishedProxyRoute::proxy_address);

        // Refresh the snapshot after caller middleware, including when the
        // connection has no route. Encoders must not revive a stale marker.
        // This remains necessary for wrapped custom connections that do not
        // use HttpClientService and its own independent snapshot refresh.
        req.extensions().insert(Egress(inner_extensions.clone()));
        let is_forward_proxy = http_proxy.is_some();

        if is_forward_proxy {
            if self.proxy_auth {
                match http_proxy.and_then(|proxy| proxy.credential.clone()) {
                    Some(ProxyCredential::Basic(basic)) => {
                        tracing::trace!(
                            "inserted configured Basic credentials into HTTP forward-proxy request"
                        );
                        req.headers_mut().typed_insert(ProxyAuthorization(basic));
                    }
                    Some(ProxyCredential::Bearer(bearer)) => {
                        tracing::trace!(
                            "inserted configured Bearer credentials into HTTP forward-proxy request"
                        );
                        req.headers_mut().typed_insert(ProxyAuthorization(bearer));
                    }
                    // Preserve an explicitly supplied header when the route
                    // has no configured credential. This keeps manual and
                    // challenge-driven authentication possible. A configured
                    // route credential always wins.
                    None => {}
                }
            }
        } else {
            // A Proxy-Authorization field belongs to the HTTP proxy hop. After
            // CONNECT succeeds, the next HTTP request is addressed to the
            // tunneled origin. Direct and SOCKS-carried requests likewise have
            // no HTTP proxy hop. Neither configured nor caller-provided proxy
            // credentials may cross those boundaries.
            remove_proxy_auth_request_headers(req.headers_mut());
        }

        let response = self.inner.serve(req).await.map_err(Into::into)?;
        if is_forward_proxy
            && self.isolate_auth_error
            && response.status() == StatusCode::PROXY_AUTHENTICATION_REQUIRED
        {
            tracing::debug!("isolating authentication challenge returned by HTTP forward proxy");
            return Err(HttpForwardProxyAuthRequired.into());
        }

        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use core::convert::Infallible;

    use rama_core::bytes::BytesMut;
    use rama_http_types::{Body, HeaderValue, header::PROXY_AUTHORIZATION};
    use rama_net::{
        address::ProxyAddress,
        client::ProxyRoute,
        user::{Basic, Bearer, ProxyCredential},
    };

    use super::*;

    fn proxy_with(credential: Option<ProxyCredential>) -> ProxyAddress {
        let mut proxy: ProxyAddress = "http://proxy.example:8080".parse().unwrap();
        proxy.credential = credential;
        proxy
    }

    fn authenticated_proxy() -> ProxyAddress {
        proxy_with(Some(ProxyCredential::Basic(
            Basic::try_from("upstream:secret").unwrap(),
        )))
    }

    fn request_with_stale_route(route: Option<EstablishedProxyRoute>) -> Request {
        let request = Request::builder()
            .uri("http://origin.example/resource")
            .header(PROXY_AUTHORIZATION, "Basic downstream-secret")
            .body(Body::empty())
            .unwrap();
        request
            .extensions()
            .insert(ProxyRoute::Proxy(proxy_with(Some(ProxyCredential::Basic(
                Basic::try_from("wrong:request-secret").unwrap(),
            )))));
        if let Some(route) = route {
            request.extensions().insert(route.clone());
            let stale_egress = Extensions::new();
            stale_egress.insert(route);
            request.extensions().insert(Egress(stale_egress));
        }
        request
    }

    #[derive(Debug, Clone)]
    struct ObserveProxyAuthorization {
        extensions: Extensions,
        status: StatusCode,
    }

    impl ExtensionsRef for ObserveProxyAuthorization {
        fn extensions(&self) -> &Extensions {
            &self.extensions
        }
    }

    impl Service<Request> for ObserveProxyAuthorization {
        type Output = Response;
        type Error = Infallible;

        async fn serve(&self, request: Request) -> Result<Self::Output, Self::Error> {
            // Both presence and absence come from the wrapped connection,
            // even if caller middleware supplied its own connection snapshot.
            assert_eq!(
                request
                    .extensions()
                    .egress()
                    .unwrap()
                    .0
                    .get_ref::<EstablishedProxyRoute>(),
                self.extensions.get_ref::<EstablishedProxyRoute>(),
            );
            let mut response = Response::builder()
                .status(self.status)
                .header("proxy-authenticate", "Basic realm=upstream")
                .body(Body::from("private upstream challenge"))
                .unwrap();
            if let Some(value) = request.headers().get(PROXY_AUTHORIZATION) {
                response
                    .headers_mut()
                    .insert("x-observed-auth", value.clone());
            }
            let mut target = BytesMut::new();
            rama_http_types::proto::h1::head::encode_request_target(
                request.method(),
                request.uri(),
                request.extensions(),
                &mut target,
            )
            .unwrap();
            response.headers_mut().insert(
                "x-observed-target",
                HeaderValue::from_bytes(&target).unwrap(),
            );
            request
                .extensions()
                .clone_to::<ProxyRoute>(response.extensions());
            Ok(response)
        }
    }

    fn observe_proxy_authorization(
        route: Option<EstablishedProxyRoute>,
    ) -> ObserveProxyAuthorization {
        let extensions = Extensions::new();
        if let Some(route) = route {
            extensions.insert(route);
        }
        ObserveProxyAuthorization {
            extensions,
            status: StatusCode::OK,
        }
    }

    fn observed_auth(response: &Response) -> Option<&HeaderValue> {
        response.headers().get("x-observed-auth")
    }

    #[tokio::test]
    async fn configured_credentials_and_target_follow_only_the_established_route() {
        let proxy = authenticated_proxy();
        for (route, is_forward) in [
            (None, false),
            (Some(EstablishedProxyRoute::Direct), false),
            (Some(EstablishedProxyRoute::Tunnel(proxy.clone())), false),
            (
                Some(EstablishedProxyRoute::Tunnel(
                    "socks5://upstream:secret@proxy.example:1080"
                        .parse()
                        .unwrap(),
                )),
                false,
            ),
            (
                Some(EstablishedProxyRoute::Forward(
                    "socks5://upstream:secret@proxy.example:1080"
                        .parse()
                        .unwrap(),
                )),
                false,
            ),
            (Some(EstablishedProxyRoute::Forward(proxy.clone())), true),
        ] {
            let stale_route = if is_forward {
                EstablishedProxyRoute::Direct
            } else {
                EstablishedProxyRoute::Forward(proxy.clone())
            };
            let request = request_with_stale_route(Some(stale_route));
            let requested_route = request
                .extensions()
                .get_ref::<ProxyRoute>()
                .unwrap()
                .clone();
            let response = HttpForwardProxyLayer::new()
                .into_layer(observe_proxy_authorization(route.clone()))
                .serve(request)
                .await
                .unwrap();
            assert_eq!(
                response.extensions().get_ref::<ProxyRoute>(),
                Some(&requested_route),
                "connection facts must not overwrite input intent",
            );
            if is_forward {
                assert_eq!(
                    observed_auth(&response).unwrap(),
                    "Basic dXBzdHJlYW06c2VjcmV0",
                );
                assert_eq!(
                    response.headers()["x-observed-target"],
                    "http://origin.example/resource",
                );
            } else {
                assert!(observed_auth(&response).is_none(), "route: {route:?}");
                assert_eq!(response.headers()["x-observed-target"], "/resource");
            }
        }
    }

    #[tokio::test]
    async fn established_forward_route_works_without_request_route_metadata() {
        let request = Request::builder()
            .uri("http://origin.example/resource")
            .body(Body::empty())
            .unwrap();
        let response = HttpForwardProxyLayer::new()
            .into_layer(observe_proxy_authorization(Some(
                EstablishedProxyRoute::Forward(authenticated_proxy()),
            )))
            .serve(request)
            .await
            .unwrap();
        assert_eq!(
            observed_auth(&response).unwrap(),
            "Basic dXBzdHJlYW06c2VjcmV0",
        );
        assert!(response.extensions().get_ref::<ProxyRoute>().is_none());
    }

    #[tokio::test]
    async fn proxy_auth_can_be_disabled_without_leaking_manual_auth_to_other_routes() {
        for (route, is_forward) in [
            (None, false),
            (Some(EstablishedProxyRoute::Direct), false),
            (
                Some(EstablishedProxyRoute::Tunnel(authenticated_proxy())),
                false,
            ),
            (
                Some(EstablishedProxyRoute::Tunnel(
                    "socks5://proxy.example:1080".parse().unwrap(),
                )),
                false,
            ),
            (
                Some(EstablishedProxyRoute::Forward(
                    "socks5://proxy.example:1080".parse().unwrap(),
                )),
                false,
            ),
            (
                Some(EstablishedProxyRoute::Forward(authenticated_proxy())),
                true,
            ),
        ] {
            let response = HttpForwardProxyLayer::new()
                .with_proxy_auth(false)
                .into_layer(observe_proxy_authorization(route))
                .serve(request_with_stale_route(Some(
                    EstablishedProxyRoute::Forward(authenticated_proxy()),
                )))
                .await
                .unwrap();
            if is_forward {
                assert_eq!(observed_auth(&response).unwrap(), "Basic downstream-secret");
            } else {
                assert!(observed_auth(&response).is_none());
            }
        }
    }

    #[tokio::test]
    async fn bearer_credentials_are_applied_and_manual_auth_is_preserved_without_route_credentials()
    {
        for (credential, expected) in [
            (
                Some(ProxyCredential::Bearer(
                    Bearer::try_from("upstream-token").unwrap(),
                )),
                "Bearer upstream-token",
            ),
            (None, "Basic downstream-secret"),
        ] {
            let response = HttpForwardProxyLayer::new()
                .into_layer(observe_proxy_authorization(Some(
                    EstablishedProxyRoute::Forward(proxy_with(credential)),
                )))
                .serve(request_with_stale_route(None))
                .await
                .unwrap();
            assert_eq!(observed_auth(&response).unwrap(), expected);
        }
    }

    #[tokio::test]
    async fn non_proxy_auth_responses_are_preserved_when_isolation_is_enabled() {
        for status in [StatusCode::OK, StatusCode::UNAUTHORIZED] {
            let mut connection = observe_proxy_authorization(Some(EstablishedProxyRoute::Forward(
                authenticated_proxy(),
            )));
            connection.status = status;
            let response = HttpForwardProxyLayer::new()
                .with_isolate_auth_error(true)
                .into_layer(connection)
                .serve(request_with_stale_route(Some(
                    EstablishedProxyRoute::Direct,
                )))
                .await
                .unwrap();
            assert_eq!(response.status(), status);
        }
    }

    #[tokio::test]
    async fn auth_challenge_is_isolated_only_for_an_established_forward_route() {
        for isolate in [false, true] {
            for (route, is_forward) in [
                (None, false),
                (Some(EstablishedProxyRoute::Direct), false),
                (
                    Some(EstablishedProxyRoute::Tunnel(authenticated_proxy())),
                    false,
                ),
                (
                    Some(EstablishedProxyRoute::Tunnel(
                        "socks5://proxy.example:1080".parse().unwrap(),
                    )),
                    false,
                ),
                (
                    Some(EstablishedProxyRoute::Forward(
                        "socks5://proxy.example:1080".parse().unwrap(),
                    )),
                    false,
                ),
                (
                    Some(EstablishedProxyRoute::Forward(authenticated_proxy())),
                    true,
                ),
            ] {
                let stale_route = if is_forward {
                    EstablishedProxyRoute::Direct
                } else {
                    EstablishedProxyRoute::Forward(authenticated_proxy())
                };
                let mut challenge = observe_proxy_authorization(route);
                challenge.status = StatusCode::PROXY_AUTHENTICATION_REQUIRED;
                let result = HttpForwardProxyLayer::new()
                    .with_isolate_auth_error(isolate)
                    .into_layer(challenge)
                    .serve(request_with_stale_route(Some(stale_route)))
                    .await;
                if isolate && is_forward {
                    assert!(matches!(
                        result
                            .unwrap_err()
                            .downcast_ref::<HttpForwardProxyAuthRequired>(),
                        Some(HttpForwardProxyAuthRequired),
                    ));
                } else {
                    let response = result.unwrap();
                    assert_eq!(response.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);
                    assert_eq!(
                        response.headers()["proxy-authenticate"],
                        "Basic realm=upstream",
                    );
                }
            }
        }
    }
}
