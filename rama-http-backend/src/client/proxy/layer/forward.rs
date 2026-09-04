use rama_core::{Layer, Service, error::BoxError, extensions::ExtensionsRef, telemetry::tracing};
use rama_http_headers::{HeaderMapExt, ProxyAuthorization};
use rama_http_types::{
    Request, Response, StatusCode, header::PROXY_AUTHORIZATION, proxy::HttpProxyConnectionMode,
};
use rama_net::{client::ProxyRoute, user::ProxyCredential};

use super::HttpProxyError;

/// HTTP middleware for requests sent directly to an HTTP forward proxy.
///
/// The layer resolves [`HttpProxyConnectionMode`] and the selected
/// [`ProxyRoute`] from the wrapped connection. A request's
/// [`rama_core::extensions::Egress`] connection snapshot is a fallback for
/// wrappers that do not expose the connection extensions directly. This lets
/// the layer distinguish a real forward-proxy connection from direct, SOCKS,
/// and HTTP CONNECT-tunneled connections after route fallback and pool lookup
/// have completed.
///
/// Configured Basic or Bearer credentials are inserted by default. Call
/// [`Self::with_proxy_auth`] with `false` to opt out. A proxy-generated `407`
/// response is exposed by default for ordinary HTTP clients; intermediary
/// clients can enable [`Self::with_isolate_auth_error`] to turn it into
/// [`HttpProxyError::AuthRequired`] before any proxy response headers or body
/// reach their downstream peer.
///
/// Custom proxy connectors must publish both [`HttpProxyConnectionMode`] and
/// the selected [`ProxyRoute`] in their established connection extensions. A
/// missing marker is treated as [`HttpProxyConnectionMode::Direct`] so
/// credentials fail closed; a missing established route never falls back to
/// mutable request-side credentials.
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
        pub fn proxy_auth(mut self, enabled: bool) -> Self {
            self.proxy_auth = enabled;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Enable or disable isolation of a forward proxy's `407` response.
        ///
        /// When enabled, the response is dropped and
        /// [`HttpProxyError::AuthRequired`] is returned. This is intended for
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
        // request-provided mode describes intent, not what fallback and pool
        // selection actually established.
        let inner_extensions = self.inner.extensions();
        let established_extensions = if inner_extensions
            .get_ref::<HttpProxyConnectionMode>()
            .is_some()
        {
            Some(inner_extensions)
        } else {
            req.extensions().egress().map(|egress| &egress.0)
        };
        let proxy_mode = established_extensions
            .and_then(|extensions| extensions.get_ref::<HttpProxyConnectionMode>())
            .copied()
            .unwrap_or(HttpProxyConnectionMode::Direct);
        let http_proxy = established_extensions
            .and_then(|extensions| extensions.get_ref::<ProxyRoute>())
            .and_then(ProxyRoute::proxy_address)
            .filter(|proxy| {
                proxy
                    .protocol
                    .as_ref()
                    .is_none_or(|protocol| protocol.is_http())
            });

        // Shadow any caller-provided or stale request-side marker with the
        // established fact. Missing provenance is Direct by design.
        req.extensions().insert(proxy_mode);
        let is_forward_proxy = proxy_mode == HttpProxyConnectionMode::Forward;

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
            req.headers_mut().remove(PROXY_AUTHORIZATION);
        }

        let response = self.inner.serve(req).await.map_err(Into::into)?;
        if is_forward_proxy
            && self.isolate_auth_error
            && response.status() == StatusCode::PROXY_AUTHENTICATION_REQUIRED
        {
            tracing::debug!("isolating authentication challenge returned by HTTP forward proxy");
            return Err(HttpProxyError::AuthRequired.into());
        }

        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use core::convert::Infallible;

    use rama_core::extensions::{Egress, Extensions};
    use rama_http_types::{Body, HeaderValue, header::PROXY_AUTHORIZATION};
    use rama_net::{
        address::ProxyAddress,
        client::ProxyRoute,
        user::{Basic, Bearer, ProxyCredential},
    };

    use super::*;

    fn request_with(
        mode: Option<HttpProxyConnectionMode>,
        credential: Option<ProxyCredential>,
    ) -> Request {
        let mut proxy: ProxyAddress = "http://proxy.example:8080".parse().unwrap();
        proxy.credential = credential;
        let route = ProxyRoute::Proxy(proxy);
        let request = Request::builder()
            .uri("http://origin.example/resource")
            .header(PROXY_AUTHORIZATION, "Basic downstream-secret")
            .body(Body::empty())
            .unwrap();
        request.extensions().insert(route.clone());
        if let Some(mode) = mode {
            let egress = Extensions::default();
            egress.insert(mode);
            egress.insert(if mode == HttpProxyConnectionMode::Direct {
                ProxyRoute::Direct
            } else {
                route
            });
            request.extensions().insert(Egress(egress));
        }
        request
    }

    fn authenticated_request(mode: HttpProxyConnectionMode) -> Request {
        request_with(
            Some(mode),
            Some(ProxyCredential::Basic(
                Basic::try_from("upstream:secret").unwrap(),
            )),
        )
    }

    #[derive(Debug, Clone, Default)]
    struct ObserveProxyAuthorization {
        extensions: Extensions,
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
            let mut response = Response::new(Body::empty());
            if let Some(value) = request.headers().get(PROXY_AUTHORIZATION) {
                response
                    .headers_mut()
                    .insert("x-observed-auth", value.clone());
            }
            Ok::<_, Infallible>(response)
        }
    }

    fn observe_proxy_authorization() -> ObserveProxyAuthorization {
        ObserveProxyAuthorization::default()
    }

    fn observed_auth(response: &Response) -> Option<&HeaderValue> {
        response.headers().get("x-observed-auth")
    }

    #[tokio::test]
    async fn configured_credentials_override_existing_header_only_for_forward_connection() {
        let response = HttpForwardProxyLayer::new()
            .into_layer(observe_proxy_authorization())
            .serve(authenticated_request(HttpProxyConnectionMode::Forward))
            .await
            .unwrap();
        assert_eq!(
            observed_auth(&response).unwrap(),
            "Basic dXBzdHJlYW06c2VjcmV0"
        );

        let response = HttpForwardProxyLayer::new()
            .into_layer(observe_proxy_authorization())
            .serve(authenticated_request(HttpProxyConnectionMode::Direct))
            .await
            .unwrap();
        assert!(observed_auth(&response).is_none());

        let response = HttpForwardProxyLayer::new()
            .into_layer(observe_proxy_authorization())
            .serve(authenticated_request(HttpProxyConnectionMode::Tunnel))
            .await
            .unwrap();
        assert!(observed_auth(&response).is_none());
    }

    #[tokio::test]
    async fn reads_established_mode_directly_from_wrapped_connection() {
        let extensions = Extensions::default();
        extensions.insert(HttpProxyConnectionMode::Forward);
        let mut proxy: ProxyAddress = "http://proxy.example:8080".parse().unwrap();
        proxy.credential = Some(ProxyCredential::Basic(
            Basic::try_from("upstream:secret").unwrap(),
        ));
        extensions.insert(ProxyRoute::Proxy(proxy));
        let service = ObserveProxyAuthorization { extensions };
        let response = HttpForwardProxyLayer::new()
            .into_layer(service)
            .serve(request_with(
                None,
                Some(ProxyCredential::Basic(
                    Basic::try_from("upstream:secret").unwrap(),
                )),
            ))
            .await
            .unwrap();
        assert_eq!(
            observed_auth(&response).unwrap(),
            "Basic dXBzdHJlYW06c2VjcmV0"
        );
    }

    #[tokio::test]
    async fn credentials_are_bound_to_established_proxy_not_mutable_request_route() {
        let extensions = Extensions::default();
        extensions.insert(HttpProxyConnectionMode::Forward);
        let mut established_proxy: ProxyAddress = "http://proxy-a.example:8080".parse().unwrap();
        established_proxy.credential = Some(ProxyCredential::Basic(
            Basic::try_from("proxy-a:secret-a").unwrap(),
        ));
        extensions.insert(ProxyRoute::Proxy(established_proxy));

        let request = request_with(None, None);
        let mut mutated_proxy: ProxyAddress = "http://proxy-b.example:8080".parse().unwrap();
        mutated_proxy.credential = Some(ProxyCredential::Basic(
            Basic::try_from("proxy-b:secret-b").unwrap(),
        ));
        request
            .extensions()
            .insert(ProxyRoute::Proxy(mutated_proxy));

        let response = HttpForwardProxyLayer::new()
            .into_layer(ObserveProxyAuthorization { extensions })
            .serve(request)
            .await
            .unwrap();
        assert_eq!(
            observed_auth(&response).unwrap(),
            "Basic cHJveHktYTpzZWNyZXQtYQ=="
        );
        assert_ne!(
            observed_auth(&response).unwrap(),
            "Basic cHJveHktYjpzZWNyZXQtYg=="
        );
    }

    #[tokio::test]
    async fn proxy_auth_can_be_disabled() {
        let response = HttpForwardProxyLayer::new()
            .with_proxy_auth(false)
            .into_layer(observe_proxy_authorization())
            .serve(authenticated_request(HttpProxyConnectionMode::Forward))
            .await
            .unwrap();
        assert_eq!(observed_auth(&response).unwrap(), "Basic downstream-secret");

        let response = HttpForwardProxyLayer::new()
            .with_proxy_auth(false)
            .into_layer(observe_proxy_authorization())
            .serve(authenticated_request(HttpProxyConnectionMode::Tunnel))
            .await
            .unwrap();
        assert!(observed_auth(&response).is_none());
    }

    #[tokio::test]
    async fn bearer_credentials_are_applied_and_manual_auth_is_preserved_without_route_credentials()
    {
        let response = HttpForwardProxyLayer::new()
            .into_layer(observe_proxy_authorization())
            .serve(request_with(
                Some(HttpProxyConnectionMode::Forward),
                Some(ProxyCredential::Bearer(
                    Bearer::try_from("upstream-token").unwrap(),
                )),
            ))
            .await
            .unwrap();
        assert_eq!(observed_auth(&response).unwrap(), "Bearer upstream-token");

        let response = HttpForwardProxyLayer::new()
            .into_layer(observe_proxy_authorization())
            .serve(request_with(Some(HttpProxyConnectionMode::Forward), None))
            .await
            .unwrap();
        assert_eq!(observed_auth(&response).unwrap(), "Basic downstream-secret");
    }

    #[tokio::test]
    async fn established_direct_mode_fails_closed_and_shadows_a_request_marker() {
        let request = authenticated_request(HttpProxyConnectionMode::Direct);
        request
            .extensions()
            .insert(HttpProxyConnectionMode::Forward);
        let response = HttpForwardProxyLayer::new()
            .into_layer(observe_proxy_authorization())
            .serve(request)
            .await
            .unwrap();
        assert!(observed_auth(&response).is_none());
    }

    #[tokio::test]
    async fn missing_egress_mode_fails_closed() {
        let request = request_with(
            None,
            Some(ProxyCredential::Basic(
                Basic::try_from("upstream:secret").unwrap(),
            )),
        );
        request
            .extensions()
            .insert(HttpProxyConnectionMode::Forward);
        let response = HttpForwardProxyLayer::new()
            .into_layer(observe_proxy_authorization())
            .serve(request)
            .await
            .unwrap();
        assert!(observed_auth(&response).is_none());
    }

    #[tokio::test]
    async fn auth_challenge_is_exposed_by_default_and_optionally_isolated() {
        #[derive(Debug, Clone, Default)]
        struct Challenge {
            extensions: Extensions,
        }

        impl ExtensionsRef for Challenge {
            fn extensions(&self) -> &Extensions {
                &self.extensions
            }
        }

        impl Service<Request> for Challenge {
            type Output = Response;
            type Error = Infallible;

            async fn serve(&self, _: Request) -> Result<Self::Output, Self::Error> {
                Ok(Response::builder()
                    .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                    .header("proxy-authenticate", "Basic realm=upstream")
                    .body(Body::from("private upstream challenge"))
                    .unwrap())
            }
        }

        let challenge = Challenge::default;

        let response = HttpForwardProxyLayer::new()
            .into_layer(challenge())
            .serve(authenticated_request(HttpProxyConnectionMode::Forward))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);

        let error = HttpForwardProxyLayer::new()
            .with_isolate_auth_error(true)
            .into_layer(challenge())
            .serve(authenticated_request(HttpProxyConnectionMode::Forward))
            .await
            .unwrap_err();
        assert!(matches!(
            error.downcast_ref::<HttpProxyError>(),
            Some(HttpProxyError::AuthRequired)
        ));

        let response = HttpForwardProxyLayer::new()
            .with_isolate_auth_error(true)
            .into_layer(challenge())
            .serve(authenticated_request(HttpProxyConnectionMode::Direct))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);
    }
}
