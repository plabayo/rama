use super::verify_proxy_tls;
use rama_core::{
    Service,
    error::{BoxError, BoxErrorExt as _},
    extensions::{Extensions, ExtensionsRef},
    telemetry::tracing,
};
use rama_http::layer::forward_proxy::HttpForwardProxyAuthRequired;
use rama_http_headers::{HeaderMapExt as _, ProxyAuthorization};
use rama_http_types::{HeaderMap, Request, Response, StatusCode, proxy::PlaintextHttpProxyMode};
use rama_net::{
    ProtocolInputExt,
    address::ProxyAddress,
    client::{
        ConnectRequest, ConnectionError, ConnectionErrorKind, ConnectorService, ConnectorTarget,
        EstablishedClientConnection, EstablishedProxyRoute, ProxyRoute, connect_to_proxy,
        proxy_http_version,
    },
    http::{TargetHttpVersion, Version},
    user::ProxyCredential,
};
use rama_utils::macros::{define_inner_service_accessors, generate_set_and_with};

/// The proxy which forwards `input` rather than tunnel it, if one does.
///
/// Forwarding is for plaintext HTTP only, it is the request's to refuse with
/// [`PlaintextHttpProxyMode::Tunnel`], and an explicitly selected endpoint rules it out:
/// a forwarded request names its origin, it does not reach a chosen address.
pub fn forwarding_proxy<Input>(input: &Input) -> Option<&ProxyAddress>
where
    Input: ProtocolInputExt + ExtensionsRef + ?Sized,
{
    let proxy = input
        .extensions()
        .get_ref::<ProxyRoute>()
        .and_then(ProxyRoute::proxy_address)
        .filter(|proxy| proxy.protocol.is_http())?;
    let forward = !input.extensions().contains::<ConnectorTarget>()
        && input
            .extensions()
            .get_ref::<PlaintextHttpProxyMode>()
            .copied()
            .unwrap_or_default()
            .should_forward(input.target_protocol());
    forward.then_some(proxy)
}

/// A connector which reaches the origin of a forwarded request over the HTTP connection to
/// its proxy: the proxy plays origin for it, and the request names its own origin.
///
/// A forwarded route is required: any other input fails. Pair it with a
/// [`MaybeProxiedConnector`] over [`HttpForwardRoute`] to reach an origin of its own instead.
///
/// The inner service is the connector towards HTTP proxies, the same one
/// [`HttpConnectProxyConnector`] tunnels over: it receives its own [`ConnectRequest`]
/// addressed at the proxy and answers with an HTTP connection to it, which this connector
/// hands out as the connection of the request. Several origins forwarded through one proxy
/// share that connection when it can carry them.
///
/// [`MaybeProxiedConnector`]: rama_net::client::MaybeProxiedConnector
/// [`HttpForwardRoute`]: super::HttpForwardRoute
/// [`HttpConnectProxyConnector`]: super::layer::HttpConnectProxyConnector
#[derive(Debug, Clone)]
pub struct HttpForwardProxyConnector<S> {
    inner: S,
    proxy_auth: bool,
    isolate_auth_error: bool,
}

impl<S> HttpForwardProxyConnector<S> {
    /// Create an [`HttpForwardProxyConnector`] over the connector towards HTTP proxies.
    pub const fn new(inner: S) -> Self {
        Self {
            inner,
            proxy_auth: true,
            isolate_auth_error: false,
        }
    }

    generate_set_and_with! {
        /// Send the credentials of a forwarded request's own route to the proxy; enabled by
        /// default. Disabling it only disables insertion: a header the request supplies
        /// itself still travels, for manual and challenge-driven authentication.
        pub fn proxy_auth(mut self, enabled: bool) -> Self {
            self.proxy_auth = enabled;
            self
        }
    }

    generate_set_and_with! {
        /// Turn a proxy's `407` into [`HttpForwardProxyAuthRequired`] instead of answering
        /// with it, so an intermediary never hands one proxy's challenge to its own client.
        pub fn isolate_auth_error(mut self, enabled: bool) -> Self {
            self.isolate_auth_error = enabled;
            self
        }
    }

    define_inner_service_accessors!();
}

/// The request travels on the connection to the proxy, so an explicit origin version that
/// the proxy does not speak has no second hop to be met on.
fn check_forwarded_version(
    demanded: Option<Version>,
    proxy_version: Version,
) -> Result<(), ConnectionError> {
    match demanded {
        Some(demanded) if demanded != proxy_version => Err(ConnectionError::local(
            BoxError::from_static_str("a forward proxy cannot carry the requested HTTP version"),
            ConnectionErrorKind::InvalidInput,
        )
        .context_debug_field("requested_version", demanded)
        .context_debug_field("proxy_version", proxy_version)),
        _ => Ok(()),
    }
}

impl<S, Input> Service<Input> for HttpForwardProxyConnector<S>
where
    S: ConnectorService<ConnectRequest, Connection: ExtensionsRef>,
    Input: ProtocolInputExt + ExtensionsRef + Send + 'static,
{
    type Output = EstablishedClientConnection<HttpForwardProxyConnection<S::Connection>, Input>;
    type Error = ConnectionError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let Some(proxy) = forwarding_proxy(&input).cloned() else {
            return Err(ConnectionError::local(
                BoxError::from_static_str(
                    "http forward proxy connector: no forwarded route is requested",
                ),
                ConnectionErrorKind::InvalidInput,
            ));
        };
        let demanded = input
            .extensions()
            .get_ref::<TargetHttpVersion>()
            .map(|target| target.0);
        if let Some(version) = proxy.protocol.http_version() {
            check_forwarded_version(demanded, version)?;
        }

        let conn = connect_to_proxy(&self.inner, &proxy, input.extensions()).await?;
        verify_proxy_tls(&proxy, conn.extensions())?;
        let version = proxy_http_version(&proxy, &conn);
        check_forwarded_version(demanded, version)?;

        tracing::trace!(
            server.address = %proxy.address.host,
            server.port = proxy.address.port,
            "http forward proxy connector: forwarding over the connection to the proxy",
        );

        // An HTTP/1 request-target is encoded from the route of the connection it travels
        // on. The connection shares the extensions of the stream below it, which a transport
        // connector claims as direct, so this route must shadow that claim. Credentials stay
        // off it, as every user of the proxy shares the connection; they are the request's,
        // from its own route.
        conn.extensions()
            .insert(EstablishedProxyRoute::Forward(ProxyAddress {
                credential: None,
                ..proxy
            }));
        input.extensions().insert(TargetHttpVersion(version));

        let extensions = conn.extensions().fork();

        Ok(EstablishedClientConnection {
            input,
            conn: HttpForwardProxyConnection {
                inner: conn,
                extensions,
                proxy_auth: self.proxy_auth,
                isolate_auth_error: self.isolate_auth_error,
            },
        })
    }
}

/// The connection of a request its proxy forwards, as [`HttpForwardProxyConnector`] hands it
/// out: the HTTP connection to the proxy, which rewrites every request it carries for that
/// proxy.
#[derive(Debug, Clone, ExtensionsRef)]
pub struct HttpForwardProxyConnection<S> {
    inner: S,
    #[extensions_ref]
    extensions: Extensions,
    proxy_auth: bool,
    isolate_auth_error: bool,
}

impl<S> HttpForwardProxyConnection<S> {
    define_inner_service_accessors!();
}

impl<S, Body> Service<Request<Body>> for HttpForwardProxyConnection<S>
where
    S: Service<Request<Body>, Output = Response, Error: Into<BoxError>> + ExtensionsRef,
    Body: Send + 'static,
{
    type Output = Response;
    type Error = BoxError;

    async fn serve(&self, mut request: Request<Body>) -> Result<Self::Output, Self::Error> {
        if self.proxy_auth {
            // The connection is shared by every origin forwarded through this proxy, so the
            // credentials are the request's own, from the route it asked for.
            let credential = request
                .extensions()
                .get_ref::<ProxyRoute>()
                .and_then(ProxyRoute::proxy_address)
                .and_then(|proxy| proxy.credential.clone());
            authorize(request.headers_mut(), credential);
        }
        let response = self.inner.serve(request).await.map_err(Into::into)?;
        if self.isolate_auth_error && response.status() == StatusCode::PROXY_AUTHENTICATION_REQUIRED
        {
            tracing::debug!("isolating authentication challenge returned by HTTP forward proxy");
            return Err(HttpForwardProxyAuthRequired.into());
        }
        Ok(response)
    }
}

fn authorize(headers: &mut HeaderMap, credential: Option<ProxyCredential>) {
    match credential {
        Some(ProxyCredential::Basic(basic)) => headers.typed_insert(ProxyAuthorization(basic)),
        Some(ProxyCredential::Bearer(bearer)) => headers.typed_insert(ProxyAuthorization(bearer)),
        // An explicitly supplied header stays, for manual and challenge-driven
        // authentication of a route without a credential of its own.
        None => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_core::{
        extensions::{Egress, Extensions},
        service::service_fn,
    };
    use rama_http_types::{
        Body, HeaderValue, Version, header::PROXY_AUTHORIZATION, proto::h1::head,
    };
    use rama_net::{
        address::HostWithPort,
        client::{ConnectRequest, ProxyRoute},
    };
    use std::{convert::Infallible, sync::Arc};

    /// A connection to a proxy which answers `status` and reports back how the request
    /// looked on the wire: its HTTP/1 request-target and its `Proxy-Authorization`.
    #[derive(Debug, Clone, ExtensionsRef)]
    struct ProxyConnection {
        extensions: Extensions,
        status: StatusCode,
    }

    impl Service<Request> for ProxyConnection {
        type Output = Response;
        type Error = Infallible;

        async fn serve(&self, request: Request) -> Result<Self::Output, Self::Error> {
            // The h1 encoder reads the route of the connection the request travels on.
            request.extensions().insert(Egress(self.extensions.clone()));
            let mut target = Vec::new();
            head::encode_request_target(
                request.method(),
                request.uri(),
                request.extensions(),
                &mut target,
            )
            .unwrap();
            let mut response = Response::builder()
                .status(self.status)
                .header("x-target", HeaderValue::from_bytes(&target).unwrap())
                .body(Body::empty())
                .unwrap();
            if let Some(auth) = request.headers().get(PROXY_AUTHORIZATION) {
                response.headers_mut().insert("x-auth", auth.clone());
            }
            Ok(response)
        }
    }

    fn proxy_connector(
        status: StatusCode,
        dialed: Arc<parking_lot::Mutex<Vec<ConnectRequest>>>,
    ) -> HttpForwardProxyConnector<
        impl ConnectorService<ConnectRequest, Connection = ProxyConnection>,
    > {
        HttpForwardProxyConnector::new(service_fn(move |input: ConnectRequest| {
            let dialed = dialed.clone();
            async move {
                let conn = ProxyConnection {
                    extensions: Extensions::new(),
                    status,
                };
                dialed.lock().push(input.clone());
                Ok::<_, ConnectionError>(EstablishedClientConnection { input, conn })
            }
        }))
    }

    fn forwarded(proxy: &str) -> ConnectRequest {
        let input = ConnectRequest::new(HostWithPort::try_from("origin.example:80").unwrap())
            .with_application_protocol(rama_net::Protocol::HTTP);
        input
            .extensions
            .insert(ProxyRoute::Proxy(proxy.parse().unwrap()));
        input
    }

    fn request() -> Request {
        Request::builder()
            .uri("http://origin.example/resource")
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn a_forwarded_request_is_sent_in_absolute_form_with_its_own_credentials() {
        let dialed = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let connector = proxy_connector(StatusCode::OK, dialed.clone());

        let input = forwarded("http://alice:secret@proxy.example:8080");
        let route = input.extensions.get_ref::<ProxyRoute>().unwrap().clone();
        let established = connector.serve(input).await.unwrap();

        let request = request();
        request.extensions().insert(route);
        let response = established.conn.serve(request).await.unwrap();

        assert_eq!(
            response.headers()["x-target"],
            "http://origin.example/resource"
        );
        assert_eq!(response.headers()["x-auth"], "Basic YWxpY2U6c2VjcmV0");
        assert_eq!(dialed.lock().len(), 1);
        assert_eq!(
            dialed.lock()[0].authority,
            HostWithPort::try_from("proxy.example:8080").unwrap()
        );
    }

    #[tokio::test]
    async fn the_forwarded_route_shadows_the_claim_of_the_stream_below() {
        let connector = HttpForwardProxyConnector::new(service_fn(|input: ConnectRequest| async {
            let extensions = Extensions::new();
            extensions.insert(EstablishedProxyRoute::Direct);
            Ok::<_, ConnectionError>(EstablishedClientConnection {
                input,
                conn: ProxyConnection {
                    extensions,
                    status: StatusCode::OK,
                },
            })
        }));
        let established = connector
            .serve(forwarded("http://proxy.example:8080"))
            .await
            .unwrap();

        assert_eq!(
            established
                .conn
                .extensions()
                .get_ref::<EstablishedProxyRoute>()
                .and_then(EstablishedProxyRoute::proxy_address)
                .map(|proxy| proxy.address.clone()),
            Some("proxy.example:8080".try_into().unwrap()),
        );
        let response = established.conn.serve(request()).await.unwrap();
        assert_eq!(
            response.headers()["x-target"],
            "http://origin.example/resource"
        );
    }

    #[tokio::test]
    async fn the_shared_connection_carries_no_credentials_of_its_own() {
        let connector = proxy_connector(StatusCode::OK, Arc::default());
        let established = connector
            .serve(forwarded("http://alice:secret@proxy.example:8080"))
            .await
            .unwrap();

        assert_eq!(
            established
                .conn
                .extensions()
                .get_ref::<EstablishedProxyRoute>()
                .and_then(EstablishedProxyRoute::proxy_address)
                .map(|proxy| proxy.credential.clone()),
            Some(None),
        );
        // A request without a route of its own sends no credentials either.
        let response = established.conn.serve(request()).await.unwrap();
        assert!(response.headers().get("x-auth").is_none());
    }

    #[tokio::test]
    async fn the_proxy_decides_the_version_a_forwarded_request_travels_in() {
        for version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
            let dialed = Arc::new(parking_lot::Mutex::new(Vec::new()));
            let connector = proxy_connector(StatusCode::OK, dialed.clone());

            let input = forwarded("http://proxy.example:8080");
            input.extensions.insert(ProxyRoute::Proxy(
                "http://proxy.example:8080"
                    .parse::<ProxyAddress>()
                    .unwrap()
                    .with_http_version(version),
            ));
            let established = connector.serve(input).await.unwrap();

            assert_eq!(
                established
                    .input
                    .extensions
                    .get_ref::<TargetHttpVersion>()
                    .map(|target| target.0),
                Some(version),
                "{version:?}",
            );
            assert_eq!(
                dialed.lock()[0]
                    .extensions
                    .get_ref::<TargetHttpVersion>()
                    .map(|target| target.0),
                Some(version),
                "{version:?}",
            );
        }
    }

    #[tokio::test]
    async fn a_version_the_proxy_cannot_speak_is_refused() {
        let connector = proxy_connector(StatusCode::OK, Arc::default());
        let input = forwarded("http://proxy.example:8080");
        input.extensions.insert(TargetHttpVersion(Version::HTTP_2));
        let error = connector.serve(input).await.unwrap_err();

        assert_eq!(error.kind(), ConnectionErrorKind::InvalidInput);
        assert!(
            format!("{error:?}").contains("cannot carry the requested HTTP version"),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn anything_but_a_forwarded_route_is_refused() {
        let connector = proxy_connector(StatusCode::OK, Arc::default());
        for input in [
            ConnectRequest::new(HostWithPort::try_from("origin.example:80").unwrap()),
            // A tunnel, not a forward: the request asked for one.
            {
                let input = forwarded("http://proxy.example:8080");
                input.extensions.insert(PlaintextHttpProxyMode::Tunnel);
                input
            },
            // SOCKS5 forwards nothing.
            forwarded("socks5://proxy.example:1080"),
        ] {
            let error = connector.serve(input).await.unwrap_err();
            assert_eq!(error.kind(), ConnectionErrorKind::InvalidInput);
            assert!(
                format!("{error:?}").contains("no forwarded route is requested"),
                "{error:?}"
            );
        }
    }

    #[tokio::test]
    async fn an_isolated_challenge_never_reaches_the_client() {
        let input = forwarded("http://proxy.example:8080");
        let exposed = proxy_connector(StatusCode::PROXY_AUTHENTICATION_REQUIRED, Arc::default())
            .serve(input)
            .await
            .unwrap()
            .conn
            .serve(request())
            .await
            .unwrap();
        assert_eq!(exposed.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);

        let input = forwarded("http://proxy.example:8080");
        let error = proxy_connector(StatusCode::PROXY_AUTHENTICATION_REQUIRED, Arc::default())
            .with_isolate_auth_error(true)
            .serve(input)
            .await
            .unwrap()
            .conn
            .serve(request())
            .await
            .unwrap_err();
        assert!(
            error
                .downcast_ref::<HttpForwardProxyAuthRequired>()
                .is_some(),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn insertion_can_be_disabled_without_dropping_a_manual_header() {
        let input = forwarded("http://alice:secret@proxy.example:8080");
        let route = input.extensions.get_ref::<ProxyRoute>().unwrap().clone();
        let established = proxy_connector(StatusCode::OK, Arc::default())
            .with_proxy_auth(false)
            .serve(input)
            .await
            .unwrap();

        let request = Request::builder()
            .uri("http://origin.example/resource")
            .header(PROXY_AUTHORIZATION, "Basic bWFudWFs")
            .body(Body::empty())
            .unwrap();
        request.extensions().insert(route);
        let response = established.conn.serve(request).await.unwrap();

        assert_eq!(response.headers()["x-auth"], "Basic bWFudWFs");
    }
}
