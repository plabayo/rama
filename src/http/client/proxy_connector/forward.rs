use crate::{
    Service,
    error::BoxError,
    extensions::{Extensions, ExtensionsRef},
    http::{
        Request, Response, client::proxy::HttpForwardRoute,
        layer::remove_header::remove_proxy_auth_request_headers,
    },
    net::{
        ProtocolInputExt,
        client::{
            ConnectionError, ConnectorService, EstablishedClientConnection, ProxySelector as _,
        },
    },
    telemetry::tracing,
};

/// Reach the origin of a request over the HTTP connection to the proxy forwarding it, or
/// over a connection to the origin itself.
///
/// A forwarded request is served by `forward`, every other one by `origin`. Use
/// [`HttpForwardProxyConnector`] on its own to require a forwarded request instead.
///
/// [`HttpForwardProxyConnector`]: crate::http::client::proxy::HttpForwardProxyConnector
#[derive(Debug, Clone)]
pub struct MaybeForwardedConnector<O, F> {
    origin: O,
    forward: F,
}

impl<O, F> MaybeForwardedConnector<O, F> {
    /// Create a new [`MaybeForwardedConnector`] over the connector towards origins and the
    /// one forwarding over HTTP proxies.
    pub const fn new(origin: O, forward: F) -> Self {
        Self { origin, forward }
    }
}

impl<O, F, Input, Origin, Forward> Service<Input> for MaybeForwardedConnector<O, F>
where
    O: ConnectorService<Input, Connection = Origin>,
    F: ConnectorService<Input, Connection = Forward>,
    Origin: Send + ExtensionsRef + 'static,
    Forward: Send + ExtensionsRef + 'static,
    Input: ProtocolInputExt + ExtensionsRef + Send + 'static,
{
    type Output = EstablishedClientConnection<MaybeForwardedConnection<Origin, Forward>, Input>;
    type Error = ConnectionError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        if HttpForwardRoute.is_proxied(&input) {
            tracing::trace!("maybe forwarded: a proxy forwards this request");
            let EstablishedClientConnection { input, conn } = self.forward.connect(input).await?;
            return Ok(EstablishedClientConnection {
                input,
                conn: MaybeForwardedConnection::Forward { conn },
            });
        }
        let EstablishedClientConnection { input, conn } = self.origin.connect(input).await?;
        Ok(EstablishedClientConnection {
            input,
            conn: MaybeForwardedConnection::Origin { conn },
        })
    }
}

/// The HTTP connection a [`MaybeForwardedConnector`] established, to the origin of a request
/// or to the proxy forwarding it.
#[derive(Debug, Clone)]
pub enum MaybeForwardedConnection<O, F> {
    /// Established towards the origin itself.
    Origin { conn: O },
    /// Established towards the proxy which forwards the request.
    Forward { conn: F },
}

impl<O: ExtensionsRef, F: ExtensionsRef> ExtensionsRef for MaybeForwardedConnection<O, F> {
    fn extensions(&self) -> &Extensions {
        match self {
            Self::Origin { conn } => conn.extensions(),
            Self::Forward { conn } => conn.extensions(),
        }
    }
}

impl<O, F, Body> Service<Request<Body>> for MaybeForwardedConnection<O, F>
where
    O: Service<Request<Body>, Output = Response, Error: Into<BoxError>>,
    F: Service<Request<Body>, Output = Response, Error: Into<BoxError>>,
    Body: Send + 'static,
{
    type Output = Response;
    type Error = BoxError;

    async fn serve(&self, mut request: Request<Body>) -> Result<Self::Output, Self::Error> {
        match self {
            Self::Origin { conn } => {
                // A Proxy-Authorization field belongs to an HTTP proxy hop. This connection
                // has none: it reaches the origin, directly or through a tunnel that is
                // already open. Inside EasyHttpWebClient its ConnectionEgress already keeps
                // the field off this connection; this guards the connector on its own.
                remove_proxy_auth_request_headers(request.headers_mut());
                conn.serve(request).await.map_err(Into::into)
            }
            Self::Forward { conn } => conn.serve(request).await.map_err(Into::into),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        extensions::Extension,
        http::{
            Body, StatusCode, client::proxy::HttpForwardProxyConnector,
            header::PROXY_AUTHORIZATION, layer::forward_proxy::HttpForwardProxyAuthRequired,
            proxy::PlaintextHttpProxyMode,
        },
        net::{
            Protocol,
            address::HostWithPort,
            client::{ConnectRequest, ConnectionErrorKind, EstablishedProxyRoute, ProxyRoute},
        },
        service::service_fn,
    };
    use std::convert::Infallible;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Extension)]
    struct Arm(&'static str);

    #[derive(Debug, Clone, ExtensionsRef)]
    struct Arrival {
        extensions: Extensions,
        status: StatusCode,
    }

    impl Service<Request> for Arrival {
        type Output = Response;
        type Error = Infallible;

        async fn serve(&self, request: Request) -> Result<Self::Output, Self::Error> {
            let mut response = Response::builder()
                .status(self.status)
                .header("proxy-authenticate", "Basic realm=upstream")
                .body(Body::empty())
                .unwrap();
            if let Some(auth) = request.headers().get(PROXY_AUTHORIZATION) {
                response.headers_mut().insert("x-auth", auth.clone());
            }
            Ok(response)
        }
    }

    fn arm(name: &'static str) -> impl ConnectorService<ConnectRequest, Connection = Arrival> {
        arm_answering(name, StatusCode::OK)
    }

    fn arm_answering(
        name: &'static str,
        status: StatusCode,
    ) -> impl ConnectorService<ConnectRequest, Connection = Arrival> {
        service_fn(move |input: ConnectRequest| async move {
            let extensions = Extensions::new();
            extensions.insert(Arm(name));
            Ok::<_, ConnectionError>(EstablishedClientConnection {
                input,
                conn: Arrival { extensions, status },
            })
        })
    }

    fn plaintext(route: Option<&str>, mode: Option<PlaintextHttpProxyMode>) -> ConnectRequest {
        let input = ConnectRequest::new(HostWithPort::try_from("origin.example:80").unwrap())
            .with_application_protocol(Protocol::HTTP);
        if let Some(route) = route {
            input
                .extensions
                .insert(ProxyRoute::Proxy(route.parse().unwrap()));
        }
        if let Some(mode) = mode {
            input.extensions.insert(mode);
        }
        input
    }

    #[tokio::test]
    async fn only_a_forwarded_request_reaches_the_forward_arm() {
        let connector = MaybeForwardedConnector::new(arm("origin"), arm("forward"));
        for (input, expected) in [
            (plaintext(None, None), "origin"),
            (
                plaintext(Some("http://proxy.example:8080"), None),
                "forward",
            ),
            (
                plaintext(
                    Some("http://proxy.example:8080"),
                    Some(PlaintextHttpProxyMode::Tunnel),
                ),
                "origin",
            ),
            (
                plaintext(Some("socks5://proxy.example:1080"), None),
                "origin",
            ),
        ] {
            let established = connector.connect(input).await.unwrap();
            assert_eq!(
                established.conn.extensions().get_ref::<Arm>(),
                Some(&Arm(expected)),
            );
        }
    }

    #[tokio::test]
    async fn proxy_credentials_never_travel_on_a_connection_to_the_origin() {
        let connector = MaybeForwardedConnector::new(arm("origin"), arm("forward"));
        let request = || {
            Request::builder()
                .uri("http://origin.example/path")
                .header(PROXY_AUTHORIZATION, "Basic bWFudWFs")
                .body(Body::empty())
                .unwrap()
        };

        let origin = connector.connect(plaintext(None, None)).await.unwrap();
        let response = origin.conn.serve(request()).await.unwrap();
        assert!(response.headers().get("x-auth").is_none());

        let forward = connector
            .connect(plaintext(Some("http://proxy.example:8080"), None))
            .await
            .unwrap();
        let response = forward.conn.serve(request()).await.unwrap();
        assert_eq!(response.headers()["x-auth"], "Basic bWFudWFs");
    }

    #[tokio::test]
    async fn auth_challenge_is_isolated_only_for_an_established_forward_route() {
        let challenge = || arm_answering("challenge", StatusCode::PROXY_AUTHENTICATION_REQUIRED);
        let proxy = "http://proxy.example:8080";
        let request = |stale: EstablishedProxyRoute| {
            let request = Request::builder()
                .uri("http://origin.example/resource")
                .body(Body::empty())
                .unwrap();
            request.extensions().insert(stale);
            request
        };

        for isolate in [false, true] {
            let connector = MaybeForwardedConnector::new(
                challenge(),
                HttpForwardProxyConnector::new(challenge()).with_isolate_auth_error(isolate),
            );
            for (input, is_forward) in [
                (plaintext(None, None), false),
                (plaintext(Some("socks5://proxy.example:1080"), None), false),
                (
                    plaintext(Some(proxy), Some(PlaintextHttpProxyMode::Tunnel)),
                    false,
                ),
                (plaintext(Some(proxy), None), true),
            ] {
                // Whatever the request claims about its connection, the established route
                // decides.
                let stale = if is_forward {
                    EstablishedProxyRoute::Direct
                } else {
                    EstablishedProxyRoute::Forward(proxy.parse().unwrap())
                };
                let established = connector.connect(input).await.unwrap();
                let result = established.conn.serve(request(stale)).await;

                if isolate && is_forward {
                    let error = result.unwrap_err();
                    assert!(
                        error
                            .downcast_ref::<HttpForwardProxyAuthRequired>()
                            .is_some(),
                        "{error:?}"
                    );
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

    #[tokio::test]
    async fn a_socks5_route_is_never_a_forwarded_one() {
        let connector =
            HttpForwardProxyConnector::new(arm("forward")).with_isolate_auth_error(true);
        let error = connector
            .connect(plaintext(Some("socks5://proxy.example:1080"), None))
            .await
            .unwrap_err();

        assert_eq!(error.kind(), ConnectionErrorKind::InvalidInput);
    }
}
