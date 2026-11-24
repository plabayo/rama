use super::forwarding_proxy;
use rama_core::extensions::ExtensionsRef;
use rama_net::{
    ProtocolInputExt,
    client::{ProxiedRoute, ProxySelector},
};

/// Selects the inputs a proxy opens a tunnel for: every proxied route, except an HTTP proxy
/// which forwards the request instead.
///
/// A forwarded request has no tunnel to its origin, so a transport-level router keeps it on
/// its direct side; the connector above the HTTP connections serves it.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct HttpTunnelRoute;

impl HttpTunnelRoute {
    pub const fn new() -> Self {
        Self
    }
}

impl<Input> ProxySelector<Input> for HttpTunnelRoute
where
    Input: ProtocolInputExt + ExtensionsRef,
{
    fn is_proxied(&self, input: &Input) -> bool {
        ProxiedRoute::new().is_proxied(input) && forwarding_proxy(input).is_none()
    }
}

/// Selects the inputs an HTTP proxy forwards, as [`forwarding_proxy`] decides.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct HttpForwardRoute;

impl HttpForwardRoute {
    pub const fn new() -> Self {
        Self
    }
}

impl<Input> ProxySelector<Input> for HttpForwardRoute
where
    Input: ProtocolInputExt + ExtensionsRef,
{
    fn is_proxied(&self, input: &Input) -> bool {
        forwarding_proxy(input).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_core::{
        Service,
        extensions::{Extension, Extensions},
        service::service_fn,
    };
    use rama_http_types::{Request, Response, proxy::PlaintextHttpProxyMode};
    use rama_net::{
        Protocol,
        address::HostWithPort,
        client::{
            ConnectRequest, ConnectionError, ConnectorService, EstablishedClientConnection,
            MaybeProxiedConnector, ProxyRoute,
        },
    };
    use std::convert::Infallible;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Extension)]
    struct Arm(&'static str);

    #[derive(Debug, Clone, ExtensionsRef)]
    struct Arrival {
        extensions: Extensions,
    }

    impl Service<Request> for Arrival {
        type Output = Response;
        type Error = Infallible;

        async fn serve(&self, _: Request) -> Result<Self::Output, Self::Error> {
            panic!("only the selected arm is asserted")
        }
    }

    fn arm(name: &'static str) -> impl ConnectorService<ConnectRequest, Connection = Arrival> {
        service_fn(move |input: ConnectRequest| async move {
            let extensions = Extensions::new();
            extensions.insert(Arm(name));
            Ok::<_, ConnectionError>(EstablishedClientConnection {
                input,
                conn: Arrival { extensions },
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

    async fn selected<Sel>(selector: Sel, input: ConnectRequest) -> Arm
    where
        Sel: ProxySelector<ConnectRequest> + Send + Sync + 'static,
    {
        let connector = MaybeProxiedConnector::new(arm("direct"), arm("proxy"), selector);
        *connector
            .serve(input)
            .await
            .unwrap()
            .conn
            .extensions()
            .get_ref::<Arm>()
            .unwrap()
    }

    #[tokio::test]
    async fn every_proxy_route_but_a_forwarded_one_is_tunneled() {
        for (input, expected) in [
            (plaintext(None, None), "direct"),
            (
                plaintext(Some("socks5://proxy.example:1080"), None),
                "proxy",
            ),
            (
                plaintext(
                    Some("http://proxy.example:8080"),
                    Some(PlaintextHttpProxyMode::Tunnel),
                ),
                "proxy",
            ),
            // https origins are tunneled whatever the plaintext mode says.
            (
                {
                    let input =
                        ConnectRequest::new(HostWithPort::try_from("origin.example:443").unwrap())
                            .with_application_protocol(Protocol::HTTPS);
                    input.extensions.insert(ProxyRoute::Proxy(
                        "http://proxy.example:8080".parse().unwrap(),
                    ));
                    input
                },
                "proxy",
            ),
        ] {
            assert_eq!(selected(HttpTunnelRoute::new(), input).await, Arm(expected));
        }
    }

    #[tokio::test]
    async fn a_forwarded_request_is_never_tunneled() {
        let input = plaintext(Some("http://proxy.example:8080"), None);
        assert_eq!(selected(HttpTunnelRoute::new(), input).await, Arm("direct"));
    }

    #[tokio::test]
    async fn only_a_forwarded_request_reaches_the_forward_arm() {
        for (input, expected) in [
            (plaintext(None, None), "direct"),
            (plaintext(Some("http://proxy.example:8080"), None), "proxy"),
            (
                plaintext(
                    Some("http://proxy.example:8080"),
                    Some(PlaintextHttpProxyMode::Tunnel),
                ),
                "direct",
            ),
            (
                plaintext(Some("socks5://proxy.example:1080"), None),
                "direct",
            ),
        ] {
            assert_eq!(
                selected(HttpForwardRoute::new(), input).await,
                Arm(expected)
            );
        }
    }
}
