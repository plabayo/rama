use std::{
    net::{IpAddr, SocketAddr},
    sync::{Arc, RwLock},
};

use rama::{
    Layer, Service,
    error::{BoxError, BoxErrorExt as _, ErrorExt as _},
    extensions::ExtensionsRef,
    http::Request,
    layer::IntoErrLayer,
    net::{
        address::ProxyAddress,
        client::{
            BypassRules, ConnectRequest, ProxyAddressLayer, ProxyBypassLayer, ProxyRoute,
            ProxyRoutes, ProxyRoutesLayer,
        },
    },
};

type ListenerAddresses = Arc<RwLock<Arc<[SocketAddr]>>>;

/// Upstream route configuration shared by HTTP and connector stacks.
#[derive(Debug, Clone)]
pub(super) struct UpstreamProxyConfig {
    explicit: Option<ProxyAddress>,
    system: bool,
    forward_proxy_auth: bool,
    tunnel_plaintext_http: bool,
    bypass: ProxyBypassLayer,
    listener_addresses: ListenerAddresses,
}

impl UpstreamProxyConfig {
    pub(super) fn new(
        explicit: Option<ProxyAddress>,
        system: bool,
        bypass: &[String],
    ) -> Result<Self, BoxError> {
        Ok(Self {
            explicit,
            system,
            forward_proxy_auth: true,
            tunnel_plaintext_http: false,
            bypass: ProxyBypassLayer::new(BypassRules::from_no_proxy(bypass.join(","))?),
            listener_addresses: Arc::new(RwLock::new(Arc::from([]))),
        })
    }

    pub(super) fn with_forward_proxy_auth(mut self, enabled: bool) -> Self {
        self.forward_proxy_auth = enabled;
        self
    }

    pub(super) fn forward_proxy_auth(&self) -> bool {
        self.forward_proxy_auth
    }

    pub(super) fn with_tunnel_plaintext_http(mut self, enabled: bool) -> Self {
        self.tunnel_plaintext_http = enabled;
        self
    }

    pub(super) fn tunnel_plaintext_http(&self) -> bool {
        self.tunnel_plaintext_http
    }

    pub(super) fn set_listener_addresses(&self, addresses: impl IntoIterator<Item = SocketAddr>) {
        let addresses: Arc<[SocketAddr]> = addresses.into_iter().collect();
        match self.listener_addresses.write() {
            Ok(mut current) => *current = addresses,
            Err(poisoned) => *poisoned.into_inner() = addresses,
        }
    }

    pub(super) fn http_service<S>(
        &self,
        inner: S,
    ) -> impl Service<Request, Output = S::Output, Error = BoxError> + Clone + use<S>
    where
        S: Service<Request> + Clone,
        S::Error: Into<BoxError>,
    {
        (
            self.bypass.clone(),
            ProxyAddressLayer::maybe(self.explicit.clone()),
            self.system.then(crate::cmd::pac::system_proxy_layer),
            ProxyRoutesLayer::new(),
            RejectSelfProxyLayer::new(self.listener_addresses.clone()),
            IntoErrLayer::into_box_error(),
        )
            .into_layer(inner)
    }

    pub(super) fn connector_service<S>(
        &self,
        inner: S,
    ) -> impl Service<ConnectRequest, Output = S::Output, Error = BoxError> + Clone + use<S>
    where
        S: Service<ConnectRequest> + Clone,
        S::Error: Into<BoxError>,
    {
        (
            self.bypass.clone(),
            ProxyAddressLayer::maybe(self.explicit.clone()),
            self.system
                .then(|| crate::cmd::pac::system_proxy_layer().into_connect_layer()),
            ProxyRoutesLayer::new(),
            RejectSelfProxyLayer::new(self.listener_addresses.clone()),
            IntoErrLayer::into_box_error(),
        )
            .into_layer(inner)
    }
}

#[derive(Clone)]
struct RejectSelfProxyLayer {
    listener_addresses: ListenerAddresses,
}

impl RejectSelfProxyLayer {
    fn new(listener_addresses: ListenerAddresses) -> Self {
        Self { listener_addresses }
    }
}

impl<S> Layer<S> for RejectSelfProxyLayer {
    type Service = RejectSelfProxyService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RejectSelfProxyService {
            inner,
            listener_addresses: self.listener_addresses.clone(),
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        RejectSelfProxyService {
            inner,
            listener_addresses: self.listener_addresses,
        }
    }
}

#[derive(Clone)]
struct RejectSelfProxyService<S> {
    inner: S,
    listener_addresses: ListenerAddresses,
}

impl<S, Input> Service<Input> for RejectSelfProxyService<S>
where
    S: Service<Input>,
    S::Error: Into<BoxError>,
    Input: ExtensionsRef + Send + 'static,
{
    type Output = S::Output;
    type Error = BoxError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let listeners = match self.listener_addresses.read() {
            Ok(addresses) => addresses.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        let route_is_self = input
            .extensions()
            .get_ref::<ProxyRoute>()
            .is_some_and(|route| proxy_route_targets_listener(route, &listeners));
        let routes_contain_self =
            input
                .extensions()
                .get_ref::<ProxyRoutes>()
                .is_some_and(|routes| {
                    routes
                        .as_slice()
                        .iter()
                        .any(|route| proxy_route_targets_listener(route, &listeners))
                });
        if route_is_self || routes_contain_self {
            return Err(BoxError::from_static_str(
                "upstream proxy resolves to this proxy's own listener",
            )
            .context("reject recursive upstream proxy route"));
        }
        self.inner.serve(input).await.map_err(Into::into)
    }
}

fn proxy_route_targets_listener(route: &ProxyRoute, listeners: &[SocketAddr]) -> bool {
    let ProxyRoute::Proxy(proxy) = route else {
        return false;
    };
    let proxy_host = proxy.address.host.view();
    listeners.iter().any(|listener| {
        if listener.port() != proxy.address.port {
            return false;
        }
        match proxy_host.try_as_ip() {
            Ok(proxy_ip) => socket_ip_overlaps(proxy_ip, listener.ip()),
            Err(_) if proxy_host.is_loopback() => {
                listener.ip().is_loopback() || listener.ip().is_unspecified()
            }
            Err(_) => false,
        }
    })
}

fn socket_ip_overlaps(left: IpAddr, right: IpAddr) -> bool {
    use rama::net::address::ip::IntoCanonicalIpAddr as _;

    let left = left.into_canonical_ip_addr();
    let right = right.into_canonical_ip_addr();
    left.is_ipv4() == right.is_ipv4()
        && (left == right || left.is_unspecified() || right.is_unspecified())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama::{
        http::Body,
        net::client::{ConnectRequest, ProxyRoute},
        service::service_fn,
    };

    fn route_service<Input>()
    -> impl Service<Input, Output = Option<ProxyRoute>, Error = BoxError> + Clone
    where
        Input: ExtensionsRef + Send + 'static,
    {
        service_fn(|input: Input| async move {
            Ok::<_, BoxError>(input.extensions().get_ref::<ProxyRoute>().cloned())
        })
    }

    #[tokio::test]
    async fn explicit_proxy_and_bypass_apply_to_http_requests() {
        let proxy: ProxyAddress = "http://127.0.0.1:3128".parse().unwrap();
        let config =
            UpstreamProxyConfig::new(Some(proxy.clone()), false, &["example.test".to_owned()])
                .unwrap();
        let service = config.http_service(route_service::<Request>());

        let proxied = service
            .serve(
                Request::builder()
                    .uri("http://other.test/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(proxied, Some(ProxyRoute::Proxy(proxy)));

        let bypassed = service
            .serve(
                Request::builder()
                    .uri("https://api.example.test/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bypassed, Some(ProxyRoute::Direct));
    }

    #[tokio::test]
    async fn explicit_proxy_applies_to_raw_connect_requests() {
        let proxy: ProxyAddress = "socks5h://127.0.0.1:1080".parse().unwrap();
        let service = UpstreamProxyConfig::new(Some(proxy.clone()), false, &[])
            .unwrap()
            .connector_service(route_service::<ConnectRequest>());
        let input = ConnectRequest::new("origin.example:443".parse().unwrap())
            .with_application_protocol(rama::net::Protocol::HTTPS);

        assert_eq!(
            service.serve(input).await.unwrap(),
            Some(ProxyRoute::Proxy(proxy))
        );
    }

    #[tokio::test]
    async fn existing_route_is_preserved_and_explicit_proxy_is_authoritative() {
        let proxy: ProxyAddress = "http://127.0.0.1:3128".parse().unwrap();
        let service = UpstreamProxyConfig::new(Some(proxy.clone()), false, &[])
            .unwrap()
            .http_service(route_service::<Request>());

        let routed = Request::builder()
            .uri("http://origin.test/")
            .extension(ProxyRoute::Direct)
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            service.serve(routed).await.unwrap(),
            Some(ProxyRoute::Direct)
        );

        let relative = Request::builder()
            .uri("/relative")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            service.serve(relative).await.unwrap(),
            Some(ProxyRoute::Proxy(proxy))
        );
    }

    #[tokio::test]
    async fn rejects_an_upstream_proxy_that_is_our_own_listener() {
        let proxy: ProxyAddress = "http://127.0.0.1:3128".parse().unwrap();
        let config = UpstreamProxyConfig::new(Some(proxy), false, &[]).unwrap();
        config.set_listener_addresses(["0.0.0.0:3128".parse().unwrap()]);
        let service = config.http_service(route_service::<Request>());

        let error = service
            .serve(
                Request::builder()
                    .uri("https://example.test/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap_err();

        assert!(error.to_string().contains("recursive upstream proxy route"));
    }
}
