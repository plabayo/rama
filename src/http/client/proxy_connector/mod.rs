mod builder;
use builder::connect_udp_not_enabled;
pub(crate) use builder::{
    DefaultProxyConnectMethod, DefaultProxyConnectUdpMethod, DefaultProxyForwardMethod,
    DefaultProxyHttpConnector, DefaultProxySocksMethod,
};
#[doc(inline)]
pub use builder::{
    DefaultProxyConnector, ProxyAltSvcConnectionLayer, ProxyConnectUdpMethod,
    ProxyConnectUdpNotEnabled, ProxyConnectorBuilder, ProxyHttpStage, ProxyMethodBuilder,
    ProxyServiceConnector, ProxySocksMethod,
};

mod forward;
#[doc(inline)]
pub use forward::{MaybeForwardedConnection, MaybeForwardedConnector};

mod not_enabled;
#[doc(inline)]
pub use not_enabled::{NoProxyConnection, ProxyMethodNotEnabled};

mod stream;
#[doc(inline)]
pub use stream::{ProxyStream, ProxyStreamConnector};

use crate::{
    error::BoxError,
    graceful::WeakScope,
    http::{StreamingBody, client::proxy::HttpForwardProxyConnector},
    net::client::ProxyDialer,
    tcp::client::service::TcpConnector,
};
use rama_utils::macros::generate_set_and_with;

#[cfg(any(feature = "rustls", feature = "boring"))]
use rama_tls::client::TlsClientConfig;

/// The proxy methods a client reaches origins with, each over the connections towards
/// proxies they were built on: see [`ProxyConnector::builder`].
///
/// Every method has a slot of its own, and one that is not enabled refuses the routes
/// asking for it rather than quietly serving them another way. A client's builder takes the
/// parts out and places each of them where it belongs, in `with_proxy_support`.
#[derive(Debug, Clone)]
pub struct ProxyConnector<Socks = (), Connect = (), ConnectUdp = (), Forward = ()> {
    socks: Socks,
    connect: Connect,
    connect_udp: ConnectUdp,
    forward: Forward,
}

impl ProxyConnector {
    /// Build the connections towards proxies of a client and the methods it speaks on them.
    #[must_use]
    pub fn builder(scope: impl Into<WeakScope>) -> ProxyConnectorBuilder {
        ProxyConnectorBuilder::new(scope)
    }

    core::cfg_select! {
        any(feature = "boring", feature = "rustls") => {
            /// Every proxy method this build of rama has, over rama's default connections
            /// towards proxies: TCP, QUIC for an `h3://` one, the global DNS resolver, and TLS
            /// for a secure one.
            ///
            /// `Body` is the body type sent to a proxy, the one the client serves origins with.
            pub fn default_with_scope<Body>(
                scope: impl Into<WeakScope>,
            ) -> DefaultProxyConnector<TcpConnector, Body>
            where
                Body: StreamingBody<Data: Send + 'static, Error: Into<BoxError>>
                    + Unpin
                    + Send
                    + 'static,
            {
                Self::default_using_tls(scope, TlsClientConfig::default_http())
            }

            /// [`Self::default_with_scope`], with `tls` towards the proxies.
            pub fn default_using_tls<Body>(
                scope: impl Into<WeakScope>,
                tls: TlsClientConfig,
            ) -> DefaultProxyConnector<TcpConnector, Body>
            where
                Body: StreamingBody<Data: Send + 'static, Error: Into<BoxError>>
                    + Unpin
                    + Send
                    + 'static,
            {
                Self::builder(scope)
                    .with_default_transport_connector()
                    .with_default_dns_connector()
                    .with_default_tls_support(tls)
                    .with_default_http_connector()
                    .with_default_connection_pool()
                    .with_all_proxy_protocols()
                    .build()
            }
        }
        _ => {
            /// Every proxy method this build of rama has, over rama's default connections
            /// towards proxies, which have no TLS to reach an `https://` proxy with.
            ///
            /// `Body` is the body type sent to a proxy, the one the client serves origins with.
            pub fn default_with_scope<Body>(
                scope: impl Into<WeakScope>,
            ) -> DefaultProxyConnector<TcpConnector, Body>
            where
                Body: StreamingBody<Data: Send + 'static, Error: Into<BoxError>>
                    + Unpin
                    + Send
                    + 'static,
            {
                Self::builder(scope)
                    .with_default_transport_connector()
                    .with_default_dns_connector()
                    .without_tls_support()
                    .with_default_http_connector()
                    .with_default_connection_pool()
                    .with_all_proxy_protocols()
                    .build()
            }
        }
    }
}

impl
    ProxyConnector<
        ProxyMethodNotEnabled,
        ProxyMethodNotEnabled,
        ProxyConnectUdpNotEnabled<()>,
        ProxyMethodNotEnabled,
    >
{
    /// A [`ProxyConnector`] with no method yet: each one refuses its routes until it is
    /// given with `with_*`, as its own stack of layers.
    #[must_use]
    pub fn new() -> Self {
        Self::from_methods(
            ProxyMethodNotEnabled::SOCKS5,
            ProxyMethodNotEnabled::HTTP_CONNECT,
            connect_udp_not_enabled(&WeakScope::detached()),
            ProxyMethodNotEnabled::HTTP_FORWARD,
        )
    }
}

impl Default
    for ProxyConnector<
        ProxyMethodNotEnabled,
        ProxyMethodNotEnabled,
        ProxyConnectUdpNotEnabled<()>,
        ProxyMethodNotEnabled,
    >
{
    fn default() -> Self {
        Self::new()
    }
}

impl<Socks, Connect, ConnectUdp, Forward> ProxyConnector<Socks, Connect, ConnectUdp, Forward> {
    /// Open a tunnel to the origin over a SOCKS5 proxy with `socks`.
    pub fn with_socks<S>(self, socks: S) -> ProxyConnector<S, Connect, ConnectUdp, Forward> {
        ProxyConnector::from_methods(socks, self.connect, self.connect_udp, self.forward)
    }

    /// Open a tunnel to the origin over an HTTP proxy with CONNECT, with `connect`.
    pub fn with_connect<C>(self, connect: C) -> ProxyConnector<Socks, C, ConnectUdp, Forward> {
        ProxyConnector::from_methods(self.socks, connect, self.connect_udp, self.forward)
    }

    /// Open a datagram tunnel to the origin with CONNECT-UDP, with `connect_udp`.
    pub fn with_connect_udp<U>(self, connect_udp: U) -> ProxyConnector<Socks, Connect, U, Forward> {
        ProxyConnector::from_methods(self.socks, self.connect, connect_udp, self.forward)
    }

    /// Have an HTTP proxy forward a plaintext request, with `forward`.
    pub fn with_forward<F>(self, forward: F) -> ProxyConnector<Socks, Connect, ConnectUdp, F> {
        ProxyConnector::from_methods(self.socks, self.connect, self.connect_udp, forward)
    }

    pub(in crate::http::client) const fn from_methods(
        socks: Socks,
        connect: Connect,
        connect_udp: ConnectUdp,
        forward: Forward,
    ) -> Self {
        Self {
            socks,
            connect,
            connect_udp,
            forward,
        }
    }

    pub fn into_parts(self) -> ProxyConnectorParts<Socks, Connect, ConnectUdp, Forward> {
        ProxyConnectorParts {
            socks: self.socks,
            connect: self.connect,
            connect_udp: self.connect_udp,
            forward: self.forward,
        }
    }
}

/// The proxy methods of a [`ProxyConnector`], taken apart with [`ProxyConnector::into_parts`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ProxyConnectorParts<Socks = (), Connect = (), ConnectUdp = (), Forward = ()> {
    /// The connector which opens a tunnel to the origin over a SOCKS5 proxy.
    pub socks: Socks,
    /// The connector which opens a tunnel to the origin over an HTTP proxy with CONNECT.
    pub connect: Connect,
    /// The connector which opens a datagram tunnel to the origin with CONNECT-UDP.
    pub connect_udp: ConnectUdp,
    /// The connector for requests an HTTP proxy forwards.
    pub forward: Forward,
}

impl<Socks, Connect, ConnectUdp, C>
    ProxyConnector<Socks, Connect, ConnectUdp, HttpForwardProxyConnector<ProxyDialer<C>>>
{
    generate_set_and_with! {
        /// See [`HttpForwardProxyConnector::with_isolate_auth_error`]; disabled by default.
        pub fn isolate_forward_proxy_auth_error(mut self, enabled: bool) -> Self {
            self.forward.set_isolate_auth_error(enabled);
            self
        }
    }

    generate_set_and_with! {
        /// See [`HttpForwardProxyConnector::with_proxy_auth`]; enabled by default.
        pub fn forward_proxy_auth(mut self, enabled: bool) -> Self {
            self.forward.set_proxy_auth(enabled);
            self
        }
    }
}
