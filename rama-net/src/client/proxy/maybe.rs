use core::fmt;
use std::{
    io::IoSlice,
    pin::Pin,
    task::{Context as TaskContext, Poll},
};

use pin_project_lite::pin_project;
use rama_core::{
    Service,
    error::BoxError,
    extensions::{Extensions, ExtensionsRef},
    telemetry::tracing,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{
    address::SocketAddress,
    client::{
        ConnectionError, ConnectorService, EstablishedClientConnection, EstablishedProxyRoute,
        ProxyRoute,
    },
    stream::Socket,
};

/// Decides which side of a [`MaybeProxiedConnector`] serves an input.
pub trait ProxySelector<Input> {
    /// Whether the proxy connector serves `input`, rather than the direct one.
    fn is_proxied(&self, input: &Input) -> bool;
}

/// Selects every input with a proxied [`ProxyRoute`], whichever proxy it names.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct ProxiedRoute;

impl ProxiedRoute {
    pub const fn new() -> Self {
        Self
    }
}

impl<Input: ExtensionsRef> ProxySelector<Input> for ProxiedRoute {
    fn is_proxied(&self, input: &Input) -> bool {
        matches!(
            input.extensions().get_ref::<ProxyRoute>(),
            Some(ProxyRoute::Proxy(_))
        )
    }
}

/// Route a client connection directly or through a proxy, making a proxy optional.
///
/// The inputs `selector` picks are served by `proxy`, every other one by `direct`.
///
/// `direct` reaches the peer of an input itself, without a proxy protocol: for a request
/// its HTTP proxy forwards, that peer is the proxy. A requested [`ProxyRoute::Direct`]
/// publishes [`EstablishedProxyRoute::Direct`].
#[derive(Debug, Clone)]
pub struct MaybeProxiedConnector<D, P, Sel> {
    direct: D,
    proxy: P,
    selector: Sel,
}

impl<D, P, Sel> MaybeProxiedConnector<D, P, Sel> {
    /// Create a new [`MaybeProxiedConnector`] router.
    pub const fn new(direct: D, proxy: P, selector: Sel) -> Self {
        Self {
            direct,
            proxy,
            selector,
        }
    }
}

impl<D, P, Sel, Input, Direct, Proxied> Service<Input> for MaybeProxiedConnector<D, P, Sel>
where
    D: ConnectorService<Input, Connection = Direct>,
    P: ConnectorService<Input, Connection = Proxied>,
    Sel: ProxySelector<Input> + Send + Sync + 'static,
    Direct: Send + ExtensionsRef + 'static,
    Proxied: Send + ExtensionsRef + 'static,
    Input: ExtensionsRef + Send + 'static,
{
    type Output = EstablishedClientConnection<MaybeProxied<Direct, Proxied>, Input>;
    type Error = ConnectionError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        if self.selector.is_proxied(&input) {
            tracing::trace!("maybe proxy: the proxy connector serves this input");
            let EstablishedClientConnection { input, conn } = self.proxy.connect(input).await?;
            return Ok(EstablishedClientConnection {
                input,
                conn: MaybeProxied::Proxied { conn },
            });
        }

        tracing::trace!("maybe proxy: the direct connector serves this input");
        let direct_requested = matches!(
            input.extensions().get_ref::<ProxyRoute>(),
            Some(ProxyRoute::Direct)
        );
        // Direct here can contain a nested proxy connector, so only insert the extension
        // if we actually used a direct proxy route here.
        let EstablishedClientConnection { input, conn } = self.direct.connect(input).await?;
        if direct_requested {
            conn.extensions().insert(EstablishedProxyRoute::Direct);
        }
        Ok(EstablishedClientConnection {
            input,
            conn: MaybeProxied::Direct { conn },
        })
    }
}

pin_project! {
    /// The connection established by [`MaybeProxiedConnector`], direct or through a proxy.
    #[project = MaybeProxiedProj]
    pub enum MaybeProxied<A, B> {
        /// Established without a proxy.
        Direct { #[pin] conn: A },
        /// Established through a proxy.
        Proxied { #[pin] conn: B },
    }
}

impl<A: fmt::Debug, B: fmt::Debug> fmt::Debug for MaybeProxied<A, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Direct { conn } => f.debug_struct("Direct").field("conn", conn).finish(),
            Self::Proxied { conn } => f.debug_struct("Proxied").field("conn", conn).finish(),
        }
    }
}

impl<A: ExtensionsRef, B: ExtensionsRef> ExtensionsRef for MaybeProxied<A, B> {
    fn extensions(&self) -> &Extensions {
        match self {
            Self::Direct { conn } => conn.extensions(),
            Self::Proxied { conn } => conn.extensions(),
        }
    }
}

impl<A, B, Input, Output> Service<Input> for MaybeProxied<A, B>
where
    A: Service<Input, Output = Output, Error: Into<BoxError>>,
    B: Service<Input, Output = Output, Error: Into<BoxError>>,
    Input: Send + 'static,
    Output: Send + 'static,
{
    type Output = Output;
    type Error = BoxError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        match self {
            Self::Direct { conn } => conn.serve(input).await.map_err(Into::into),
            Self::Proxied { conn } => conn.serve(input).await.map_err(Into::into),
        }
    }
}

#[warn(clippy::missing_trait_methods)]
impl<A: AsyncRead, B: AsyncRead> AsyncRead for MaybeProxied<A, B> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.project() {
            MaybeProxiedProj::Direct { conn } => conn.poll_read(cx, buf),
            MaybeProxiedProj::Proxied { conn } => conn.poll_read(cx, buf),
        }
    }
}

#[warn(clippy::missing_trait_methods)]
impl<A: AsyncWrite, B: AsyncWrite> AsyncWrite for MaybeProxied<A, B> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.project() {
            MaybeProxiedProj::Direct { conn } => conn.poll_write(cx, buf),
            MaybeProxiedProj::Proxied { conn } => conn.poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        match self.project() {
            MaybeProxiedProj::Direct { conn } => conn.poll_flush(cx),
            MaybeProxiedProj::Proxied { conn } => conn.poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        match self.project() {
            MaybeProxiedProj::Direct { conn } => conn.poll_shutdown(cx),
            MaybeProxiedProj::Proxied { conn } => conn.poll_shutdown(cx),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Direct { conn } => conn.is_write_vectored(),
            Self::Proxied { conn } => conn.is_write_vectored(),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        match self.project() {
            MaybeProxiedProj::Direct { conn } => conn.poll_write_vectored(cx, bufs),
            MaybeProxiedProj::Proxied { conn } => conn.poll_write_vectored(cx, bufs),
        }
    }
}

impl<A: Socket, B: Socket> Socket for MaybeProxied<A, B> {
    fn local_addr(&self) -> std::io::Result<SocketAddress> {
        match self {
            Self::Direct { conn } => conn.local_addr(),
            Self::Proxied { conn } => conn.local_addr(),
        }
    }

    fn peer_addr(&self) -> std::io::Result<SocketAddress> {
        match self {
            Self::Direct { conn } => conn.peer_addr(),
            Self::Proxied { conn } => conn.peer_addr(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        address::{HostWithPort, ProxyAddress},
        client::ConnectRequest,
    };
    use rama_core::{
        Layer, ServiceInput,
        error::{BoxError, BoxErrorExt as _},
        service::service_fn,
    };
    use std::convert::Infallible;

    use crate::client::ConnectionErrorKind;

    fn duplex_connector<Input: Send + 'static>() -> impl Clone
    + Service<
        Input,
        Output = EstablishedClientConnection<ServiceInput<tokio::io::DuplexStream>, Input>,
        Error = Infallible,
    > {
        service_fn(|input: Input| async move {
            let (io, _peer) = tokio::io::duplex(64);
            Ok(EstablishedClientConnection {
                input,
                conn: ServiceInput::new(io),
            })
        })
    }

    fn unreachable_connector<Input: Send + 'static>() -> impl Service<
        Input,
        Output = EstablishedClientConnection<ServiceInput<tokio::io::DuplexStream>, Input>,
        Error = ConnectionError,
    > {
        service_fn(|_: Input| async move {
            Err(ConnectionError::local(
                BoxError::from_static_str("connector must not be used"),
                ConnectionErrorKind::Unavailable,
            ))
        })
    }

    fn socks_proxy() -> ProxyAddress {
        "socks5://proxy.example:1080".parse().unwrap()
    }

    #[derive(Clone)]
    struct TunnelLayer;

    #[derive(Clone)]
    struct TunnelConnector<S>(S);

    impl<S> Layer<S> for TunnelLayer {
        type Service = TunnelConnector<S>;

        fn layer(&self, inner: S) -> Self::Service {
            TunnelConnector(inner)
        }
    }

    impl<S, Input, Conn> Service<Input> for TunnelConnector<S>
    where
        S: ConnectorService<Input, Connection = Conn>,
        Conn: Send + ExtensionsRef + 'static,
        Input: Send + 'static,
    {
        type Output = EstablishedClientConnection<Conn, Input>;
        type Error = ConnectionError;

        async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
            let established = self.0.connect(input).await?;
            established
                .conn
                .extensions()
                .insert(EstablishedProxyRoute::Tunnel(socks_proxy()));
            Ok(established)
        }
    }

    struct NeverProxied;

    impl<Input> ProxySelector<Input> for NeverProxied {
        fn is_proxied(&self, _: &Input) -> bool {
            false
        }
    }

    #[tokio::test]
    async fn only_a_requested_direct_route_publishes_the_direct_outcome() {
        let connector = MaybeProxiedConnector::new(
            duplex_connector(),
            unreachable_connector(),
            ProxiedRoute::new(),
        );

        let established = connector
            .connect(ConnectRequest::new(HostWithPort::example_domain_http()))
            .await
            .unwrap();
        assert!(matches!(established.conn, MaybeProxied::Direct { .. }));
        assert!(
            !established
                .conn
                .extensions()
                .contains::<EstablishedProxyRoute>(),
            "no route was requested",
        );

        let input = ConnectRequest::new(HostWithPort::example_domain_http());
        input.extensions.insert(ProxyRoute::Direct);
        let established = connector.connect(input).await.unwrap();
        assert_eq!(
            established
                .conn
                .extensions()
                .get_ref::<EstablishedProxyRoute>(),
            Some(&EstablishedProxyRoute::Direct),
        );
    }

    #[tokio::test]
    async fn optional_direct_connection_records_only_the_original_route_selection() {
        for route_configured in [false, true] {
            for rewrite_input in [false, true] {
                let direct = service_fn(move |mut input: ConnectRequest| async move {
                    if rewrite_input {
                        input.extensions = Extensions::new();
                        if !route_configured {
                            input.extensions.insert(ProxyRoute::Direct);
                        }
                    }
                    let (io, _peer) = tokio::io::duplex(64);
                    Ok::<_, Infallible>(EstablishedClientConnection {
                        input,
                        conn: ServiceInput::new(io),
                    })
                });
                let connector = MaybeProxiedConnector::new(
                    direct,
                    unreachable_connector(),
                    ProxiedRoute::new(),
                );
                let input = ConnectRequest::new(HostWithPort::example_domain_http());
                if route_configured {
                    input.extensions.insert(ProxyRoute::Direct);
                }

                let established = connector.connect(input).await.unwrap();
                assert_eq!(
                    established
                        .conn
                        .extensions()
                        .get_ref::<EstablishedProxyRoute>(),
                    route_configured.then_some(&EstablishedProxyRoute::Direct),
                    "route configured: {route_configured}, input rewritten: {rewrite_input}",
                );
                assert!(!established.conn.extensions().contains::<ProxyRoute>());
            }
        }
    }

    #[tokio::test]
    async fn a_route_this_selector_passes_over_is_never_called_direct() {
        let connector =
            MaybeProxiedConnector::new(duplex_connector(), unreachable_connector(), NeverProxied);
        let input = ConnectRequest::new(HostWithPort::example_domain_http());
        input.extensions.insert(ProxyRoute::Proxy(socks_proxy()));
        let established = connector.connect(input).await.unwrap();

        assert!(matches!(established.conn, MaybeProxied::Direct { .. }));
        assert!(
            !established
                .conn
                .extensions()
                .contains::<EstablishedProxyRoute>(),
            "another connector establishes the route of this connection",
        );
    }

    #[tokio::test]
    async fn selected_inputs_go_to_the_proxy_connector_which_publishes_its_own_outcome() {
        let connector = MaybeProxiedConnector::new(
            unreachable_connector(),
            TunnelLayer.into_layer(duplex_connector()),
            ProxiedRoute::new(),
        );
        let input = ConnectRequest::new(HostWithPort::example_domain_http());
        input.extensions.insert(ProxyRoute::Proxy(socks_proxy()));
        let established = connector.connect(input).await.unwrap();

        assert!(matches!(established.conn, MaybeProxied::Proxied { .. }));
        assert_eq!(
            established
                .conn
                .extensions()
                .get_ref::<EstablishedProxyRoute>(),
            Some(&EstablishedProxyRoute::Tunnel(socks_proxy())),
        );
    }
}
