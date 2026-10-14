//! Prepare the egress socket of a datagram association: the datagram counterpart of bridging
//! an accepted stream to its proxy target.

use rama_core::{
    Layer, Service,
    error::{BoxError, BoxErrorExt as _, ErrorContext as _},
    extensions::ExtensionsRef,
    io::BridgeIo,
    telemetry::tracing,
};
use rama_net::{
    address::HostWithPort,
    client::{ConnectRequest, ConnectorService, ConnectorTarget, EstablishedClientConnection},
};

use crate::{DatagramSocket, UdpPacketSocket, UdpSocketConfig, bind_udp_socket_with_connect};

/// Connects a [`UdpPacketSocket`] to the request's IP target, configured by its
/// [`UdpSocketConfig`]. Resolving a name is the caller's: a domain target is refused.
#[derive(Debug, Clone, Default)]
pub struct UdpConnector {
    config: UdpSocketConfig,
}

impl UdpConnector {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    rama_utils::macros::generate_set_and_with! {
        /// The configuration egress sockets are created with, including the features they must
        /// provide.
        pub fn config(mut self, config: UdpSocketConfig) -> Self {
            self.config = config;
            self
        }
    }
}

impl Service<ConnectRequest> for UdpConnector {
    type Output = EstablishedClientConnection<UdpPacketSocket, ConnectRequest>;
    type Error = BoxError;

    async fn serve(&self, request: ConnectRequest) -> Result<Self::Output, Self::Error> {
        let socket =
            bind_udp_socket_with_connect(request.authority.clone(), Some(&request.extensions))
                .await?;
        let conn = self.config.wrap_tokio(socket)?;
        Ok(EstablishedClientConnection {
            input: request,
            conn,
        })
    }
}

#[derive(Debug, Clone)]
enum AddressProvider {
    Static(HostWithPort),
    ExtensionConnectorTarget,
}

/// Connects an egress socket for each ingress association, with a pluggable connector, and
/// hands both to the inner service as a [`BridgeIo`].
///
/// The egress socket is created by the connector, so a platform that must bind or mark it
/// before it connects supplies its own. The target is fixed, or the association's
/// [`ConnectorTarget`] extension; never anything its datagrams carry.
#[derive(Debug, Clone)]
pub struct DatagramToProxyBridge<S, C = UdpConnector> {
    inner: S,
    connector: C,
    address_provider: AddressProvider,
}

impl<S> DatagramToProxyBridge<S> {
    /// Bridge every association to `target`.
    pub fn new(inner: S, target: impl Into<HostWithPort>) -> Self {
        Self {
            inner,
            connector: UdpConnector::new(),
            address_provider: AddressProvider::Static(target.into()),
        }
    }

    /// Bridge every association to its [`ConnectorTarget`] extension, failing one without it.
    pub fn extension_connector_target(inner: S) -> Self {
        Self {
            inner,
            connector: UdpConnector::new(),
            address_provider: AddressProvider::ExtensionConnectorTarget,
        }
    }

    /// Create egress sockets with `connector` instead.
    pub fn with_connector<C>(self, connector: C) -> DatagramToProxyBridge<S, C> {
        DatagramToProxyBridge {
            inner: self.inner,
            connector,
            address_provider: self.address_provider,
        }
    }
}

/// A [`Layer`] that produces [`DatagramToProxyBridge`] services.
#[derive(Debug, Clone)]
pub struct DatagramToProxyBridgeLayer<C = UdpConnector> {
    connector: C,
    address_provider: AddressProvider,
}

impl DatagramToProxyBridgeLayer {
    /// See [`DatagramToProxyBridge::new`].
    pub fn new(target: impl Into<HostWithPort>) -> Self {
        Self {
            connector: UdpConnector::new(),
            address_provider: AddressProvider::Static(target.into()),
        }
    }

    /// See [`DatagramToProxyBridge::extension_connector_target`].
    #[must_use]
    pub fn extension_connector_target() -> Self {
        Self {
            connector: UdpConnector::new(),
            address_provider: AddressProvider::ExtensionConnectorTarget,
        }
    }

    /// Create egress sockets with `connector` instead.
    pub fn with_connector<C>(self, connector: C) -> DatagramToProxyBridgeLayer<C> {
        DatagramToProxyBridgeLayer {
            connector,
            address_provider: self.address_provider,
        }
    }
}

impl<S, C: Clone> Layer<S> for DatagramToProxyBridgeLayer<C> {
    type Service = DatagramToProxyBridge<S, C>;

    fn layer(&self, inner: S) -> Self::Service {
        DatagramToProxyBridge {
            inner,
            connector: self.connector.clone(),
            address_provider: self.address_provider.clone(),
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        DatagramToProxyBridge {
            inner,
            connector: self.connector,
            address_provider: self.address_provider,
        }
    }
}

impl<S, Ingress, C> Service<Ingress> for DatagramToProxyBridge<S, C>
where
    S: Service<BridgeIo<Ingress, C::Connection>, Error: Into<BoxError>>,
    Ingress: DatagramSocket + ExtensionsRef + Send + 'static,
    C: ConnectorService<ConnectRequest, Connection: DatagramSocket>,
{
    type Output = S::Output;
    type Error = BoxError;

    async fn serve(&self, ingress: Ingress) -> Result<Self::Output, Self::Error> {
        let target = match &self.address_provider {
            AddressProvider::Static(target) => target.clone(),
            AddressProvider::ExtensionConnectorTarget => {
                let Some(ConnectorTarget(target)) = ingress.extensions().get_ref().cloned() else {
                    return Err(BoxError::from_static_str(
                        "datagram bridge needs a ConnectorTarget in the association's extensions",
                    ));
                };
                target
            }
        };
        tracing::trace!("connect the egress of a datagram association: target = {target}");
        let request =
            ConnectRequest::new_with_extensions(target.clone(), ingress.extensions().fork());
        let EstablishedClientConnection { conn: egress, .. } = self
            .connector
            .connect(request)
            .await
            .context("connect datagram egress")
            .context_field("target", target)?;
        self.inner
            .serve(BridgeIo(ingress, egress))
            .await
            .into_box_error()
    }
}

#[cfg(test)]
mod tests;
