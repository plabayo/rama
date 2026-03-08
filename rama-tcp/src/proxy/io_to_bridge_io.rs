use rama_core::{
    Layer, Service,
    error::{BoxError, ErrorContext as _},
    extensions::{ExtensionsMut as _, ExtensionsRef},
    io::{BridgeIo, Io},
    rt::Executor,
    telemetry::tracing,
};
use rama_dns::client::{GlobalDnsResolver, resolver::DnsAddressResolver};
use rama_net::{
    address::HostWithPort,
    proxy::ProxyTarget,
    stream::{ClientSocketInfo, Socket as _, SocketInfo},
};
use rama_utils::macros::define_inner_service_accessors;

use crate::{
    TcpStream,
    client::{
        TcpStreamConnector,
        service::{
            CreatedTcpStreamConnector, TcpStreamConnectorCloneFactory, TcpStreamConnectorFactory,
        },
    },
};

#[derive(Debug, Clone)]
pub struct IoToProxyBridgeIo<S, Connector = (), Dns = GlobalDnsResolver> {
    inner: S,
    connector_factory: Connector,
    dns: Dns,
    exec: Executor,
    address_provider: AddressProvider,
}

#[derive(Debug, Clone)]
enum AddressProvider {
    Static(HostWithPort),
    ExtensionProxyTarget,
}

// TODO: once we refactor ProxyAddress support out of TcpConnector,
// we can instead use that one here, as we no longer need to be afraid for
// side-effects

impl<S> IoToProxyBridgeIo<S> {
    #[inline(always)]
    /// Creates a new [`IoToProxyBridgeIo`] service,
    /// which will use the provided target info to connect to.
    ///
    /// Use [`Self::extension_proxy_target`] if you wish to have it be done
    /// using the [`ProxyTarget`] extension instead, failing the input flow
    /// in case that extension not exist.
    pub fn new(inner: S, exec: Executor, target: HostWithPort) -> Self {
        Self {
            inner,
            connector_factory: (),
            dns: GlobalDnsResolver::new(),
            exec,
            address_provider: AddressProvider::Static(target),
        }
    }

    #[inline(always)]
    /// Creates a new [`IoToProxyBridgeIo`] service,
    /// which expects while serving that [`ProxyTarget`]
    /// is available in the input's extension, and fail otherwise.
    ///
    /// Use [`Self::new`] if you wish to use a hardcoded target instead,
    pub fn extension_proxy_target(exec: Executor, inner: S) -> Self {
        Self {
            inner,
            connector_factory: (),
            dns: GlobalDnsResolver::new(),
            exec,
            address_provider: AddressProvider::ExtensionProxyTarget,
        }
    }

    define_inner_service_accessors!();
}

impl<S, Connector, Dns> IoToProxyBridgeIo<S, Connector, Dns> {
    /// Consume `self` to attach the given `dns`
    /// (a [`DnsAddressResolver`]) as a new [`IoToProxyBridgeIo`].
    pub fn with_dns<OtherDns>(self, dns: OtherDns) -> IoToProxyBridgeIo<S, Connector, OtherDns>
    where
        OtherDns: DnsAddressResolver + Clone,
    {
        IoToProxyBridgeIo {
            inner: self.inner,
            connector_factory: self.connector_factory,
            dns,
            exec: self.exec,
            address_provider: self.address_provider,
        }
    }
}

impl<S, Dns> IoToProxyBridgeIo<S, (), Dns> {
    /// Consume `self` to attach the given `Connector`
    /// (a [`TcpStreamConnector`]) as a new [`IoToProxyBridgeIo`].
    pub fn with_connector<Connector>(
        self,
        connector: Connector,
    ) -> IoToProxyBridgeIo<S, TcpStreamConnectorCloneFactory<Connector>, Dns> {
        IoToProxyBridgeIo {
            inner: self.inner,
            connector_factory: TcpStreamConnectorCloneFactory(connector),
            dns: self.dns,
            exec: self.exec,
            address_provider: self.address_provider,
        }
    }

    /// Consume `self` to attach the given `Factory` (a [`TcpStreamConnectorFactory`]) as a new [`IoToProxyBridgeIo`].
    pub fn with_connector_factory<Factory>(
        self,
        factory: Factory,
    ) -> IoToProxyBridgeIo<S, Factory, Dns> {
        IoToProxyBridgeIo {
            inner: self.inner,
            connector_factory: factory,
            dns: self.dns,
            exec: self.exec,
            address_provider: self.address_provider,
        }
    }
}

/// A [`Layer`] that produces [`IoToProxyBridgeIo`] services.
#[derive(Debug, Clone)]
pub struct IoToProxyBridgeIoLayer<Connector = (), Dns = GlobalDnsResolver> {
    connector_factory: Connector,
    dns: Dns,
    exec: Executor,
    address_provider: AddressProvider,
}

impl IoToProxyBridgeIoLayer {
    #[inline(always)]
    /// Creates a new [`IoToProxyBridgeIoLayer`],
    /// which will use by the [`IoToProxyBridgeIo`] [`Service`] the provided target info to connect to.
    ///
    /// Use [`Self::extension_proxy_target`] if you wish to have it be done
    /// using the [`ProxyTarget`] extension instead, failing the input flow
    /// in case that extension not exist.
    pub fn new(exec: Executor, target: HostWithPort) -> Self {
        Self {
            connector_factory: (),
            dns: GlobalDnsResolver::new(),
            exec,
            address_provider: AddressProvider::Static(target),
        }
    }

    #[inline(always)]
    /// Creates a new [`IoToProxyBridgeIoLayer`],
    /// which will create the [`IoToProxyBridgeIo`] [`Service`]
    /// that with this constructor will expect while serving that [`ProxyTarget`]
    /// is available in the input's extension, and fail otherwise.
    ///
    /// Use [`Self::new`] if you wish to use a hardcoded target instead,
    pub fn extension_proxy_target(exec: Executor) -> Self {
        Self {
            connector_factory: (),
            dns: GlobalDnsResolver::new(),
            exec,
            address_provider: AddressProvider::ExtensionProxyTarget,
        }
    }
}

impl<Connector, Dns> IoToProxyBridgeIoLayer<Connector, Dns> {
    /// Consume `self` to attach the given `dns`
    /// (a [`DnsAddressResolver`]) as a new [`IoToProxyBridgeIoLayer`].
    pub fn with_dns<OtherDns>(self, dns: OtherDns) -> IoToProxyBridgeIoLayer<Connector, OtherDns>
    where
        OtherDns: DnsAddressResolver + Clone,
    {
        IoToProxyBridgeIoLayer {
            connector_factory: self.connector_factory,
            dns,
            exec: self.exec,
            address_provider: self.address_provider,
        }
    }
}

impl<Dns> IoToProxyBridgeIoLayer<(), Dns> {
    /// Consume `self` to attach the given `Connector`
    /// (a [`TcpStreamConnector`]) as a new [`IoToProxyBridgeIoLayer`].
    pub fn with_connector<Connector>(
        self,
        connector: Connector,
    ) -> IoToProxyBridgeIoLayer<TcpStreamConnectorCloneFactory<Connector>, Dns> {
        IoToProxyBridgeIoLayer {
            connector_factory: TcpStreamConnectorCloneFactory(connector),
            dns: self.dns,
            exec: self.exec,
            address_provider: self.address_provider,
        }
    }

    /// Consume `self` to attach the given `Factory` (a [`TcpStreamConnectorFactory`]) as a new [`IoToProxyBridgeIoLayer`].
    pub fn with_connector_factory<Factory>(
        self,
        factory: Factory,
    ) -> IoToProxyBridgeIoLayer<Factory, Dns> {
        IoToProxyBridgeIoLayer {
            connector_factory: factory,
            dns: self.dns,
            exec: self.exec,
            address_provider: self.address_provider,
        }
    }
}

impl<S, Connector, Dns> Layer<S> for IoToProxyBridgeIoLayer<Connector, Dns>
where
    Connector: Clone,
    Dns: Clone,
{
    type Service = IoToProxyBridgeIo<S, Connector, Dns>;

    fn layer(&self, inner: S) -> Self::Service {
        Self::Service {
            inner,
            connector_factory: self.connector_factory.clone(),
            dns: self.dns.clone(),
            exec: self.exec.clone(),
            address_provider: self.address_provider.clone(),
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        Self::Service {
            inner,
            connector_factory: self.connector_factory,
            dns: self.dns,
            exec: self.exec,
            address_provider: self.address_provider,
        }
    }
}

impl<S, Ingress, Dns, ConnectorFactory> Service<Ingress>
    for IoToProxyBridgeIo<S, ConnectorFactory, Dns>
where
    S: Service<BridgeIo<Ingress, TcpStream>, Error: Into<BoxError>>,
    Ingress: Io + ExtensionsRef,
    Dns: DnsAddressResolver + Clone,
    ConnectorFactory: TcpStreamConnectorFactory<
            Connector: TcpStreamConnector<Error: Into<BoxError> + Send + 'static>,
            Error: Into<BoxError> + Send + 'static,
        > + Clone,
{
    type Output = S::Output;
    type Error = BoxError;

    async fn serve(&self, ingress: Ingress) -> Result<Self::Output, Self::Error> {
        let CreatedTcpStreamConnector { connector } = self
            .connector_factory
            .make_connector()
            .await
            .into_box_error()?;

        let egress_addr = match self.address_provider.clone() {
            AddressProvider::Static(host_with_port) => host_with_port,
            AddressProvider::ExtensionProxyTarget => {
                if let Some(ProxyTarget(host_with_port)) = ingress.extensions().get().cloned() {
                    host_with_port
                } else {
                    return Err(BoxError::from(
                        "missing ProxyTarget in IoToProxyBridgeIo: proxy target assumed to exist in ingress extensions",
                    ));
                }
            }
        };

        tracing::trace!(
            "try to establish connection to egress as a means to create a BridgeIo: addr = {egress_addr}"
        );

        let (mut egress, egress_addr) = crate::client::tcp_connect(
            ingress.extensions(),
            egress_addr,
            self.dns.clone(),
            connector,
            self.exec.clone(),
        )
        .await
        .context("IoToPRoxyBridgeIo: tcp connector: connect to egress")?;

        let socket_info = ClientSocketInfo(SocketInfo::new(
            egress
                .local_addr()
                .inspect_err(|err| {
                    tracing::debug!(
                        "failed to receive local addr of established connection: {err:?}"
                    )
                })
                .ok(),
            egress_addr.into(),
        ));
        egress.extensions_mut().insert(socket_info);

        let bridge_io = BridgeIo(ingress, egress);
        self.inner.serve(bridge_io).await.into_box_error()
    }
}
