use rama_core::{
    Service,
    error::{BoxError, ErrorContext, ErrorExt, OpaqueError},
    extensions::ExtensionsMut,
    rt::Executor,
    telemetry::tracing,
};
use rama_dns::{DnsResolver, GlobalDnsResolver};
use rama_net::{
    address::ProxyAddress,
    client::{ConnectorTarget, EstablishedClientConnection},
    stream::{ClientSocketInfo, Socket, SocketInfo},
    transport::{TransportProtocol, TryRefIntoTransportContext},
};

use crate::TcpStream;
use crate::client::connect::TcpStreamConnector;

use super::{CreatedTcpStreamConnector, TcpStreamConnectorCloneFactory, TcpStreamConnectorFactory};

/// A connector which can be used to establish a TCP connection to a server.
#[derive(Debug, Clone)]
pub struct TcpConnector<Dns = GlobalDnsResolver, ConnectorFactory = ()> {
    dns: Dns,
    connector_factory: ConnectorFactory,
    exec: Executor,
}

impl<Dns, Connector> TcpConnector<Dns, Connector> {}

impl TcpConnector {
    /// Create a new [`TcpConnector`], which is used to establish a connection to a server.
    ///
    /// You can use middleware around the [`TcpConnector`]
    /// or add connection pools, retry logic and more.
    #[must_use]
    pub fn new(exec: Executor) -> Self {
        Self {
            dns: GlobalDnsResolver::new(),
            connector_factory: (),
            exec,
        }
    }
}

impl<Dns, ConnectorFactory> TcpConnector<Dns, ConnectorFactory> {
    /// Consume `self` to attach the given `dns` (a [`DnsResolver`]) as a new [`TcpConnector`].
    pub fn with_dns<OtherDns>(self, dns: OtherDns) -> TcpConnector<OtherDns, ConnectorFactory>
    where
        OtherDns: DnsResolver + Clone,
    {
        TcpConnector {
            dns,
            connector_factory: self.connector_factory,
            exec: self.exec,
        }
    }
}

impl<Dns> TcpConnector<Dns, ()> {
    /// Consume `self` to attach the given `Connector` (a [`TcpStreamConnector`]) as a new [`TcpConnector`].
    pub fn with_connector<Connector>(
        self,
        connector: Connector,
    ) -> TcpConnector<Dns, TcpStreamConnectorCloneFactory<Connector>>
where {
        TcpConnector {
            dns: self.dns,
            connector_factory: TcpStreamConnectorCloneFactory(connector),
            exec: self.exec,
        }
    }

    /// Consume `self` to attach the given `Factory` (a [`TcpStreamConnectorFactory`]) as a new [`TcpConnector`].
    pub fn with_connector_factory<Factory>(self, factory: Factory) -> TcpConnector<Dns, Factory>
where {
        TcpConnector {
            dns: self.dns,
            connector_factory: factory,
            exec: self.exec,
        }
    }
}

impl Default for TcpConnector {
    fn default() -> Self {
        Self::new(Executor::default())
    }
}

impl<Input, Dns, ConnectorFactory> Service<Input> for TcpConnector<Dns, ConnectorFactory>
where
    Input: TryRefIntoTransportContext + Send + ExtensionsMut + 'static,
    Input::Error: Into<BoxError> + Send + Sync + 'static,
    Dns: DnsResolver + Clone,
    ConnectorFactory: TcpStreamConnectorFactory<
            Connector: TcpStreamConnector<Error: Into<BoxError> + Send + 'static>,
            Error: Into<BoxError> + Send + 'static,
        > + Clone,
{
    type Output = EstablishedClientConnection<TcpStream, Input>;
    type Error = BoxError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let CreatedTcpStreamConnector { connector } = self
            .connector_factory
            .make_connector()
            .await
            .map_err(Into::into)?;

        if let Some(proxy) = input.extensions().get::<ProxyAddress>() {
            let (mut conn, addr) = crate::client::tcp_connect(
                input.extensions(),
                proxy.address.clone(),
                self.dns.clone(),
                connector,
                self.exec.clone(),
            )
            .await
            .context("tcp connector: conncept to proxy")?;

            let socket_info= ClientSocketInfo(SocketInfo::new(
                conn.local_addr()
                    .inspect_err(|err| {
                        tracing::debug!(
                            "failed to receive local addr of established connection to proxy: {err:?}"
                        )
                    })
                    .ok(),
                addr.into(),
            ));
            conn.extensions_mut().insert(socket_info);

            return Ok(EstablishedClientConnection { input, conn });
        }

        if let Some(ConnectorTarget(target)) = input.extensions().get::<ConnectorTarget>().cloned()
        {
            let (mut conn, addr) = crate::client::tcp_connect(
                input.extensions(),
                target,
                self.dns.clone(),
                connector,
                self.exec.clone(),
            )
            .await
            .context("tcp connector: conncept to connector target (overwrite?)")?;

            let socket_info= ClientSocketInfo(SocketInfo::new(
                conn.local_addr()
                    .inspect_err(|err| {
                        tracing::debug!(
                            "failed to receive local addr of established connection to target (overwrite?): {err:?}"
                        )
                    })
                    .ok(),
                addr.into(),
            ));
            conn.extensions_mut().insert(socket_info);

            return Ok(EstablishedClientConnection { input, conn });
        }

        let transport_ctx = input.try_ref_into_transport_ctx().map_err(|err| {
            OpaqueError::from_boxed(err.into())
                .context("tcp connecter: compute transport context to get authority")
        })?;

        match transport_ctx.protocol {
            TransportProtocol::Tcp => (), // a-ok :)
            TransportProtocol::Udp => {
                // sanity check, shouldn't happen, but in case someone makes a weird stack, it can
                return Err(OpaqueError::from_display(
                    "Tcp Connector Service cannot establish a UDP transport",
                )
                .into());
            }
        }

        let authority = transport_ctx
            .host_with_port()
            .context("get host:port from transport ctx")?;
        let (mut conn, addr) = crate::client::tcp_connect(
            input.extensions(),
            authority,
            self.dns.clone(),
            connector,
            self.exec.clone(),
        )
        .await
        .context("tcp connector: connect to server")?;

        let socket_info = ClientSocketInfo(SocketInfo::new(
            conn.local_addr()
                .inspect_err(|err| {
                    tracing::debug!(
                        "failed to receive local addr of established connection: {err:?}"
                    )
                })
                .ok(),
            addr.into(),
        ));
        conn.extensions_mut().insert(socket_info);

        Ok(EstablishedClientConnection { input, conn })
    }
}
