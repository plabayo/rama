use rama_core::{
    Service,
    error::{BoxError, BoxErrorExt as _, ErrorContext},
    extensions::ExtensionsRef,
    rt::Executor,
    telemetry::tracing,
};
use rama_dns::client::{GlobalDnsResolver, resolver::DnsAddressResolver};
use rama_net::{
    ConnectorTargetInputExt, TransportProtocolInputExt,
    client::EstablishedClientConnection,
    stream::{Socket, SocketInfo},
    transport::TransportProtocol,
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
    /// Consume `self` to attach the given `dns`
    /// (a [`DnsAddressResolver`]) as a new [`TcpConnector`].
    pub fn with_dns<OtherDns>(self, dns: OtherDns) -> TcpConnector<OtherDns, ConnectorFactory>
    where
        OtherDns: DnsAddressResolver + Clone,
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
    Input: ConnectorTargetInputExt + TransportProtocolInputExt + Send + 'static,
    Dns: DnsAddressResolver + Clone,
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
            .into_box_error()?;

        match input.transport_protocol() {
            Some(TransportProtocol::Tcp) | None => (), // a-ok :)
            Some(TransportProtocol::Udp) => {
                return Err(BoxError::from_static_str(
                    "Tcp Connector Service cannot establish a UDP transport",
                ));
            }
        }

        let authority = input
            .connector_target()
            .context("get host:port from input")?;

        let (conn, addr) = crate::client::tcp_connect(
            input.extensions(),
            authority,
            self.dns.clone(),
            connector,
            self.exec.clone(),
        )
        .await
        .context("tcp connector: connect to server")?;

        let socket_info = SocketInfo::new(
            conn.local_addr()
                .inspect_err(|err| {
                    tracing::debug!(
                        "failed to receive local addr of established connection: {err:?}"
                    )
                })
                .ok(),
            addr.into(),
        );
        conn.extensions().insert(socket_info);

        Ok(EstablishedClientConnection { input, conn })
    }
}

#[cfg(test)]
mod tests {
    use rama_net::{address::HostWithPort, client::Request, transport::TransportProtocol};

    use crate::client::connect::DenyTcpStreamConnector;

    use super::*;

    #[tokio::test]
    async fn rejects_udp_transport_inputs() {
        let connector =
            TcpConnector::new(Executor::default()).with_connector(DenyTcpStreamConnector::new());
        let req = Request::new(HostWithPort::local_ipv4(80))
            .with_transport_protocol(TransportProtocol::Udp);

        let err = connector.serve(req).await.unwrap_err();

        assert!(
            err.to_string().contains("cannot establish a UDP transport"),
            "unexpected error: {err}"
        );
    }
}
