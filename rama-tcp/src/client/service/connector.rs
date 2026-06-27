use rama_core::{
    Service,
    error::{BoxError, BoxErrorExt as _, ErrorContext},
    extensions::ExtensionsRef,
    telemetry::tracing,
};
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
pub struct TcpConnector<ConnectorFactory = ()> {
    connector_factory: ConnectorFactory,
}

impl TcpConnector {
    /// Create a new [`TcpConnector`], which is used to establish a connection to a server.
    ///
    /// You can use middleware around the [`TcpConnector`]
    /// or add connection pools, retry logic and more.
    #[must_use]
    pub fn new(_exec: rama_core::rt::Executor) -> Self {
        Self {
            connector_factory: (),
        }
    }
}

impl TcpConnector<()> {
    /// Consume `self` to attach the given `Connector` (a [`TcpStreamConnector`]) as a new [`TcpConnector`].
    pub fn with_connector<Connector>(
        self,
        connector: Connector,
    ) -> TcpConnector<TcpStreamConnectorCloneFactory<Connector>>
where {
        TcpConnector {
            connector_factory: TcpStreamConnectorCloneFactory(connector),
        }
    }

    /// Consume `self` to attach the given `Factory` (a [`TcpStreamConnectorFactory`]) as a new [`TcpConnector`].
    pub fn with_connector_factory<Factory>(self, factory: Factory) -> TcpConnector<Factory>
where {
        TcpConnector {
            connector_factory: factory,
        }
    }
}

impl Default for TcpConnector {
    fn default() -> Self {
        Self {
            connector_factory: (),
        }
    }
}

impl<Input, ConnectorFactory> Service<Input> for TcpConnector<ConnectorFactory>
where
    Input: ConnectorTargetInputExt + TransportProtocolInputExt + Send + 'static,
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

        let (conn, addr) = crate::client::tcp_connect(input.extensions(), authority, connector)
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
        let connector = TcpConnector::new(rama_core::rt::Executor::default())
            .with_connector(DenyTcpStreamConnector::new());
        let req = Request::new(HostWithPort::local_ipv4(80))
            .with_transport_protocol(TransportProtocol::Udp);

        connector.serve(req).await.unwrap_err();
    }
}
