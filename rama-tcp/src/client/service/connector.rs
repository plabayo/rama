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

/// A connector which can be used to establish a TCP connection to a server.
#[derive(Debug, Clone)]
pub struct TcpConnector<StreamConnector = ()> {
    connector: StreamConnector,
}

impl TcpConnector {
    /// Create a new [`TcpConnector`], which is used to establish a connection to a server.
    ///
    /// You can use middleware around the [`TcpConnector`]
    /// or add connection pools, retry logic and more.
    #[must_use]
    pub fn new() -> Self {
        Self { connector: () }
    }
}

impl TcpConnector<()> {
    /// Consume `self` to attach the given `Connector` (a [`TcpStreamConnector`]),
    /// used to establish the actual [`TcpStream`].
    pub fn with_connector<StreamConnector>(
        self,
        connector: StreamConnector,
    ) -> TcpConnector<StreamConnector>
where {
        TcpConnector { connector }
    }
}

impl Default for TcpConnector {
    fn default() -> Self {
        Self { connector: () }
    }
}

impl<Input, StreamConnector> Service<Input> for TcpConnector<StreamConnector>
where
    Input: ConnectorTargetInputExt + TransportProtocolInputExt + Send + 'static,
    StreamConnector: TcpStreamConnector<Error: Into<BoxError>> + Send + 'static,
{
    type Output = EstablishedClientConnection<TcpStream, Input>;
    type Error = BoxError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
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

        let (conn, addr) =
            crate::client::tcp_connect(input.extensions(), authority, &self.connector)
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
        let connector = TcpConnector::new().with_connector(DenyTcpStreamConnector::new());
        let req = Request::new(HostWithPort::local_ipv4(80))
            .with_transport_protocol(TransportProtocol::Udp);

        connector.serve(req).await.unwrap_err();
    }
}
