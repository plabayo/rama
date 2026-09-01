use rama_core::{
    Service,
    error::{BoxError, BoxErrorExt as _},
    extensions::ExtensionsRef,
    telemetry::tracing,
};
use rama_net::{
    ConnectorTargetInputExt, ConnectorTransportProtocolInputExt,
    client::{
        ConnectionError, ConnectionErrorKind, ConnectorTarget, ConnectorTargetStream,
        EstablishedClientConnection, race_connect,
    },
    stream::{Socket, SocketInfo},
    transport::TransportProtocol,
};

use rama_utils::macros::generate_set_and_with;

use crate::TcpStream;
use crate::client::connect::TcpStreamConnector;

/// Default number of resolved-candidate connection attempts raced concurrently.
const DEFAULT_MAX_IN_FLIGHT_CONNECT_ATTEMPTS: usize = 3;

/// A connector which can be used to establish a TCP connection to a server.
#[derive(Debug, Clone)]
pub struct TcpConnector<StreamConnector = ()> {
    connector: StreamConnector,
    max_in_flight: usize,
}

impl TcpConnector {
    /// Create a new [`TcpConnector`], which is used to establish a connection to a server.
    ///
    /// You can use middleware around the [`TcpConnector`]
    /// or add connection pools, retry logic and more.
    #[must_use]
    pub fn new() -> Self {
        Self {
            connector: (),
            max_in_flight: DEFAULT_MAX_IN_FLIGHT_CONNECT_ATTEMPTS,
        }
    }
}

impl<StreamConnector> TcpConnector<StreamConnector> {
    generate_set_and_with! {
        /// Set the maximum number of resolved candidate connection attempts
        /// raced concurrently (default `3`, clamped to a minimum of `1`).
        ///
        /// Only takes effect when a [`ConnectorTargetStream`] is present on the
        /// input (i.e. a domain target was resolved by an upstream DNS
        /// connector), a single IP target is dialed directly.
        pub fn max_in_flight_connect_attempts(mut self, n: usize) -> Self {
            self.max_in_flight = n.max(1);
            self
        }
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
        TcpConnector {
            connector,
            max_in_flight: self.max_in_flight,
        }
    }
}

impl Default for TcpConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl<Input, StreamConnector> Service<Input> for TcpConnector<StreamConnector>
where
    Input: ConnectorTargetInputExt + ConnectorTransportProtocolInputExt + Send + 'static,
    StreamConnector: TcpStreamConnector<Error: Into<BoxError>> + Send + 'static,
{
    type Output = EstablishedClientConnection<TcpStream, Input>;
    type Error = ConnectionError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        match input.connector_transport_protocol() {
            Some(TransportProtocol::Tcp) | None => (), // a-ok :)
            Some(TransportProtocol::Udp) => {
                return Err(ConnectionError::local(
                    BoxError::from_static_str(
                        "Tcp Connector Service cannot establish a UDP transport",
                    ),
                    ConnectionErrorKind::InvalidInput,
                ));
            }
        }

        let authority = input.connector_target().ok_or_else(|| {
            ConnectionError::local(
                BoxError::from_static_str("tcp connector: connector target missing from input"),
                ConnectionErrorKind::InvalidInput,
            )
        })?;

        let target_is_overridden = input.extensions().contains::<ConnectorTarget>();
        let (conn, addr) = if let Some(candidates) = input
            .extensions()
            .get_ref::<ConnectorTargetStream>()
            .filter(|candidates| match candidates.target() {
                Some(target) => target == &authority,
                None => !target_is_overridden,
            }) {
            let stream = candidates.stream(input.extensions());
            let (addr, conn) = race_connect(stream, self.max_in_flight, |addr| async move {
                self.connector.connect(addr).await.map_err(Into::into)
            })
            .await
            .map_err(|error| {
                ConnectionError::transport(error, ConnectionErrorKind::Unavailable)
                    .context("tcp connector: connect to resolved candidate")
            })?;
            (conn, addr)
        } else {
            crate::client::tcp_connect(input.extensions(), authority, &self.connector)
                .await
                .map_err(|error| {
                    ConnectionError::transport(error, ConnectionErrorKind::Unavailable)
                        .context("tcp connector: connect to server")
                })?
        };

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
    use std::{net::SocketAddr, sync::Arc};

    use rama_core::{
        error::BoxError,
        extensions::Extensions,
        futures::{Stream, stream},
    };
    use rama_net::{
        address::HostWithPort,
        client::{
            AddressCandidates, ConnectRequest, ConnectionErrorDomain, ConnectorTarget,
            ConnectorTargetStream, ConnectorTransportProtocol,
        },
        transport::TransportProtocol,
    };

    use crate::client::connect::DenyTcpStreamConnector;

    use super::*;

    #[tokio::test]
    async fn rejects_udp_transport_inputs() {
        let connector = TcpConnector::new().with_connector(DenyTcpStreamConnector::new());
        let req = ConnectRequest::new(HostWithPort::local_ipv4(80))
            .with_transport_protocol(TransportProtocol::Udp);

        let error = connector.serve(req).await.unwrap_err();
        assert_eq!(error.domain(), ConnectionErrorDomain::Local);
        assert_eq!(error.kind(), ConnectionErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn physical_tcp_override_accepts_logical_udp_input() {
        let connector = TcpConnector::new().with_connector(DenyTcpStreamConnector::new());
        let req = ConnectRequest::new(HostWithPort::local_ipv4(80))
            .with_transport_protocol(TransportProtocol::Udp);
        req.extensions
            .insert(ConnectorTransportProtocol(TransportProtocol::Tcp));

        let error = connector.serve(req).await.unwrap_err();
        assert_eq!(error.domain(), ConnectionErrorDomain::Transport);
        assert_eq!(error.kind(), ConnectionErrorKind::Unavailable);
    }

    struct OneCandidate {
        target: Option<HostWithPort>,
        addr: SocketAddr,
    }

    impl AddressCandidates for OneCandidate {
        fn target(&self) -> Option<&HostWithPort> {
            self.target.as_ref()
        }

        fn stream<'a>(
            &'a self,
            _: &'a Extensions,
        ) -> core::pin::Pin<Box<dyn Stream<Item = Result<SocketAddr, BoxError>> + Send + 'a>>
        {
            Box::pin(stream::iter([Ok(self.addr)]))
        }
    }

    #[tokio::test]
    async fn ignores_candidate_stream_for_a_different_target() {
        let proxy_addr = SocketAddr::from(([127, 0, 0, 1], 8080));
        let origin_addr = SocketAddr::from(([127, 0, 0, 1], 443));
        for candidate_target in [Some(HostWithPort::example_domain_https()), None] {
            let recorded = Arc::new(rama_utils::collections::AppendOnlyVec::<SocketAddr>::new());
            let connector = TcpConnector::new().with_connector({
                let recorded = Arc::clone(&recorded);
                move |addr| {
                    recorded.push(addr);
                    async { Err::<TcpStream, _>(std::io::Error::other("denied")) }
                }
            });
            let req = ConnectRequest::new(HostWithPort::example_domain_https());
            req.extensions.insert(ConnectorTarget(proxy_addr.into()));
            req.extensions
                .insert(ConnectorTargetStream::new(OneCandidate {
                    target: candidate_target,
                    addr: origin_addr,
                }));

            let error = connector.serve(req).await.unwrap_err();
            assert_eq!(error.domain(), ConnectionErrorDomain::Transport);
            assert_eq!(error.kind(), ConnectionErrorKind::Unavailable);
            assert_eq!(recorded.iter().copied().collect::<Vec<_>>(), [proxy_addr]);
        }
    }

    #[tokio::test]
    async fn consumes_candidate_stream_for_the_current_target() {
        let target = HostWithPort::example_domain_https();
        let candidate_addr = SocketAddr::from(([127, 0, 0, 1], 8443));
        for candidate_target in [Some(target.clone()), None] {
            let recorded = Arc::new(rama_utils::collections::AppendOnlyVec::<SocketAddr>::new());
            let connector = TcpConnector::new().with_connector({
                let recorded = Arc::clone(&recorded);
                move |addr| {
                    recorded.push(addr);
                    async { Err::<TcpStream, _>(std::io::Error::other("denied")) }
                }
            });
            let req = ConnectRequest::new(target.clone());
            req.extensions
                .insert(ConnectorTargetStream::new(OneCandidate {
                    target: candidate_target,
                    addr: candidate_addr,
                }));

            let error = connector.serve(req).await.unwrap_err();
            assert_eq!(error.domain(), ConnectionErrorDomain::Transport);
            assert_eq!(error.kind(), ConnectionErrorKind::Unavailable);
            assert_eq!(
                recorded.iter().copied().collect::<Vec<_>>(),
                [candidate_addr]
            );
        }
    }

    #[tokio::test]
    async fn classifies_dial_failure_as_transport_unavailable() {
        let connector = TcpConnector::new().with_connector(DenyTcpStreamConnector::new());
        let req = ConnectRequest::new(HostWithPort::local_ipv4(80));

        let error = connector.serve(req).await.unwrap_err();
        assert_eq!(error.domain(), ConnectionErrorDomain::Transport);
        assert_eq!(error.kind(), ConnectionErrorKind::Unavailable);
    }
}
