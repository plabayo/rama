use std::{convert::Infallible, marker::PhantomData, num::NonZeroUsize};

use rama_core::{Service, error::BoxError, graceful::WeakScope};
use rama_net::{
    address::SocketAddress,
    client::{ConnectRequest, EstablishedClientConnection},
    test_utils::client::MakeMockServer,
};
use rama_udp::test_utils::MemoryDatagramSocket;

use crate::{Connection, Endpoint, ServerConfig, client::ClientEndpoint};

/// Mock QUIC connector for tests of clients and servers that speak QUIC, without
/// opening an actual socket: every request gets an in-memory datagram pair with a
/// server endpoint on the other side.
#[derive(Debug, Clone)]
pub struct MockQuicConnectorService<S, M> {
    create_server: S,
    server_config: ServerConfig,
    capacity: NonZeroUsize,
    scope: Option<WeakScope>,
    _marker: PhantomData<M>,
}

impl<S, M> MockQuicConnectorService<S, M> {
    pub fn new(server_config: ServerConfig, create_server: S) -> Self
    where
        S: MakeMockServer<Connection, M>,
    {
        Self {
            create_server,
            server_config,
            capacity: NonZeroUsize::MIN,
            scope: None,
            _marker: PhantomData,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the datagrams each side of the pair queues.
        pub fn capacity(mut self, capacity: NonZeroUsize) -> Self {
            self.capacity = capacity;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set `WeakScope` used for child tasks.
        pub fn scope(mut self, scope: Option<WeakScope>) -> Self {
            self.scope = scope;
            self
        }
    }
}

impl<S, M> Service<ConnectRequest> for MockQuicConnectorService<S, M>
where
    S: MakeMockServer<Connection, M, Server: Service<Connection, Error: Into<BoxError>> + Clone>
        + Send
        + Sync
        + 'static,
    M: Send + Sync + 'static,
{
    type Error = Infallible;
    type Output = EstablishedClientConnection<ClientEndpoint, ConnectRequest>;

    #[expect(
        clippy::panic,
        reason = "test helper: failures must surface loudly to invalidate the test run"
    )]
    async fn serve(&self, input: ConnectRequest) -> Result<Self::Output, Self::Error> {
        let (server_socket, client_socket) = MemoryDatagramSocket::pair(
            SocketAddress::local_ipv4(443),
            SocketAddress::local_ipv4(444),
            self.capacity,
        );
        let scope = self.scope.clone().unwrap_or_default();
        let held = match scope.try_hold() {
            Ok(held) => held,
            Err(err) => panic!("mock quic server not spawned: {err}"),
        };

        // An endpoint closes its connections as soon as its own scope is cancelled, so
        // serving runs in a child of the scope the endpoint was built in.
        let server = match Endpoint::build(&held)
            .with_server_config(self.server_config.clone())
            .with_datagram_socket(server_socket)
        {
            Ok(server) => server,
            Err(err) => panic!("mock quic server endpoint not built: {err}"),
        };
        let peer = match server.local_addr() {
            Ok(peer) => peer,
            Err(err) => panic!("mock quic server endpoint has no address: {err}"),
        };

        let service = PanicOnError(self.create_server.make_server(&input));
        let serving = WeakScope::from(held.child());
        let client = match Endpoint::build(&held).with_datagram_socket(client_socket) {
            Ok(client) => client,
            Err(err) => panic!("mock quic client endpoint not built: {err}"),
        };
        held.into_spawn_task(server.serve(serving, service));
        Ok(EstablishedClientConnection {
            input,
            conn: ClientEndpoint::new(client).with_peer(peer),
        })
    }
}

#[derive(Debug, Clone)]
struct PanicOnError<S>(S);

impl<S> Service<Connection> for PanicOnError<S>
where
    S: Service<Connection, Error: Into<BoxError>>,
{
    type Output = S::Output;
    type Error = Infallible;

    #[expect(
        clippy::panic,
        reason = "test helper: failures must surface loudly to invalidate the test run"
    )]
    async fn serve(&self, connection: Connection) -> Result<Self::Output, Self::Error> {
        match self.0.serve(connection).await {
            Ok(output) => Ok(output),
            Err(err) => panic!("created mock quic server failed: {}", err.into()),
        }
    }
}
