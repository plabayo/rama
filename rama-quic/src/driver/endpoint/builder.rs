//! Building an endpoint on an application's own executor.
//!
//! Tasks are spawned through that executor onto the caller's Tokio runtime. An executor
//! carrying a graceful guard ties the endpoint to the application's shutdown.
//!
//! The supervisor takes the executor, and with it the strong guard. Endpoint handles hold only
//! a weak cancellation reference, so a handle the application keeps does not hold the shutdown
//! open.

use std::{io, time::Duration};

use rama_core::rt::Executor;
use rama_net::address::SocketAddress;
use rama_udp::{DatagramError, UdpPacketSocket, UdpSocketConfig, UdpSocketFactory};

use crate::driver::{
    EndpointConfig,
    endpoint::{Endpoint, bind_advertised},
    udp::Socket,
};
use crate::proto::ServerConfig;

/// How long a shutdown gives drivers to finish before it stops waiting and forces them.
pub const DEFAULT_SHUTDOWN_BUDGET: Duration = Duration::from_secs(5);

/// An endpoint being built: the runtime it will live on, what it is configured with, and the
/// socket it will bind.
#[derive(Debug, Clone)]
pub struct EndpointBuilder {
    exec: Executor,
    config: EndpointConfig,
    server_config: Option<ServerConfig>,
    socket_config: UdpSocketConfig,
    shutdown_budget: Duration,
}

impl EndpointBuilder {
    /// A builder that spawns through `exec`, with `config` as the endpoint's own
    /// configuration.
    #[must_use]
    pub fn new(exec: Executor, config: EndpointConfig) -> Self {
        Self {
            exec,
            config,
            server_config: None,
            socket_config: UdpSocketConfig::default(),
            shutdown_budget: DEFAULT_SHUTDOWN_BUDGET,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// The endpoint's own configuration.
        pub fn config(mut self, value: EndpointConfig) -> Self {
            self.config = value;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// What this endpoint serves incoming connections with. Without one it is a client.
        pub fn server_config(mut self, value: Option<ServerConfig>) -> Self {
            self.server_config = value;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// The socket options to bind with, and the packet features this endpoint requires. A
        /// feature the platform does not provide fails the bind rather than being dropped.
        pub fn socket_config(mut self, value: UdpSocketConfig) -> Self {
            self.socket_config = value;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// How long a shutdown gives the drivers before it stops waiting and forces them. Zero
        /// forces immediately.
        pub fn shutdown_budget(mut self, value: Duration) -> Self {
            self.shutdown_budget = value;
            self
        }
    }

    /// Bind the address, and the addresses this endpoint advertises as preferred with it.
    ///
    /// The advertised sockets are bound before the endpoint exists, so it advertises the
    /// addresses its sockets have, including ports the platform assigned.
    pub async fn bind_address(
        self,
        address: impl Into<SocketAddress>,
    ) -> Result<Endpoint, DatagramError> {
        let Self {
            exec,
            config,
            server_config,
            socket_config,
            shutdown_budget,
        } = self;
        let factory = UdpSocketFactory::new(socket_config);
        let listener = factory.bind(address.into()).await?;
        let (server_config, advertised) = bind_advertised(&factory, server_config).await?;
        let advertised = advertised
            .into_iter()
            .map(Socket::new)
            .collect::<io::Result<Vec<_>>>()?;
        Endpoint::new_with_advertised(
            config,
            server_config,
            Socket::new(listener)?,
            advertised,
            exec,
            shutdown_budget,
        )
        .map_err(DatagramError::from)
    }

    /// Build on a packet socket the caller prepared, with its packet metadata set up and its
    /// required features validated.
    ///
    /// The socket configuration this builder carries describes what to bind, so it takes no
    /// part here.
    pub fn with_packet_socket(self, socket: UdpPacketSocket) -> Result<Endpoint, DatagramError> {
        self.on_socket(Socket::new(socket).map_err(DatagramError::from)?)
    }

    /// Build on a bound standard socket. The packet metadata a [`UdpSocketConfig`] describes is
    /// not set up here; a caller that needs it wraps the socket first and uses
    /// [`with_packet_socket`](Self::with_packet_socket).
    pub fn with_std_socket(self, socket: std::net::UdpSocket) -> Result<Endpoint, DatagramError> {
        self.on_socket(Socket::from_std(socket).map_err(DatagramError::from)?)
    }

    /// Where a prepared socket becomes an endpoint.
    fn on_socket(self, socket: Socket) -> Result<Endpoint, DatagramError> {
        Endpoint::new_with_advertised(
            self.config,
            self.server_config,
            socket,
            Vec::new(),
            self.exec,
            self.shutdown_budget,
        )
        .map_err(DatagramError::from)
    }
}
