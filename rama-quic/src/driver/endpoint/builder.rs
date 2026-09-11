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
    config: Option<EndpointConfig>,
    server_config: Option<ServerConfig>,
    shutdown_budget: Duration,
}

impl EndpointBuilder {
    /// Build a client endpoint whose tasks run through `exec`.
    ///
    /// Unless configured otherwise, construction generates a fresh secret reset key.
    /// A random-source failure is returned when binding or attaching a socket.
    #[must_use]
    pub fn new(exec: Executor) -> Self {
        Self {
            exec,
            config: None,
            server_config: None,
            shutdown_budget: DEFAULT_SHUTDOWN_BUDGET,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// The endpoint configuration; when omitted, construction generates a random reset key.
        pub fn config(mut self, value: Option<EndpointConfig>) -> Self {
            self.config = value;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// What this endpoint serves incoming connections with
        ///
        /// Without a server config, the default, it is a client.
        pub fn server_config(mut self, value: Option<ServerConfig>) -> Self {
            self.server_config = value;
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
        self.bind_address_with_socket_config(address, UdpSocketConfig::default())
            .await
    }

    /// Same as [`Self::bind_address`] but with custom [`UdpSocketConfig`].
    pub async fn bind_address_with_socket_config(
        self,
        address: impl Into<SocketAddress>,
        socket_config: UdpSocketConfig,
    ) -> Result<Endpoint, DatagramError> {
        let Self {
            exec,
            config,
            server_config,
            shutdown_budget,
        } = self;

        let config = match config {
            Some(config) => config,
            None => EndpointConfig::try_with_rand_key().map_err(io::Error::other)?,
        };
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
    /// This does not bind preferred-address sockets or change the supplied socket options.
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
        let Self {
            exec,
            config,
            server_config,
            shutdown_budget,
        } = self;

        let config = match config {
            Some(config) => config,
            None => EndpointConfig::try_with_rand_key().map_err(io::Error::other)?,
        };

        Endpoint::new_with_advertised(
            config,
            server_config,
            socket,
            Vec::new(),
            exec,
            shutdown_budget,
        )
        .map_err(DatagramError::from)
    }
}
