//! [`TcpListener] implementation.

use std::net::{SocketAddr, ToSocketAddrs};
use tokio::net::TcpStream;
use tower_async::{MakeService, Service};

/// Listens to incoming TCP connections and serves them with a [`tower_async::Service`].
///
/// That [`tower_async::Service`] is created by a [`tower_async::Service`] for each incoming connection.
///
/// [`tower_async::Service`]: https://docs.rs/tower-async/*/tower_async/trait.Service.html
#[derive(Debug)]
pub struct TcpListener<S> {
    listener: tokio::net::TcpListener,
    #[allow(dead_code)]
    state: S,
}

impl TcpListener<()> {
    /// Creates a new [`TcpListener`] bound to a local address with an open port.
    ///
    /// This [`TcpListener`] will use the default [`ErrorHandler`] to handle errors by simply
    /// logging them to the [`tracing`] subscriber. And will trigger a graceful shutdown
    /// only when the infamous "CTRL+C" signal (future) resolves.
    ///
    /// [`tracer`]: https://docs.rs/tracing/*/tracing/
    pub fn new() -> Result<Self, std::io::Error> {
        Self::bind("127.0.0.1:0")
    }

    /// Creates a new [`TcpListener`] bound to a given address.
    ///
    /// This [`TcpListener`] will use the default [`ErrorHandler`] to handle errors by simply
    /// logging them to the [`tracing`] subscriber. And will trigger a graceful shutdown
    /// only when the infamous "CTRL+C" signal (future) resolves.
    ///
    /// [`tracer`]: https://docs.rs/tracing/*/tracing/
    pub fn bind(addr: impl ToSocketAddrs) -> Result<Self, std::io::Error> {
        let std_listener = std::net::TcpListener::bind(addr)?;
        std_listener.try_into()
    }

    fn from_tcp_listener(listener: tokio::net::TcpListener) -> Self {
        tracing::info!(
            "TCP server bound to local address: {:?}",
            listener.local_addr()
        );
        Self {
            listener,
            state: (),
        }
    }
}

impl<S> TcpListener<S>
where
    S: Clone + Send + Sync + 'static,
{
    /// Sets a state for the [`TcpListener`].
    /// This state will be cloned for each incoming connection.
    pub fn state<T>(self, state: T) -> TcpListener<T>
    where
        T: Clone + Send + Sync + 'static,
    {
        TcpListener {
            listener: self.listener,
            state,
        }
    }

    /// Serves incoming connections with a [`tower_async::Service`] that acts as a factory,
    /// creating a new [`Service`] for each incoming connection,
    /// and exiting when the graceful signal is triggered.
    pub async fn serve_graceful<Factory>(
        self,
        mut service_factory: Factory,
    ) -> Result<(), Factory::MakeError>
    where
        Factory: MakeService<SocketAddr, TcpStream>,
        Factory::Service: Service<TcpStream, call(): Send> + Send + 'static,
        Factory::MakeError: std::error::Error,
        Factory::Error: std::error::Error + 'static,
        Factory::Response: Send + 'static,
        <Factory as MakeService<std::net::SocketAddr, TcpStream>>::Service: Send,
    {
        loop {
            let (socket, peer_addr) = tokio::select! {
                result = self.listener.accept() => {
                    match result{
                        Ok((socket, peer_addr)) => (socket, peer_addr),
                        Err(err) => {
                            tracing::error!(error = &err as &dyn std::error::Error, "TCP accept error");
                            continue;
                        }
                    }
                },
            };

            let mut service = service_factory.make_service(peer_addr).await?;

            tokio::spawn(async move {
                if let Err(err) = service.call(socket).await {
                    tracing::error!(
                        error = &err as &dyn std::error::Error,
                        "TCP service serve error"
                    );
                }
            });
        }
    }
}

impl From<tokio::net::TcpListener> for TcpListener<()> {
    fn from(listener: tokio::net::TcpListener) -> Self {
        Self::from_tcp_listener(listener)
    }
}

impl TryFrom<std::net::TcpListener> for TcpListener<()> {
    type Error = std::io::Error;

    fn try_from(listener: std::net::TcpListener) -> Result<Self, Self::Error> {
        listener.set_nonblocking(true)?;
        let listener = tokio::net::TcpListener::from_std(listener)?;
        Ok(Self::from_tcp_listener(listener))
    }
}
