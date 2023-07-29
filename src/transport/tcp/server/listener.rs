//! [`TcpListener] implementation.

use std::{
    future::Future,
    net::{SocketAddr, ToSocketAddrs},
    time::Duration,
};
use tokio::net::TcpStream;
use tower_async::{BoxError, MakeService, Service};
use tracing::{debug, info};

use self::private::DefaultErrorHandler;

use super::error::{Error, ErrorHandler, ErrorKind};
use crate::transport::Connection;

/// Listens to incoming TCP connections and serves them with a [`tower_async::Service`].
///
/// That [`tower_async::Service`] is created by a [`tower_async::Service`] for each incoming connection.
///
/// [`tower_async::Service`]: https://docs.rs/tower-async/*/tower_async/trait.Service.html
#[derive(Debug)]
pub struct TcpListener<H, S> {
    listener: tokio::net::TcpListener,
    shutdown_timeout: Option<Duration>,
    graceful: private::GracefulKind,
    err_handler: H,
    state: S,
}

impl TcpListener<private::DefaultErrorHandler, ()> {
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
        info!(
            "TCP server bound to local address: {:?}",
            listener.local_addr()
        );
        Self {
            listener,
            shutdown_timeout: None,
            graceful: private::GracefulKind::Default,
            err_handler: private::DefaultErrorHandler,
            state: (),
        }
    }
}

impl<H, S> TcpListener<H, S>
where
    H: ErrorHandler<handle_service_err(): Send>,
    S: Clone + Send + Sync + 'static,
{
    /// Sets an [`ErrorHandler`] for the [`TcpListener`].
    pub fn err_handler<E>(self, err_handler: E) -> TcpListener<E, S>
    where
        E: ErrorHandler<handle_service_err(): Send>,
    {
        TcpListener {
            listener: self.listener,
            shutdown_timeout: self.shutdown_timeout,
            graceful: self.graceful,
            err_handler,
            state: self.state,
        }
    }

    /// Sets a state for the [`TcpListener`].
    /// This state will be cloned for each incoming connection.
    pub fn state<T>(self, state: T) -> TcpListener<H, T>
    where
        T: Clone + Send + Sync + 'static,
    {
        TcpListener {
            listener: self.listener,
            shutdown_timeout: self.shutdown_timeout,
            graceful: self.graceful,
            err_handler: self.err_handler,
            state,
        }
    }

    /// Sets a timeout for the [`TcpListener`] shutdown
    /// which will be used to wait a maximum amount of time for all services to finish.
    ///
    /// By default, the [`TcpListener`] will wait forever.
    pub fn shutdown_timeout(&mut self, timeout: Duration) -> &mut Self {
        self.shutdown_timeout = Some(timeout);
        self
    }

    /// Sets an instant shutdown for the [`TcpListener`]
    /// which will be used to shutdown immediately after the first critical error occurs or
    /// the graceful shutdown signal is triggered.
    ///
    /// By default, the [`TcpListener`] will wait forever.
    pub fn instant_shutdown(&mut self) -> &mut Self {
        self.shutdown_timeout = Some(Duration::from_secs(0));
        self
    }

    /// Sets a graceful shutdown signal for the [`TcpListener`].
    ///
    /// By default, the [`TcpListener`] will use the Ctrl+C signal.
    pub fn graceful_signal(
        &mut self,
        signal: impl Future<Output = ()> + Send + 'static,
    ) -> &mut Self {
        self.graceful = private::GracefulKind::Signal(Box::pin(signal));
        self
    }

    /// Configures the [`TcpListener`] to use the SIGTERM signal
    /// to trigger a graceful shutdown (instead of the by default used "Ctrl+C" signal).
    #[cfg(unix)]
    pub fn graceful_sigterm(&mut self) -> &mut Self {
        self.graceful = private::GracefulKind::Sigterm;
        self
    }

    /// Sets a graceful shutdown for the [`TcpListener`]
    /// as a manual trigger only.
    ///
    /// This means that the [`TcpListener`] will not use any signal
    /// to trigger a graceful shutdown, but instead will wait for a manual trigger,
    /// which is only called when a fatal error occurs.
    pub fn graceful_without_signal(&mut self) -> &mut Self {
        self.graceful = private::GracefulKind::NoSignal;
        self
    }

    /// Serves incoming connections with a [`tower_async::Service`] that acts as a factory,
    /// creating a new [`Service`] for each incoming connection.
    pub async fn serve<Factory>(mut self, mut service_factory: Factory) -> Result<(), Error>
    where
        Factory: MakeService<SocketAddr, Connection<TcpStream, S>>,
        Factory::Service: Service<Connection<TcpStream, S>, call(): Send> + Send + 'static,
        Factory::MakeError: Into<BoxError>,
        Factory::Error: Into<BoxError> + Send + 'static,
        Factory::Response: Send + 'static,
        <Factory as MakeService<
            std::net::SocketAddr,
            Connection<tokio::net::TcpStream, S>,
        >>::Service: Send,
    {
        let graceful = self.graceful.service();

        let (service_err_tx, mut service_err_rx) = tokio::sync::mpsc::channel(1);
        loop {
            let (socket, peer_addr) = tokio::select! {
                maybe_err = service_err_rx.recv() => {
                    if let Some(err) = maybe_err {
                        graceful.trigger_shutdown().await;
                        if let Err(delay_err) = graceful.shutdown_gracefully(self.shutdown_timeout).await {
                            debug!("TCP server: graceful delay error: {} (while waiting to fail on service err: {})", delay_err, err)
                        }
                        return Err(err);
                    }
                    continue;
                },
                result = self.listener.accept() => {
                    match result{
                        Ok((socket, peer_addr)) => (socket, peer_addr),
                        Err(err) => {
                            if let Err(err) = self.err_handler.handle_accept_err(err).await.map_err(Into::into) {
                                graceful.trigger_shutdown().await;
                                if let Err(delay_err) = graceful.shutdown_gracefully(self.shutdown_timeout).await {
                                    debug!("TCP server: graceful delay error: {} (while waiting to fail on accept err: {})", delay_err, err)
                                }
                                return Err(Error::new(ErrorKind::Accept, err));
                            }
                            continue;
                        }
                    }
                },
                _ = graceful.shutdown_triggered() => {
                    return graceful.shutdown_gracefully(self.shutdown_timeout).await.map_err(|err| Error::new(ErrorKind::Timeout, err));
                },
            };

            let mut service = match service_factory.make_service(peer_addr).await {
                Ok(service) => service,
                Err(err) => {
                    self.err_handler
                        .handle_factory_err(err.into())
                        .await
                        .map_err(|err| Error::new(ErrorKind::Factory, err))?;
                    continue;
                }
            };

            let token = graceful.token();
            let state = self.state.clone();
            let service_err_tx = service_err_tx.clone();

            let mut err_handler = self.err_handler.clone();
            let conn: Connection<_, _> = Connection::new(socket, token, state);

            tokio::spawn(async move {
                if let Err(err) = service.call(conn).await {
                    if let Err(err) = err_handler
                        .handle_service_err(err.into())
                        .await
                        .map_err(|err| Error::new(ErrorKind::Service, err))
                    {
                        service_err_tx.send(err).await.ok();
                    }
                }
            });
        }
    }
}

impl From<tokio::net::TcpListener> for TcpListener<DefaultErrorHandler, ()> {
    fn from(listener: tokio::net::TcpListener) -> Self {
        Self::from_tcp_listener(listener)
    }
}

impl TryFrom<std::net::TcpListener> for TcpListener<DefaultErrorHandler, ()> {
    type Error = std::io::Error;

    fn try_from(listener: std::net::TcpListener) -> Result<Self, Self::Error> {
        listener.set_nonblocking(true)?;
        let listener = tokio::net::TcpListener::from_std(listener)?;
        Ok(Self::from_tcp_listener(listener))
    }
}

mod private {
    use std::pin::Pin;

    use crate::transport::{tcp::server::error::ErrorHandler, GracefulService};

    pub enum GracefulKind {
        Default,
        Sigterm,
        Signal(Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>>),
        NoSignal,
    }

    impl GracefulKind {
        pub fn service(self) -> GracefulService {
            match self {
                Self::Default => GracefulService::default(),
                Self::Sigterm => GracefulService::sigterm(),
                Self::Signal(signal) => GracefulService::new(signal),
                Self::NoSignal => GracefulService::pending(),
            }
        }
    }

    impl std::fmt::Debug for GracefulKind {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Default => write!(f, "Default"),
                Self::Sigterm => write!(f, "Sigterm"),
                Self::Signal(_) => write!(f, "Signal"),
                Self::NoSignal => write!(f, "NoSignal"),
            }
        }
    }

    #[derive(Debug, Clone, Copy, Default)]
    pub struct DefaultErrorHandler;

    impl std::fmt::Display for DefaultErrorHandler {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "(DefaultErrorHandler)")
        }
    }

    impl ErrorHandler for DefaultErrorHandler {
        type Error = std::convert::Infallible;
    }
}
