//! [`TcpListener] implementation.

use std::{
    future::Future,
    net::{SocketAddr, ToSocketAddrs},
    time::Duration,
};
use tokio::net::TcpStream;
use tower_async::{BoxError, MakeService, Service};
use tracing::{debug, info};

use super::error::{Error, ErrorHandler, ErrorKind};
use crate::transport::{graceful, Connection, GracefulService};

/// Listens to incoming TCP connections and serves them with a [`tower_async::Service`].
///
/// That [`tower_async::Service`] is created by a [`tower_async::Service`] for each incoming connection.
///
/// [`tower_async::Service`]: https://docs.rs/tower-async/*/tower_async/trait.Service.html
#[derive(Debug)]
pub struct TcpListener<S, H, G, D> {
    listener: tokio::net::TcpListener,
    shutdown_timeout: D,
    graceful: G,
    err_handler: H,
    state: S,
}

impl
    TcpListener<
        private::NoState,
        private::DefaultErrorHandler,
        private::DefaultGracefulService,
        private::NoShutdownTimeout,
    >
{
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
            shutdown_timeout: private::NoShutdownTimeout,
            graceful: private::DefaultGracefulService,
            err_handler: Default::default(),
            state: private::NoState,
        }
    }
}

impl From<tokio::net::TcpListener>
    for TcpListener<
        private::NoState,
        private::DefaultErrorHandler,
        private::DefaultGracefulService,
        private::NoShutdownTimeout,
    >
{
    fn from(listener: tokio::net::TcpListener) -> Self {
        Self::from_tcp_listener(listener)
    }
}

impl TryFrom<std::net::TcpListener>
    for TcpListener<
        private::NoState,
        private::DefaultErrorHandler,
        private::DefaultGracefulService,
        private::NoShutdownTimeout,
    >
{
    type Error = std::io::Error;

    fn try_from(listener: std::net::TcpListener) -> Result<Self, Self::Error> {
        listener.set_nonblocking(true)?;
        let listener = tokio::net::TcpListener::from_std(listener)?;
        Ok(Self::from_tcp_listener(listener))
    }
}

impl<H, G, D> TcpListener<private::NoState, H, G, D> {
    /// Sets a state for the [`TcpListener`],
    /// which will be passed to the [`tower_async::Service`] for each incoming connection.
    ///
    /// [`tower_async::Service`]: https://docs.rs/tower-async/*/tower_async/trait.Service.html
    pub fn state<S>(self, state: S) -> TcpListener<private::SomeState<S>, H, G, D>
    where
        S: Clone + Send + 'static,
    {
        TcpListener {
            listener: self.listener,
            shutdown_timeout: self.shutdown_timeout,
            graceful: self.graceful,
            err_handler: self.err_handler,
            state: private::SomeState(state),
        }
    }
}

impl<S, G, D> TcpListener<S, private::DefaultErrorHandler, G, D> {
    /// Sets an [``] for the [`TcpListener`].
    pub fn err_handler<H>(self, err_handler: H) -> TcpListener<S, H, G, D>
    where
        H: ErrorHandler<handle(): Send> + Send + Clone + 'static,
    {
        TcpListener {
            listener: self.listener,
            shutdown_timeout: self.shutdown_timeout,
            graceful: self.graceful,
            err_handler,
            state: self.state,
        }
    }
}

impl<S, H, G> TcpListener<S, H, G, private::NoShutdownTimeout> {
    /// Sets a timeout for the [`TcpListener`] shutdown
    /// which will be used to wait a maximum amount of time for all services to finish.
    ///
    /// By default, the [`TcpListener`] will wait forever.
    pub fn shutdown_timeout(
        self,
        timeout: Duration,
    ) -> TcpListener<S, H, G, private::ShutdownTimeout> {
        TcpListener {
            listener: self.listener,
            shutdown_timeout: private::ShutdownTimeout(timeout),
            graceful: self.graceful,
            err_handler: self.err_handler,
            state: self.state,
        }
    }

    /// Sets an instant shutdown for the [`TcpListener`]
    /// which will be used to shutdown immediately after the first critical error occurs or
    /// the graceful shutdown signal is triggered.
    ///
    /// By default, the [`TcpListener`] will wait forever.
    pub fn instant_shutdown(self) -> TcpListener<S, H, G, private::InstantShutdown> {
        TcpListener {
            listener: self.listener,
            shutdown_timeout: private::InstantShutdown,
            graceful: self.graceful,
            err_handler: self.err_handler,
            state: self.state,
        }
    }
}

impl<S, H, D> TcpListener<S, H, private::DefaultGracefulService, D> {
    /// Sets a graceful shutdown signal for the [`TcpListener`].
    ///
    /// By default, the [`TcpListener`] will use the Ctrl+C signal.
    pub fn graceful_signal(
        self,
        signal: impl Future + Send + 'static,
    ) -> TcpListener<S, H, private::CustomGracefulService, D> {
        TcpListener {
            listener: self.listener,
            shutdown_timeout: self.shutdown_timeout,
            graceful: private::CustomGracefulService(graceful::service(signal)),
            err_handler: self.err_handler,
            state: self.state,
        }
    }

    /// Configures the [`TcpListener`] to use the SIGTERM signal
    /// to trigger a graceful shutdown (instead of the by default used "Ctrl+C" signal).
    #[cfg(unix)]
    pub fn graceful_sigterm(self) -> TcpListener<S, H, private::CustomGracefulService, D> {
        TcpListener {
            listener: self.listener,
            shutdown_timeout: self.shutdown_timeout,
            graceful: private::CustomGracefulService(GracefulService::sigterm()),
            err_handler: self.err_handler,
            state: self.state,
        }
    }

    /// Sets a graceful shutdown for the [`TcpListener`]
    /// as a manual trigger only.
    ///
    /// This means that the [`TcpListener`] will not use any signal
    /// to trigger a graceful shutdown, but instead will wait for a manual trigger,
    /// which is only called when a fatal error occurs.
    pub fn graceful_without_signal(self) -> TcpListener<S, H, private::CustomGracefulService, D> {
        TcpListener {
            listener: self.listener,
            shutdown_timeout: self.shutdown_timeout,
            graceful: private::CustomGracefulService(GracefulService::pending()),
            err_handler: self.err_handler,
            state: self.state,
        }
    }
}

impl<S, H, G, D> TcpListener<S, H, G, D>
where
    H: ErrorHandler<handle(): Send> + Send + Clone + 'static,
    S: private::IntoState,
    G: Into<GracefulService>,
    D: private::IntoShutdownTimeout,
    S::State: Clone + Send + 'static,
{
    /// Serves incoming connections with a [`tower_async::Service`] that acts as a factory,
    /// creating a new [`Service`] for each incoming connection.
    pub async fn serve<Factory>(mut self, mut service_factory: Factory) -> Result<(), Error>
    where
        Factory: MakeService<SocketAddr, Connection<TcpStream, S::State>>,
        Factory::Service: Service<Connection<TcpStream, S::State>, call(): Send> + Send + 'static,
        Factory::MakeError: Into<BoxError>,
        Factory::Error: Into<BoxError> + Send + 'static,
        Factory::Response: Send + 'static,
        <Factory as MakeService<
            std::net::SocketAddr,
            Connection<tokio::net::TcpStream, <S as private::IntoState>::State>,
        >>::Service: Send,
    {
        let state = self.state.into_state();
        let graceful = self.graceful.into();
        let shutdown_timeout = self.shutdown_timeout.into_shutdown_timeout();

        let (service_err_tx, mut service_err_rx) = tokio::sync::mpsc::channel(1);
        loop {
            let (socket, peer_addr) = tokio::select! {
                maybe_err = service_err_rx.recv() => {
                    if let Some(err) = maybe_err {
                        graceful.trigger_shutdown().await;
                        graceful_delay(graceful, shutdown_timeout).await;
                        return Err(err);
                    }
                    continue;
                },
                result = self.listener.accept() => {
                    match result{
                        Ok((socket, peer_addr)) => (socket, peer_addr),
                        Err(err) => {
                            let error = Error::new(ErrorKind::Accept, err);
                            if let Err(err) = self.err_handler.handle(error).await.map_err(|err| Error::new(ErrorKind::Accept, err)) {
                                graceful.trigger_shutdown().await;
                                graceful_delay(graceful, shutdown_timeout).await;
                                return Err(err);
                            }
                            continue;
                        }
                    }
                },
                _ = graceful.shutdown_req() => {
                    graceful_delay(graceful, shutdown_timeout).await;
                    return Ok(());
                },
            };

            let mut service = match service_factory.make_service(peer_addr).await {
                Ok(service) => service,
                Err(err) => {
                    let error = Error::new(ErrorKind::Factory, err);
                    self.err_handler
                        .handle(error)
                        .await
                        .map_err(|err| Error::new(ErrorKind::Factory, err))?;
                    continue;
                }
            };

            let token = graceful.token();
            let state = state.clone();
            let service_err_tx = service_err_tx.clone();

            let mut err_handler = self.err_handler.clone();
            let conn: Connection<_, _> = Connection::new(socket, token, state);

            tokio::spawn(async move {
                if let Err(err) = service.call(conn).await {
                    let error = Error::new(ErrorKind::Service, err);
                    if let Err(err) = err_handler
                        .handle(error)
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

async fn graceful_delay(service: GracefulService, maybe_timeout: Option<Duration>) {
    if let Some(timeout) = maybe_timeout {
        if let Err(err) = service.shutdown_until(timeout).await {
            debug!("TCP server shutdown error: {err}");
        }
    } else {
        service.shutdown().await;
    }
}

mod private {
    use tower_async::BoxError;
    use tracing::{debug, error};

    use crate::transport::{
        tcp::server::error::{Error, ErrorHandler, ErrorKind},
        GracefulService,
    };

    /// Marker trait for the [`super::TcpListener`] to indicate
    /// no state is defined, meaning we'll fallback to the empty type `()`.
    #[derive(Debug)]
    pub struct NoState;

    /// Marker trait for the [`super::TcpListener`] to indicate
    /// some state is defined, meaning we'll use the type `T` in the end for the
    /// passed down [`crate::transport::Connection`].
    #[derive(Debug)]
    pub struct SomeState<T>(pub T);

    pub trait IntoState {
        type State;

        fn into_state(self) -> Self::State;
    }

    impl IntoState for NoState {
        type State = ();

        fn into_state(self) -> Self::State {}
    }

    impl<T> IntoState for SomeState<T> {
        type State = T;

        fn into_state(self) -> Self::State {
            self.0
        }
    }

    /// Marker trait for the [`super::TcpListener`] to indicate
    /// no custom [`crate::graceful::GracefulService`] is defined, meaning we'll fallback to the
    /// default [`crate::graceful::GracefulService`].
    ///
    /// It also means one can still be defined in the [`super::TcpListener`].
    #[derive(Debug)]
    pub struct DefaultGracefulService;

    /// Marker trait for the [`super::TcpListener`] to indicate
    /// that a custom [`crate::graceful::GracefulService`] is defined, meaning we'll fallback to the
    /// default [`crate::graceful::GracefulService`].
    ///
    /// It also means that no other can be defined in the [`super::TcpListener`].
    #[derive(Debug)]
    pub struct CustomGracefulService(pub GracefulService);

    impl From<DefaultGracefulService> for GracefulService {
        fn from(_: DefaultGracefulService) -> Self {
            Self::default()
        }
    }

    impl From<CustomGracefulService> for GracefulService {
        fn from(service: CustomGracefulService) -> Self {
            service.0
        }
    }

    /// Marker trait for the [`super::TcpListener`] to indicate
    /// no shutdown timeout is requested and thus that we'll wait
    /// until all services are finished, no matter how long it takes.
    #[derive(Debug)]
    pub struct NoShutdownTimeout;

    /// Marker trait for the [`super::TcpListener`] to indicate
    /// an instant shutdown is requested and thus that we'll shutdown
    /// immediately after the first critical error occurs or
    /// the graceful shutdown signal is triggered.
    #[derive(Debug)]
    pub struct InstantShutdown;

    /// Marker trait for the [`super::TcpListener`] to indicate
    /// a custom shutdown timeout is requested and thus that we'll wait
    /// until all services are finished or the timeout is reached.
    #[derive(Debug)]
    pub struct ShutdownTimeout(pub std::time::Duration);

    pub trait IntoShutdownTimeout {
        fn into_shutdown_timeout(self) -> Option<std::time::Duration>;
    }

    impl IntoShutdownTimeout for NoShutdownTimeout {
        fn into_shutdown_timeout(self) -> Option<std::time::Duration> {
            None
        }
    }

    impl IntoShutdownTimeout for InstantShutdown {
        fn into_shutdown_timeout(self) -> Option<std::time::Duration> {
            Some(std::time::Duration::from_secs(0))
        }
    }

    impl IntoShutdownTimeout for ShutdownTimeout {
        fn into_shutdown_timeout(self) -> Option<std::time::Duration> {
            Some(self.0)
        }
    }

    #[derive(Debug, Clone, Copy, Default)]
    pub struct DefaultErrorHandler;

    impl ErrorHandler for DefaultErrorHandler {
        async fn handle(&mut self, error: Error) -> std::result::Result<(), BoxError> {
            match error.kind() {
                ErrorKind::Accept => {
                    error!("TCP server accept error: {}", error);
                }
                ErrorKind::Service => {
                    debug!("TCP server service error: {}", error);
                }
                ErrorKind::Factory => {
                    debug!("TCP server factory error: {}", error);
                }
            }
            Ok(())
        }
    }
}
