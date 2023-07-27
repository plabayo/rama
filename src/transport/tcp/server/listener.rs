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
pub struct TcpListener<S, H> {
    listener: tokio::net::TcpListener,
    shutdown_timeout: Option<Duration>,
    graceful: GracefulService,
    err_handler: H,
    state: S,
}

impl TcpListener<private::NoState, private::DefaultErrorHandler> {
    /// Creates a new [`TcpListener`] bound to a local address with an open port.
    pub fn new() -> Result<Self, std::io::Error> {
        Self::bind("127.0.0.1:0")
    }

    /// Creates a new [`TcpListener`] bound to a given address.
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
            graceful: Default::default(),
            err_handler: Default::default(),
            state: private::NoState,
        }
    }
}

impl From<tokio::net::TcpListener> for TcpListener<private::NoState, private::DefaultErrorHandler> {
    fn from(listener: tokio::net::TcpListener) -> Self {
        Self::from_tcp_listener(listener)
    }
}

impl TryFrom<std::net::TcpListener>
    for TcpListener<private::NoState, private::DefaultErrorHandler>
{
    type Error = std::io::Error;

    fn try_from(listener: std::net::TcpListener) -> Result<Self, Self::Error> {
        listener.set_nonblocking(true)?;
        let listener = tokio::net::TcpListener::from_std(listener)?;
        Ok(Self::from_tcp_listener(listener))
    }
}

impl<H> TcpListener<private::NoState, H> {
    /// Sets a state for the [`TcpListener`],
    /// which will be passed to the [`tower_async::Service`] for each incoming connection.
    ///
    /// [`tower_async::Service`]: https://docs.rs/tower-async/*/tower_async/trait.Service.html
    pub fn state<S>(self, state: S) -> TcpListener<private::SomeState<S>, H>
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

impl<S> TcpListener<S, private::DefaultErrorHandler> {
    /// Sets an [``] for the [`TcpListener`].
    pub fn err_handler<H>(self, err_handler: impl Into<H>) -> TcpListener<S, H> {
        TcpListener {
            listener: self.listener,
            shutdown_timeout: self.shutdown_timeout,
            graceful: self.graceful,
            err_handler: err_handler.into(),
            state: self.state,
        }
    }
}

impl<S, H> TcpListener<S, H> {
    /// Sets a timeout for the [`TcpListener`] shutdown
    /// which will be used to wait a maximum amount of time for all services to finish.
    ///
    /// By default, the [`TcpListener`] will wait forever.
    pub fn shutdown_timeout(mut self, timeout: Duration) -> Self {
        self.shutdown_timeout = Some(timeout);
        self
    }

    /// Sets a graceful shutdown signal for the [`TcpListener`].
    ///
    /// By default, the [`TcpListener`] will use the Ctrl+C signal.
    pub fn graceful_signal(mut self, signal: impl Future + Send + 'static) -> Self {
        self.graceful = graceful::service(signal);
        self
    }
}

impl<S, H> TcpListener<S, H>
where
    H: ErrorHandler,
    S: private::IntoState,
    S::State: Clone + Send + 'static,
{
    /// Serves incoming connections with a [`tower_async::Service`] that acts as a factory,
    /// creating a new [`Service`] for each incoming connection.
    pub async fn serve<Factory>(mut self, mut service_factory: Factory) -> Result<(), Error>
    where
        Factory: MakeService<SocketAddr, Connection<TcpStream, S::State>>,
        // Factory::Service: Service<Connection<TcpStream, S::State>, call(): Send> + Send + 'static,
        Factory::Service: Service<Connection<TcpStream, S::State>> + Send + 'static,
        Factory::MakeError: Into<BoxError>,
        Factory::Error: Into<BoxError> + Send + 'static,
        <Factory as MakeService<
            std::net::SocketAddr,
            Connection<tokio::net::TcpStream, <S as private::IntoState>::State>,
        >>::Service: Send,
    {
        let state = self.state.into_state();

        // let (service_err_tx, mut service_err_rx) = tokio::sync::mpsc::unbounded_channel();
        loop {
            let (socket, peer_addr) = tokio::select! {
                // maybe_err = service_err_rx.recv() => {
                //     if let Some(err) = maybe_err {
                //         let error = Error::new(ErrorKind::Accept, err);
                //         self.err_handler.handle(error).await?;
                //     }
                //     continue;
                // },
                result = self.listener.accept() => {
                    match result{
                        Ok((socket, peer_addr)) => (socket, peer_addr),
                        Err(err) => {
                            let error = Error::new(ErrorKind::Accept, err);
                            self.err_handler.handle(error).await.map_err(|err| Error::new(ErrorKind::Accept, err))?;
                            continue;
                        }
                    }
                },
                _ = self.graceful.shutdown_req() => break,
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

            let token = self.graceful.token();
            let state = state.clone();
            // let service_err_tx = service_err_tx.clone();
            let conn: Connection<_, _> = Connection::new(socket, token, state);

            // TODO: enable this kind of features once again when
            // this bug is fixed: https://github.com/plabayo/tower-async/issues/9
            // tokio::spawn(async move {
            //     if let Err(err) = service.call(conn).await {
            //         let _ = service_err_tx.send(err);
            //     }
            // });

            if let Err(err) = service.call(conn).await {
                let error = Error::new(ErrorKind::Service, err);
                self.err_handler
                    .handle(error)
                    .await
                    .map_err(|err| Error::new(ErrorKind::Service, err))?;
            }
        }

        // wait for all services to finish
        if let Some(timeout) = self.shutdown_timeout {
            if let Err(err) = self.graceful.shutdown_until(timeout).await {
                debug!("TCP server shutdown error: {err}");
            }
        } else {
            self.graceful.shutdown().await;
        }

        // all services finished, return
        Ok(())
    }
}

mod private {
    use tower_async::BoxError;
    use tracing::{debug, error};

    use crate::transport::tcp::server::error::{Error, ErrorHandler, ErrorKind};

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
