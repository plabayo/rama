use std::{
    convert::Infallible,
    future::{self, Future},
    net::{TcpListener as StdTcpListener, ToSocketAddrs},
    pin::Pin,
    sync::Arc,
    task::{ready, Context, Poll},
    time::Duration,
};

use pin_project_lite::pin_project;
use tokio::net::{TcpListener, TcpStream};

use crate::core::transport::{
    graceful::{self, TimeoutError},
    tcp::server::{Connection, Service, ServiceFactory, Stateful, Stateless},
};

#[derive(Debug)]
pub enum ListenerErrorKind {
    Accept,
    Service,
    Factory,
    Timeout,
}

#[derive(Debug)]
pub struct ListenerError {
    kind: ListenerErrorKind,
    source: Box<dyn std::error::Error>,
}

impl std::fmt::Display for ListenerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ListenerError({:?}): {}", self.kind, self.source)
    }
}

impl std::error::Error for ListenerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&*self.source)
    }
}

pub struct Listener<F, State> {
    tcp: TcpListener,
    service_factory: F,
    shutdown_timeout: Option<Duration>,
    graceful: graceful::GracefulService,
    state: State,
}

impl<F, State> Listener<F, State> {
    fn new<S: Future + Send + 'static>(
        tcp: TcpListener,
        service_factory: F,
        shutdown: S,
        shutdown_timeout: Option<Duration>,
        state: State,
    ) -> Self {
        let graceful = graceful::GracefulService::new(shutdown);
        Self {
            tcp,
            service_factory,
            shutdown_timeout,
            graceful,
            state,
        }
    }
}

enum ListenerEvent<Error> {
    Accept(std::io::Result<(TcpStream, std::net::SocketAddr)>),
    ServiceError(Error),
    Shutdown,
}

impl<F, State> Listener<F, State>
where
    F: ServiceFactory<State>,
    F::Service: Service<State> + Send + 'static,
    F::Error: 'static,
    <<F as ServiceFactory<State>>::Service as Service<State>>::Future: Send,
    <<F as ServiceFactory<State>>::Service as Service<State>>::Error: 'static,
    State: Clone + Send + 'static,
{
    async fn serve(self) -> Result<(), ListenerError> {
        let Self {
            tcp,
            mut service_factory,
            shutdown_timeout,
            graceful,
            state,
        } = self;

        let (error_tx, mut error_rx) = tokio::sync::mpsc::channel(1);

        loop {
            // listen for any listener event
            let event = tokio::select! {
                res = tcp.accept() => {
                    ListenerEvent::Accept(res)
                },
                opt = error_rx.recv() => {
                    ListenerEvent::ServiceError(opt.unwrap())
                },
                _ = graceful.shutdown_req() => ListenerEvent::Shutdown,
            };

            // handle the listner event
            let result = match event {
                ListenerEvent::Accept(res) => res,
                ListenerEvent::ServiceError(err) => {
                    Arc::new(
                        service_factory
                            .handle_service_error(err)
                            .await
                            .map_err(|err| ListenerError {
                                kind: ListenerErrorKind::Service,
                                source: Box::new(err),
                            }),
                    );
                    continue;
                }
                ListenerEvent::Shutdown => {
                    break;
                }
            };

            // handle the accept error or serve the incoming (tcp) stream
            match result {
                Err(err) => service_factory
                    .handle_accept_error(err.into())
                    .await
                    .map_err(|err| ListenerError {
                        kind: ListenerErrorKind::Accept,
                        source: Box::new(err),
                    })?,
                Ok((stream, _)) => {
                    let mut service =
                        service_factory
                            .new_service()
                            .await
                            .map_err(|err| ListenerError {
                                kind: ListenerErrorKind::Accept,
                                source: Box::new(err),
                            })?;
                    let error_tx = error_tx.clone();
                    let token = graceful.token();
                    let state = state.clone();
                    tokio::spawn(async move {
                        let conn = Connection::new(stream, token, state);
                        if let Err(err) = service.call(conn).await {
                            // try to send the error to the main loop
                            let _ = error_tx.send(err).await;
                        }
                    });
                }
            }
        }

        // wait for all services to finish
        if let Some(timeout) = shutdown_timeout {
            graceful.shutdown_until(timeout).await
        } else {
            graceful.shutdown().await;
            Ok(())
        }
        .map_err(|err| {
            ListenerError {
                kind: ListenerErrorKind::Timeout,
                source: Box::new(err),
            }
        })
    }
}

impl Listener<(), ()> {
    pub fn bind<A: ToSocketAddrs>(addr: A) -> Builder<SocketConfig<StdTcpListener>, (), Stateless> {
        match Self::try_bind(addr) {
            Ok(incoming) => incoming,
            Err(err) => panic!("failed to bind tcp listener: {}", err),
        }
    }

    pub fn try_bind<A: ToSocketAddrs>(
        addr: A,
    ) -> Result<Builder<SocketConfig<StdTcpListener>, (), Stateless>, std::io::Error> {
        let incoming = StdTcpListener::bind(addr)?;
        incoming.set_nonblocking(true)?;
        Ok(Self::build(incoming))
    }

    pub fn build(incoming: StdTcpListener) -> Builder<SocketConfig<StdTcpListener>, (), Stateless> {
        Builder::new(incoming, (), Stateless(()))
    }
}

pub struct Builder<I, G, S> {
    incoming: I,
    graceful: G,
    state: S,
}

pub struct SocketConfig<L> {
    listener: L,
    ttl: Option<u32>,
}

pub struct GracefulConfig<S> {
    shutdown: S,
    timeout: Option<Duration>,
}

impl<I, G> Builder<I, G, Stateless> {
    pub fn state<S>(self, state: S) -> Builder<I, G, Stateful<S>> {
        Builder {
            incoming: self.incoming,
            graceful: self.graceful,
            state: Stateful(state),
        }
    }
}

impl<G, S> Builder<SocketConfig<StdTcpListener>, G, S> {
    /// Create a new `Builder` with the specified address.
    pub fn new(listener: StdTcpListener, graceful: G, state: S) -> Self {
        Self {
            incoming: SocketConfig {
                listener,
                ttl: None,
            },
            graceful,
            state,
        }
    }

    /// Set the value of `IP_TTL` option for accepted connections.
    ///
    /// If `None` is specified, ttl is not explicitly set.
    pub fn ttl(mut self, ttl: Option<u32>) -> Self {
        self.incoming.ttl = ttl;
        self
    }
}

impl<I, S, State> Builder<I, GracefulConfig<S>, State> {
    /// Upgrade the builder to one which builds
    /// a graceful TCP listener which will shutdown once the given future resolves.
    pub fn graceful(self, shutdown: S) -> Builder<I, GracefulConfig<S>, State> {
        Builder {
            incoming: self.incoming,
            graceful: GracefulConfig {
                shutdown,
                timeout: None,
            },
            state: self.state,
        }
    }
}

impl<I, State, F: Future<Output = ()>> Builder<I, GracefulConfig<F>, State> {
    /// Upgrade the builder to one which builds
    /// a graceful TCP listener which will shutdown once the "ctrl+c" signal is received (SIGINT).
    pub fn graceful_ctrl_c(self) -> Builder<I, GracefulConfig<impl Future<Output = ()>>, State> {
        self.graceful(async {
            let _ = tokio::signal::ctrl_c().await;
        })
    }
}

impl<I, S, State> Builder<I, GracefulConfig<S>, State> {
    /// Set the timeout for graceful shutdown.
    ///
    /// If `None` is specified, the default timeout is used.
    pub fn timeout(mut self, timeout: Option<Duration>) -> Self {
        self.graceful.timeout = timeout;
        self
    }
}

pub trait ToTcpListener {
    type Error;
    type Future: Future<Output = Result<TcpListener, Self::Error>>;

    fn into_tcp_listener(self) -> Self::Future;
}

impl ToTcpListener for TcpListener {
    type Error = Infallible;
    type Future = future::Ready<Result<TcpListener, Self::Error>>;

    fn into_tcp_listener(self) -> Self::Future {
        future::ready(Ok(self))
    }
}

pin_project! {
    pub struct SocketConfigToTcpListenerFuture<F> {
        #[pin]
        future: F,
        ttl: Option<u32>,
    }
}

impl<F, E> Future for SocketConfigToTcpListenerFuture<F>
where
    F: Future<Output = Result<TcpListener, E>>,
{
    type Output = Result<TcpListener, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let listener = ready!(this.future.poll(cx))?;
        if let Some(ttl) = this.ttl {
            listener.set_ttl(*ttl)?;
        }
        Poll::Ready(Ok(listener))
    }
}

impl ToTcpListener for SocketConfig<StdTcpListener> {
    type Error = std::io::Error;
    type Future = SocketConfigToTcpListenerFuture<future::Ready<Result<TcpListener, Self::Error>>>;

    fn into_tcp_listener(self) -> Self::Future {
        let listener = TcpListener::from_std(self.listener);
        let future = future::ready(listener);
        SocketConfigToTcpListenerFuture {
            future,
            ttl: self.ttl,
        }
    }
}

impl<T, State> Builder<T, (), State>
where
    T: ToTcpListener,
{
    pub async fn serve<F>(self, service_factory: F) -> Result<(), Box<dyn std::error::Error>>
    where
        F: ServiceFactory<State>,
        F::Service: Service<State> + Send + 'static,
        F::Error: std::error::Error + 'static,
        <<F as ServiceFactory<State>>::Service as Service<State>>::Future: Send,
        <<F as ServiceFactory<State>>::Service as Service<State>>::Error: std::error::Error + 'static,
        State: Clone + Send + 'static,
    {
        // create and configure the tcp listener...
        let listener = self.incoming.into_tcp_listener().await.map_err(Box::new)?;

        // listen without any grace..
        Listener::new(
            listener,
            service_factory,
            future::pending(),
            None,
            self.state,
        )
        .serve()
        .await
        .map_err(Box::new)
    }
}

impl<T, S, State> Builder<T, GracefulConfig<S>, State>
where
    T: ToTcpListener,
    S: Future + Send + 'static,
{
    pub async fn serve<F>(self, service_factory: F) -> Result<(), Box<dyn std::error::Error>>
    where
        F: ServiceFactory<State>,
        F::Service: Service<State> + Send + 'static,
        <<F as ServiceFactory<State>>::Service as Service<State>>::Future: Send,
    {
        // create and configure the tcp listener...
        let listener = self.incoming.into_tcp_listener().await?;

        // listen gracefully..
        Listener::new(
            listener,
            service_factory,
            self.kind.shutdown,
            self.kind.timeout,
            self.error_handler,
        )
        .serve()
        .await
    }
}
