use std::{
    future::{self, Future},
    net::{TcpListener as StdTcpListener, ToSocketAddrs},
    pin::Pin,
    task::{ready, Context, Poll},
    time::Duration,
};

use pin_project_lite::pin_project;
use tokio::net::{TcpListener, TcpStream};

use crate::core::transport::graceful;

use super::{
    Error, ErrorHandler, GracefulTcpStream, LogErrorHandler, Result, Service, ServiceFactory,
};

pub struct Listener<F, E> {
    tcp: TcpListener,
    service_factory: F,
    error_handler: E,
}

impl<F, E> Listener<F, E> {
    fn new(tcp: TcpListener, service_factory: F, error_handler: E) -> Self {
        Self {
            tcp,
            service_factory,
            error_handler,
        }
    }
}

impl<F, E> Listener<F, E>
where
    F: ServiceFactory<TcpStream>,
    F::Service: Service<TcpStream> + Send + 'static,
    <<F as ServiceFactory<TcpStream>>::Service as Service<TcpStream>>::Future: Send,
    E: ErrorHandler,
{
    async fn serve(self) -> Result<()> {
        let Self {
            tcp,
            mut service_factory,
            error_handler,
        } = self;

        let (error_tx, mut error_rx) = tokio::sync::mpsc::channel(1);

        loop {
            // accept incoming stream or handle a service error
            let result = tokio::select! {
                res = tcp.accept() => {
                    Ok(res)
                },
                opt = error_rx.recv() => {
                    Err(opt.unwrap())
                },
            };

            // unwrap the accept result if no service error was (yet) returned
            let result = match result {
                Ok(res) => res,
                Err(err) => {
                    error_handler.handle_service_error(err).await?;
                    continue;
                }
            };

            // handle the accept error or serve the incoming (tcp) stream
            match result {
                Err(err) => error_handler.handle_accept_error(err.into()).await?,
                Ok((stream, _)) => {
                    let mut service = service_factory.new_service()?;
                    let error_tx = error_tx.clone();
                    tokio::spawn(async move {
                        if let Err(err) = service.call(stream).await {
                            // try to send the error to the main loop
                            let _ = error_tx.send(err).await;
                        }
                    });
                }
            }
        }
    }
}

pub struct GracefulListener<F, E> {
    tcp: TcpListener,
    service_factory: F,
    shutdown_timeout: Option<Duration>,
    graceful: graceful::GracefulService,
    error_handler: E,
}

impl<F, E> GracefulListener<F, E> {
    fn new<S: Future + Send + 'static>(
        tcp: TcpListener,
        service_factory: F,
        shutdown: S,
        shutdown_timeout: Option<Duration>,
        error_handler: E,
    ) -> Self {
        let graceful = graceful::GracefulService::new(shutdown);
        Self {
            tcp,
            service_factory,
            shutdown_timeout,
            graceful,
            error_handler,
        }
    }
}

enum GracefulListenerEvent {
    Accept(std::io::Result<(TcpStream, std::net::SocketAddr)>),
    ServiceError(Error),
    Shutdown,
}

impl<F, E> GracefulListener<F, E>
where
    F: ServiceFactory<GracefulTcpStream>,
    F::Service: Service<GracefulTcpStream> + Send + 'static,
    <<F as ServiceFactory<GracefulTcpStream>>::Service as Service<GracefulTcpStream>>::Future: Send,
    E: ErrorHandler,
{
    async fn serve(self) -> Result<()> {
        let Self {
            tcp,
            mut service_factory,
            shutdown_timeout,
            graceful,
            error_handler,
        } = self;

        let (error_tx, mut error_rx) = tokio::sync::mpsc::channel(1);

        loop {
            // listen for any listener event
            let event = tokio::select! {
                res = tcp.accept() => {
                    GracefulListenerEvent::Accept(res)
                },
                opt = error_rx.recv() => {
                    GracefulListenerEvent::ServiceError(opt.unwrap())
                },
                _ = graceful.shutdown_req() => GracefulListenerEvent::Shutdown,
            };

            // handle the listner event
            let result = match event {
                GracefulListenerEvent::Accept(res) => res,
                GracefulListenerEvent::ServiceError(err) => {
                    error_handler.handle_service_error(err).await?;
                    continue;
                }
                GracefulListenerEvent::Shutdown => {
                    break;
                }
            };

            // handle the accept error or serve the incoming (tcp) stream
            match result {
                Err(err) => error_handler.handle_accept_error(err.into()).await?,
                Ok((stream, _)) => {
                    let mut service = service_factory.new_service()?;
                    let error_tx = error_tx.clone();
                    let token = graceful.token();
                    tokio::spawn(async move {
                        let stream = GracefulTcpStream(stream, token);
                        if let Err(err) = service.call(stream).await {
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
        .map_err(|err| Error::Other(err.into()))
    }
}

impl Listener<(), LogErrorHandler> {
    pub fn bind<A: ToSocketAddrs>(
        addr: A,
    ) -> Builder<SocketConfig<StdTcpListener>, LogErrorHandler, ()> {
        match Self::try_bind(addr) {
            Ok(incoming) => incoming,
            Err(err) => panic!("failed to bind tcp listener: {}", err),
        }
    }

    pub fn try_bind<A: ToSocketAddrs>(
        addr: A,
    ) -> Result<Builder<SocketConfig<StdTcpListener>, LogErrorHandler, ()>> {
        let incoming = StdTcpListener::bind(addr)?;
        incoming.set_nonblocking(true)?;
        Ok(Builder::new(incoming, LogErrorHandler, ()))
    }

    pub fn build(
        incoming: StdTcpListener,
    ) -> Builder<SocketConfig<StdTcpListener>, LogErrorHandler, ()> {
        Builder::new(incoming, LogErrorHandler, ())
    }
}

pub struct Builder<I, E, K> {
    incoming: I,
    error_handler: E,
    kind: K,
}

impl<I, E, K> Builder<I, E, K> {
    pub fn error_handler<F>(self, error_handler: F) -> Builder<I, F, K> {
        Builder {
            incoming: self.incoming,
            error_handler,
            kind: self.kind,
        }
    }
}

pub struct SocketConfig<L> {
    listener: L,
    ttl: Option<u32>,
}

pub struct GracefulConfig<S> {
    shutdown: S,
    timeout: Option<Duration>,
}

impl<E, K> Builder<SocketConfig<StdTcpListener>, E, K> {
    /// Create a new `Builder` with the specified address.
    pub fn new(listener: StdTcpListener, error_handler: E, kind: K) -> Self {
        Self {
            incoming: SocketConfig {
                listener,
                ttl: None,
            },
            error_handler,
            kind,
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

impl<I, E> Builder<I, E, ()> {
    /// Upgrade the builder to one which builds
    /// a graceful TCP listener which will shutdown once the given future resolves.
    pub fn graceful<S>(self, shutdown: S) -> Builder<I, E, GracefulConfig<S>> {
        Builder {
            incoming: self.incoming,
            error_handler: self.error_handler,
            kind: GracefulConfig {
                shutdown,
                timeout: None,
            },
        }
    }

    /// Upgrade the builder to one which builds
    /// a graceful TCP listener which will shutdown once the "ctrl+c" signal is received (SIGINT).
    pub fn graceful_ctrl_c(self) -> Builder<I, E, GracefulConfig<impl Future<Output = ()>>> {
        self.graceful(async {
            let _ = tokio::signal::ctrl_c().await;
        })
    }
}

impl<I, E, S> Builder<I, E, GracefulConfig<S>> {
    /// Set the timeout for graceful shutdown.
    ///
    /// If `None` is specified, the default timeout is used.
    pub fn timeout(mut self, timeout: Option<Duration>) -> Self {
        self.kind.timeout = timeout;
        self
    }
}

pub trait ToTcpListener {
    type Future: Future<Output = Result<TcpListener>>;

    fn into_tcp_listener(self) -> Self::Future;
}

impl ToTcpListener for TcpListener {
    type Future = future::Ready<Result<TcpListener>>;

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

impl<F> Future for SocketConfigToTcpListenerFuture<F>
where
    F: Future<Output = Result<TcpListener>>,
{
    type Output = Result<TcpListener>;

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
    type Future = SocketConfigToTcpListenerFuture<future::Ready<Result<TcpListener>>>;

    fn into_tcp_listener(self) -> Self::Future {
        let listener = TcpListener::from_std(self.listener).map_err(|err| err.into());
        let future = future::ready(listener);
        SocketConfigToTcpListenerFuture {
            future,
            ttl: self.ttl,
        }
    }
}

impl<T, E> Builder<T, E, ()>
where
    T: ToTcpListener,
    E: ErrorHandler,
{
    pub async fn serve<F>(self, service_factory: F) -> Result<()>
    where
        F: ServiceFactory<TcpStream>,
        F::Service: Service<TcpStream> + Send + 'static,
        <<F as ServiceFactory<TcpStream>>::Service as Service<TcpStream>>::Future: Send,
    {
        // create and configure the tcp listener...
        let listener = self.incoming.into_tcp_listener().await?;

        // listen without any grace..
        Listener::new(listener, service_factory, self.error_handler)
            .serve()
            .await
    }
}

impl<T, E, S> Builder<T, E, GracefulConfig<S>>
where
    T: ToTcpListener,
    S: Future + Send + 'static,
    E: ErrorHandler,
{
    pub async fn serve<F>(self, service_factory: F) -> Result<()>
    where
        F: ServiceFactory<GracefulTcpStream>,
        F::Service: Service<GracefulTcpStream> + Send + 'static,
        <<F as ServiceFactory<GracefulTcpStream>>::Service as Service<GracefulTcpStream>>::Future:
            Send,
    {
        // create and configure the tcp listener...
        let listener = self.incoming.into_tcp_listener().await?;

        // listen gracefully..
        GracefulListener::new(
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
