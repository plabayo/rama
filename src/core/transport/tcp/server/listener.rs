use std::{
    future::{self, Future},
    net::{Shutdown, TcpListener as StdTcpListener},
    pin::Pin,
    task::{ready, Context, Poll},
    time::Duration,
};

// TODO: change bind to bind to StdTcpListener immediately:
// - this way we can implement bind (panic) + try_bind (return Error)
// - and we'll have to change the building as that will now need to:
//      - set the std listener to not block
//      - use that instead of binding from socket addr

use tokio::{net::{TcpListener, TcpStream, ToSocketAddrs}};

use pin_project_lite::pin_project;

use crate::core::transport::graceful;

use super::{PermissiveServiceFactory, Result, Service};

pin_project! {
    pub struct Listener<F> {
        #[pin]
        tcp: TcpListener,

        #[pin]
        service_factory: F,
    }
}

impl<F> Listener<F> {
    fn new(tcp: TcpListener, service_factory: F) -> Self {
        Self {
            tcp,
            service_factory,
        }
    }
}

impl<F> Listener<F>
where
    F: PermissiveServiceFactory<TcpStream>,
    F::Service: Service<TcpStream> + Send + 'static,
    <<F as PermissiveServiceFactory<TcpStream>>::Service as Service<TcpStream>>::Future: Send,
{
    async fn serve(self) -> Result<()> {
        let Self {
            tcp,
            service_factory,
            ..
        } = self;

        let (error_tx, mut error_rx) = tokio::sync::mpsc::channel(1);

        loop {
            let result = tokio::select! {
                res = tcp.accept() => { Ok(res) },
                opt = error_rx.recv() => { Err(opt.unwrap()) },
            }?;

            match result {
                Err(err) => service_factory.handle_error(err.into())?,
                Ok((stream, _)) => {
                    let mut service = service_factory.new_service()?;
                    let error_tx = error_tx.clone();
                    tokio::spawn(async move {
                        if let Err(err) = service.call(stream).await {
                            // try to send the error to the main loop
                            error_tx.send(err).await;
                        }
                    });
                }
            }
        }
    }
}

pin_project! {
    pub struct GracefulListener<F> {
        #[pin]
        tcp: TcpListener,

        #[pin]
        service_factory: F,

        #[pin]
        service: graceful::GracefulService,
    }
}

impl<F> Listener<F> {
    pub fn bind<A: ToSocketAddrs>(incoming: A) -> Builder<SocketConfig<A>, ()> {
        Builder::new(incoming, ())
    }
    pub fn build<I>(incoming: I) -> Builder<I, ()> {
        Builder::new(incoming, ())
    }
}

pub struct Builder<I, K> {
    incoming: I,
    kind: K,
}

pub struct SocketConfig<A> {
    addr: A,
    ttl: Option<u32>,
}

pub struct GracefulConfig<S> {
    shutdown: S,
    timeout: Option<Duration>,
}

impl<A: ToSocketAddrs, K> Builder<SocketConfig<A>, K> {
    /// Create a new `Builder` with the specified address.
    pub fn new(addr: A, kind: K) -> Self {
        Self {
            incoming: SocketConfig { addr, ttl: None },
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

impl<I> Builder<I, ()> {
    /// Upgrade the builder to one which builds
    /// a graceful TCP listener which will shutdown once the given future resolves.
    pub fn graceful<S>(self, shutdown: S) -> Builder<I, GracefulConfig<S>> {
        Builder {
            incoming: self.incoming,
            kind: GracefulConfig {
                shutdown,
                timeout: None,
            },
        }
    }

    /// Upgrade the builder to one which builds
    /// a graceful TCP listener which will shutdown once the "ctrl+c" signal is received (SIGINT).
    pub fn graceful_ctrl_c(self) -> Builder<I, GracefulConfig<impl Future<Output = ()>>> {
        self.graceful(async {
            tokio::signal::ctrl_c().await;
        })
    }
}

impl<I, S> Builder<I, GracefulConfig<S>> {
    /// Set the timeout for graceful shutdown.
    ///
    /// If `None` is specified, the default timeout is used.
    pub fn timeout(mut self, timeout: Option<Duration>) -> Self {
        self.kind.timeout = timeout;
        self
    }
}

trait ToTcpListener {
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
    struct SocketConfigToTcpListenerFuture<F> {
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
            listener.set_ttl(ttl)?;
        }
        Poll::Ready(Ok(listener))
    }
}

impl<A: ToSocketAddrs> ToTcpListener for SocketConfig<A> {
    type Future =
        SocketConfigToTcpListenerFuture<Pin<Box<dyn Future<Output = Result<TcpListener>>>>>;

    fn into_tcp_listener(self) -> Self::Future {
        let future = Box::pin(async move {
            let listener = TcpListener::bind(self.addr).await?;
            Ok(listener)
        });
        SocketConfigToTcpListenerFuture {
            future: future,
            ttl: self.ttl,
        }
    }
}

impl<T: ToTcpListener> Builder<T, ()> {
    pub async fn serve<F>(self, service_factory: F) -> Result<Listener<F>> {
        // create and configure the tcp listener...
        let listener = self.incoming.into_tcp_listener().await?;

        // listen without any grace..
        Listener::new(listener, service_factory).listen().await
    }
}

impl<T: ToTcpListener, S> Builder<T, GracefulConfig<S>> {
    pub async fn serve<F>(self, service_factory: F) -> Result<GracefulListener<S>> {
        // create and configure the tcp listener...
        let listener = self.incoming.into_tcp_listener().await?;

        // listen gracefully..
        GracefulListener::new(
            listener,
            self.kind.shutdown,
            self.kind.timeout,
            service_factory,
        )
        .listen()
        .await
    }
}
