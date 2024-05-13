use crate::rt::Executor;
use crate::service::handler::{Factory, FromContextRequest};
use crate::service::Context;
use crate::service::Service;
use crate::stream::SocketInfo;
use crate::utils::graceful::ShutdownGuard;
use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::{io, net::SocketAddr};
use tokio::net::{TcpListener as TokioTcpListener, TcpStream, ToSocketAddrs};

/// Builder for `TcpListener`.
#[derive(Debug)]
pub struct TcpListenerBuilder<S> {
    ttl: Option<u32>,
    state: Arc<S>,
}

impl TcpListenerBuilder<()> {
    /// Create a new `TcpListenerBuilder` without a state.
    pub fn new() -> Self {
        Self {
            ttl: None,
            state: Arc::new(()),
        }
    }
}

impl Default for TcpListenerBuilder<()> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Clone for TcpListenerBuilder<S> {
    fn clone(&self) -> Self {
        Self {
            ttl: self.ttl,
            state: self.state.clone(),
        }
    }
}

impl<S> TcpListenerBuilder<S> {
    /// Sets the value for the `IP_TTL` option on this socket.
    ///
    /// This value sets the time-to-live field that is used in every packet sent
    /// from this socket.
    pub fn ttl(&mut self, ttl: u32) -> &mut Self {
        self.ttl = Some(ttl);
        self
    }
}

impl<S> TcpListenerBuilder<S>
where
    S: Send + Sync + 'static,
{
    /// Create a new `TcpListenerBuilder` with the given state.
    pub fn with_state(state: S) -> Self {
        Self {
            ttl: None,
            state: Arc::new(state),
        }
    }

    /// Creates a new TcpListener, which will be bound to the specified address.
    ///
    /// The returned listener is ready for accepting connections.
    ///
    /// Binding with a port number of 0 will request that the OS assigns a port
    /// to this listener. The port allocated can be queried via the `local_addr`
    /// method.
    pub async fn bind<A: ToSocketAddrs>(&self, addr: A) -> io::Result<TcpListener<S>> {
        let inner = TokioTcpListener::bind(addr).await?;

        if let Some(ttl) = self.ttl {
            inner.set_ttl(ttl)?;
        }

        Ok(TcpListener {
            inner,
            state: self.state.clone(),
        })
    }
}

/// A TCP socket server, listening for incoming connections once served
/// using one of the `serve` methods such as [`TcpListener::serve`].
#[derive(Debug)]
pub struct TcpListener<S> {
    inner: TokioTcpListener,
    state: Arc<S>,
}

impl TcpListener<()> {
    /// Create a new `TcpListenerBuilder` without a state,
    /// which can be used to configure a `TcpListener`.
    pub fn build() -> TcpListenerBuilder<()> {
        TcpListenerBuilder::new()
    }

    /// Create a new `TcpListenerBuilder` with the given state,
    /// which can be used to configure a `TcpListener`.
    pub fn build_with_state<S>(state: S) -> TcpListenerBuilder<S>
    where
        S: Send + Sync + 'static,
    {
        TcpListenerBuilder::with_state(state)
    }

    /// Creates a new TcpListener, which will be bound to the specified address.
    ///
    /// The returned listener is ready for accepting connections.
    ///
    /// Binding with a port number of 0 will request that the OS assigns a port
    /// to this listener. The port allocated can be queried via the `local_addr`
    /// method.
    pub async fn bind<A: ToSocketAddrs>(addr: A) -> io::Result<Self> {
        TcpListenerBuilder::default().bind(addr).await
    }
}

impl<S> TcpListener<S> {
    /// Returns the local address that this listener is bound to.
    ///
    /// This can be useful, for example, when binding to port 0 to figure out
    /// which port was actually bound.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// Gets the value of the `IP_TTL` option for this socket.
    ///
    /// For more information about this option, see [`set_ttl`].
    ///
    /// [`set_ttl`]: TcpListenerBuilder::ttl
    pub fn ttl(&self) -> io::Result<u32> {
        self.inner.ttl()
    }

    /// Gets a reference to the listener's state.
    pub fn state(&self) -> &S {
        &self.state
    }
}

impl<State> TcpListener<State>
where
    State: Send + Sync + 'static,
{
    /// Serve connections from this listener with the given service.
    ///
    /// This method will block the current listener for each incoming connection,
    /// the underlying service can choose to spawn a task to handle the accepted stream.
    pub async fn serve<S>(self, service: S)
    where
        S: Service<State, TcpStream>,
    {
        let ctx = Context::new(self.state, Executor::new());
        let service = Arc::new(service);

        loop {
            let (socket, peer_addr) = match self.inner.accept().await {
                Ok(stream) => stream,
                Err(err) => {
                    handle_accept_err(err).await;
                    continue;
                }
            };

            let service = service.clone();
            let mut ctx = ctx.clone();

            tokio::spawn(async move {
                let local_addr = socket.local_addr().ok();
                ctx.insert(SocketInfo::new(local_addr, peer_addr));

                let _ = service.serve(ctx, socket).await;
            });
        }
    }

    /// Serve connections from this listener with the given service function.
    ///
    /// See [`Self::serve`] for more details.
    pub async fn serve_fn<F, T, R, O, E>(self, f: F)
    where
        F: Factory<T, R, O, E>,
        R: Future<Output = Result<O, E>> + Send + Sync + 'static,
        O: Send + Sync + 'static,
        E: Send + Sync + 'static,
        T: FromContextRequest<State, TcpStream>,
    {
        let service = crate::service::service_fn(f);
        self.serve(service).await
    }

    /// Serve gracefully connections from this listener with the given service.
    ///
    /// This method does the same as [`Self::serve`] but it
    /// will respect the given [`crate::utils::graceful::ShutdownGuard`], and also pass
    /// it to the service.
    pub async fn serve_graceful<S>(self, guard: ShutdownGuard, service: S)
    where
        S: Service<State, TcpStream>,
    {
        let ctx: Context<State> = Context::new(self.state, Executor::graceful(guard.clone()));
        let service = Arc::new(service);
        let mut cancelled_fut = pin!(guard.cancelled());

        loop {
            tokio::select! {
                _ = cancelled_fut.as_mut() => {
                    tracing::trace!("signal received: initiate graceful shutdown");
                    break;
                }
                result = self.inner.accept() => {
                    match result {
                        Ok((socket, peer_addr)) => {
                            let service = service.clone();
                            let mut ctx = ctx.clone();

                            guard.spawn_task(async move {
                                let local_addr = socket.local_addr().ok();
                                ctx.insert(SocketInfo::new(local_addr, peer_addr));

                                let _ = service.serve(ctx, socket).await;
                            });
                        }
                        Err(err) => {
                            handle_accept_err(err).await;
                        }
                    }
                }
            }
        }
    }

    /// Serve gracefully connections from this listener with the given service function.
    ///
    /// See [`Self::serve_graceful`] for more details.
    pub async fn serve_fn_graceful<F, T, R, O, E>(self, guard: ShutdownGuard, service: F)
    where
        F: Factory<T, R, O, E>,
        R: Future<Output = Result<O, E>> + Send + Sync + 'static,
        O: Send + Sync + 'static,
        E: Send + Sync + 'static,
        T: FromContextRequest<State, TcpStream>,
    {
        let service = crate::service::service_fn(service);
        self.serve_graceful(guard, service).await
    }
}

async fn handle_accept_err(err: io::Error) {
    if crate::tcp::utils::is_connection_error(&err) {
        tracing::trace!(
            error = &err as &dyn std::error::Error,
            "TCP accept error: connect error"
        );
    } else {
        // [From `hyper::Server` in 0.14](https://github.com/hyperium/hyper/blob/v0.14.27/src/server/tcp.rs#L186)
        //
        // > A possible scenario is that the process has hit the max open files
        // > allowed, and so trying to accept a new connection will fail with
        // > `EMFILE`. In some cases, it's preferable to just wait for some time, if
        // > the application will likely close some files (or connections), and try
        // > to accept the connection again. If this option is `true`, the error
        // > will be logged at the `error` level, since it is still a big deal,
        // > and then the listener will sleep for 1 second.
        //
        // hyper allowed customizing this but axum does not.
        tracing::error!(error = &err as &dyn std::error::Error, "TCP accept error");
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}
