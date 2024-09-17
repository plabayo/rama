use rama_core::context::StateTransformer;
use rama_core::graceful::ShutdownGuard;
use rama_core::rt::Executor;
use rama_core::service::handler::{Factory, FromContextRequest};
use rama_core::Context;
use rama_core::Service;
use rama_net::stream::SocketInfo;
use std::fmt;
use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::{io, net::SocketAddr};
use tokio::net::{TcpListener as TokioTcpListener, TcpStream, ToSocketAddrs};

/// Builder for `TcpListener`.
pub struct TcpListenerBuilder<S, T = ()> {
    ttl: Option<u32>,
    state: S,
    state_transformer: T,
}

impl<S, T> fmt::Debug for TcpListenerBuilder<S, T>
where
    S: fmt::Debug,
    T: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpListenerBuilder")
            .field("ttl", &self.ttl)
            .field("state", &self.state)
            .field("state_transformer", &self.state_transformer)
            .finish()
    }
}

impl TcpListenerBuilder<(), ()> {
    /// Create a new `TcpListenerBuilder` without a state.
    pub fn new() -> Self {
        Self {
            ttl: None,
            state: (),
            state_transformer: (),
        }
    }
}

impl<S> TcpListenerBuilder<S> {
    /// Attach a new [`StateTransformer`] to this [`TcpListenerBuilder`].
    pub fn with_state_transformer<T>(self, transformer: T) -> TcpListenerBuilder<S, T> {
        TcpListenerBuilder {
            ttl: self.ttl,
            state: self.state,
            state_transformer: transformer,
        }
    }
}

impl Default for TcpListenerBuilder<(), ()> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: Clone, T: Clone> Clone for TcpListenerBuilder<S, T> {
    fn clone(&self) -> Self {
        Self {
            ttl: self.ttl,
            state: self.state.clone(),
            state_transformer: self.state_transformer.clone(),
        }
    }
}

impl<S, T> TcpListenerBuilder<S, T> {
    /// Sets the value for the `IP_TTL` option on this socket.
    ///
    /// This value sets the time-to-live field that is used in every packet sent
    /// from this socket.
    pub fn ttl(mut self, ttl: u32) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Sets the value for the `IP_TTL` option on this socket.
    ///
    /// This value sets the time-to-live field that is used in every packet sent
    /// from this socket.
    pub fn set_ttl(&mut self, ttl: u32) -> &mut Self {
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
            state,
            state_transformer: (),
        }
    }
}

impl<S, T> TcpListenerBuilder<S, T>
where
    S: Send + Sync + 'static,
{
    /// Creates a new TcpListener, which will be bound to the specified address.
    ///
    /// The returned listener is ready for accepting connections.
    ///
    /// Binding with a port number of 0 will request that the OS assigns a port
    /// to this listener. The port allocated can be queried via the `local_addr`
    /// method.
    pub async fn bind<A: ToSocketAddrs>(self, addr: A) -> io::Result<TcpListener<S, T>> {
        let inner = TokioTcpListener::bind(addr).await?;

        if let Some(ttl) = self.ttl {
            inner.set_ttl(ttl)?;
        }

        Ok(TcpListener {
            inner,
            state: self.state,
            state_transformer: self.state_transformer,
        })
    }
}

/// A TCP socket server, listening for incoming connections once served
/// using one of the `serve` methods such as [`TcpListener::serve`].
pub struct TcpListener<S, T = ()> {
    inner: TokioTcpListener,
    state: S,
    state_transformer: T,
}

impl<S, T> fmt::Debug for TcpListener<S, T>
where
    S: fmt::Debug,
    T: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpListener")
            .field("inner", &self.inner)
            .field("state", &self.state)
            .field("state_transformer", &self.state_transformer)
            .finish()
    }
}

impl TcpListener<(), ()> {
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

impl<S, T> TcpListener<S, T> {
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

    /// Gets an exclusive reference to the listener's state.
    pub fn state_mut(&mut self) -> &mut S {
        &mut self.state
    }
}

impl<State, T> TcpListener<State, T>
where
    State: Send + Sync + 'static,
    T: StateTransformer<State, Output: Send + Sync + 'static, Error: std::error::Error + 'static>,
{
    /// Serve connections from this listener with the given service.
    ///
    /// This method will block the current listener for each incoming connection,
    /// the underlying service can choose to spawn a task to handle the accepted stream.
    pub async fn serve<S>(self, service: S)
    where
        S: Service<T::Output, TcpStream>,
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

            let state = match self.state_transformer.transform_state(&ctx) {
                Ok(state) => state,
                Err(err) => {
                    tracing::error!(
                        error = &err as &dyn std::error::Error,
                        "TCP accept error: state transformer failed"
                    );
                    continue;
                }
            };
            let mut ctx = ctx.clone_with_state(state);

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
    pub async fn serve_fn<F, X, R, O, E>(self, f: F)
    where
        F: Factory<X, R, O, E>,
        R: Future<Output = Result<O, E>> + Send + 'static,
        O: Send + Sync + 'static,
        E: Send + Sync + 'static,
        X: FromContextRequest<T::Output, TcpStream>,
    {
        let service = rama_core::service::service_fn(f);
        self.serve(service).await
    }

    /// Serve gracefully connections from this listener with the given service.
    ///
    /// This method does the same as [`Self::serve`] but it
    /// will respect the given [`rama_core::graceful::ShutdownGuard`], and also pass
    /// it to the service.
    pub async fn serve_graceful<S>(self, guard: ShutdownGuard, service: S)
    where
        S: Service<T::Output, TcpStream>,
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

                            let state = match self.state_transformer.transform_state(&ctx) {
                                Ok(state) => state,
                                Err(err) => {
                                    tracing::error!(
                                        error = &err as &dyn std::error::Error,
                                        "TCP accept error: state transformer failed"
                                    );
                                    continue;
                                }
                            };
                            let mut ctx = ctx.clone_with_state(state);

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
    pub async fn serve_fn_graceful<F, X, R, O, E>(self, guard: ShutdownGuard, service: F)
    where
        F: Factory<X, R, O, E>,
        R: Future<Output = Result<O, E>> + Send + 'static,
        O: Send + Sync + 'static,
        E: Send + Sync + 'static,
        X: FromContextRequest<T::Output, TcpStream>,
    {
        let service = rama_core::service::service_fn(service);
        self.serve_graceful(guard, service).await
    }
}

async fn handle_accept_err(err: io::Error) {
    if crate::utils::is_connection_error(&err) {
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
