use super::TcpSocketInfo;
use crate::error::BoxError;
use crate::graceful::ShutdownGuard;
use crate::service::{
    layer::{Identity, Stack},
    Layer, Service, ServiceBuilder,
};
use crate::service::{Context, ServiceFn};
use std::convert::Infallible;
use std::pin::pin;
use std::{future::Future, io, net::SocketAddr};
use tokio::net::{TcpListener as TokioTcpListener, TcpStream, ToSocketAddrs};

/// Builder for `TcpListener`.
#[derive(Debug)]
pub struct TcpListenerBuilder<S> {
    ttl: Option<u32>,
    state: S,
}

impl TcpListenerBuilder<()> {
    /// Create a new `TcpListenerBuilder` without a state.
    pub fn new() -> Self {
        Self {
            ttl: None,
            state: (),
        }
    }
}

impl Default for TcpListenerBuilder<()> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Clone for TcpListenerBuilder<S>
where
    S: Clone,
{
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
    S: Clone + Send + 'static,
{
    /// Create a new `TcpListenerBuilder` with the given state.
    pub fn with_state(state: S) -> Self {
        Self { ttl: None, state }
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
    state: S,
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
        S: Clone + Send + 'static,
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

    /// Gets a mutable reference to the listener's state.
    pub fn state_mut(&mut self) -> &mut S {
        &mut self.state
    }
}

impl<State> TcpListener<State>
where
    State: Clone + Send + 'static,
{
    /// Serve connections from this listener with the given service.
    ///
    /// This method will block the current listener for each incoming connection,
    /// the underlying service can choose to spawn a task to handle the accepted stream.
    pub async fn serve<T, S>(self, service: S)
    where
        S: Service<State, TcpStream, Response = T, Error = Infallible> + Clone,
        T: Send + 'static,
    {
        let ctx = Context::new(self.state);

        loop {
            let (socket, peer_addr) = match self.inner.accept().await {
                Ok(stream) => stream,
                Err(err) => {
                    tracing::trace!(error = &err as &dyn std::error::Error, "accept error");
                    continue;
                }
            };

            let service = service.clone();
            let mut ctx = ctx.clone();

            tokio::spawn(async move {
                let local_addr = socket.local_addr().ok();
                ctx.extensions_mut()
                    .insert(TcpSocketInfo::new(local_addr, peer_addr));

                let _ = service.serve(ctx, socket).await;
            });
        }
    }

    /// Serve connections from this listener with the given service function.
    ///
    /// See [`Self::serve`] for more details.
    pub async fn serve_fn<F, A>(self, f: F)
    where
        A: Send + 'static,
        F: ServiceFn<State, TcpStream, A, Error = Infallible> + Clone,
    {
        let service = crate::service::service_fn(f);
        self.serve(service).await
    }

    /// Serve gracefully connections from this listener with the given service.
    ///
    /// This method does the same as [`Self::serve`] but it
    /// will respect the given [`crate::graceful::ShutdownGuard`], and also pass
    /// it to the service.
    pub async fn serve_graceful<T, S>(self, guard: ShutdownGuard, service: S)
    where
        S: Service<State, TcpStream, Response = T, Error = Infallible> + Clone,
    {
        let ctx: Context<State> = Context::new(self.state);
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

                            guard.spawn_task_fn(move |guard| async move {
                                let local_addr = socket.local_addr().ok();
                                ctx.extensions_mut().insert(guard);
                                ctx.extensions_mut().insert(TcpSocketInfo::new(local_addr, peer_addr));

                                let _ = service.serve(ctx, socket).await;
                            });
                        }
                        Err(err) => {
                            tracing::trace!(error = &err as &dyn std::error::Error, "accept error");
                        }
                    }
                }
            }
        }
    }

    /// Serve gracefully connections from this listener with the given service function.
    ///
    /// See [`Self::serve_graceful`] for more details.
    pub async fn serve_fn_graceful<F, A>(self, guard: ShutdownGuard, service: F)
    where
        A: Send + 'static,
        F: ServiceFn<State, TcpStream, A, Error = Infallible> + Clone,
    {
        let service = crate::service::service_fn(service);
        self.serve_graceful(guard, service).await
    }
}
