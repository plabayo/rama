use rama_core::Context;
use rama_core::Service;
use rama_core::error::BoxError;
use rama_core::error::ErrorContext;
use rama_core::graceful::ShutdownGuard;
use rama_core::rt::Executor;
use rama_core::telemetry::tracing::{self, Instrument, trace_root_span};
use rama_net::address::SocketAddress;
use rama_net::socket::Interface;
use rama_net::stream::SocketInfo;
use std::fmt;
use std::pin::pin;
use std::sync::Arc;
use std::{io, net::SocketAddr};
use tokio::net::TcpListener as TokioTcpListener;

#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
use rama_net::socket::{DeviceName, SocketOptions};

use crate::TcpStream;

/// Builder for `TcpListener`.
pub struct TcpListenerBuilder<S> {
    ttl: Option<u32>,
    state: S,
}

impl<S> fmt::Debug for TcpListenerBuilder<S>
where
    S: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpListenerBuilder")
            .field("ttl", &self.ttl)
            .field("state", &self.state)
            .finish()
    }
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

impl<S: Clone> Clone for TcpListenerBuilder<S> {
    fn clone(&self) -> Self {
        Self {
            ttl: self.ttl,
            state: self.state.clone(),
        }
    }
}

impl<S> TcpListenerBuilder<S> {
    rama_utils::macros::generate_set_and_with! {
        /// Sets the value for the `IP_TTL` option on this socket.
        ///
        /// This value sets the time-to-live field that is used in every packet sent
        /// from this socket.
        pub fn ttl(mut self, ttl: u32) -> Self {
            self.ttl = Some(ttl);
            self
        }
    }
}

impl<S> TcpListenerBuilder<S>
where
    S: Clone + Send + Sync + 'static,
{
    /// Create a new `TcpListenerBuilder` with the given state.
    pub fn with_state(state: S) -> Self {
        Self { ttl: None, state }
    }
}

impl<S> TcpListenerBuilder<S>
where
    S: Clone + Send + Sync + 'static,
{
    /// Creates a new TcpListener, which will be bound to the specified socket address.
    ///
    /// The returned listener is ready for accepting connections.
    ///
    /// Binding with a port number of 0 will request that the OS assigns a port
    /// to this listener. The port allocated can be queried via the `local_addr`
    /// method.
    pub async fn bind_address<A: TryInto<SocketAddress, Error: Into<BoxError>>>(
        self,
        addr: A,
    ) -> Result<TcpListener<S>, BoxError> {
        let socket_addr = addr.try_into().map_err(Into::<BoxError>::into)?;
        let tokio_socket_addr: SocketAddr = socket_addr.into();
        let inner = TokioTcpListener::bind(tokio_socket_addr)
            .await
            .map_err(Into::<BoxError>::into)?;

        if let Some(ttl) = self.ttl {
            inner.set_ttl(ttl).context("set ttl on tcp listener")?;
        }

        Ok(TcpListener {
            inner,
            state: self.state,
        })
    }

    #[cfg(any(windows, unix))]
    /// Creates a new TcpListener, which will be bound to the specified socket.
    ///
    /// The returned listener is ready for accepting connections.
    pub async fn bind_socket(
        self,
        socket: rama_net::socket::core::Socket,
    ) -> Result<TcpListener<S>, BoxError> {
        tokio::task::spawn_blocking(|| bind_socket_internal(self.state, socket))
            .await
            .context("await blocking bind socket task")?
    }

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    /// Creates a new TcpListener, which will be bound to the specified (interface) device name).
    ///
    /// The returned listener is ready for accepting connections.
    pub async fn bind_device<N: TryInto<DeviceName, Error: Into<BoxError>> + Send + 'static>(
        self,
        name: N,
    ) -> Result<TcpListener<S>, BoxError> {
        tokio::task::spawn_blocking(|| {
            let name = name.try_into().map_err(Into::<BoxError>::into)?;
            let socket = SocketOptions {
                device: Some(name),
                ..SocketOptions::default_tcp()
            }
            .try_build_socket()
            .context("create tcp ipv4 socket attached to device")?;
            socket
                .listen(4096)
                .context("mark the socket as ready to accept incoming connection requests")?;
            bind_socket_internal(self.state, socket)
        })
        .await
        .context("await blocking bind socket task")?
    }

    /// Creates a new TcpListener, which will be bound to the specified interface.
    ///
    /// The returned listener is ready for accepting connections.
    pub async fn bind<I: TryInto<Interface, Error: Into<BoxError>>>(
        self,
        interface: I,
    ) -> Result<TcpListener<S>, BoxError> {
        match interface.try_into().map_err(Into::<BoxError>::into)? {
            Interface::Address(addr) => self.bind_address(addr).await,
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            Interface::Device(name) => self.bind_device(name).await,
            Interface::Socket(opts) => {
                let socket = opts
                    .try_build_socket()
                    .context("build socket from options")?;
                socket
                    .listen(4096)
                    .context("mark the socket as ready to accept incoming connection requests")?;
                self.bind_socket(socket).await
            }
        }
    }
}

/// A TCP socket server, listening for incoming connections once served
/// using one of the `serve` methods such as [`TcpListener::serve`].
pub struct TcpListener<S> {
    inner: TokioTcpListener,
    state: S,
}

impl<S> fmt::Debug for TcpListener<S>
where
    S: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpListener")
            .field("inner", &self.inner)
            .field("state", &self.state)
            .finish()
    }
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
        S: Clone + Send + Sync + 'static,
    {
        TcpListenerBuilder::with_state(state)
    }

    /// Creates a new TcpListener, which will be bound to the specified (socket) address.
    ///
    /// The returned listener is ready for accepting connections.
    ///
    /// Binding with a port number of 0 will request that the OS assigns a port
    /// to this listener. The port allocated can be queried via the `local_addr`
    /// method.
    pub async fn bind_address<A: TryInto<SocketAddress, Error: Into<BoxError>>>(
        addr: A,
    ) -> Result<TcpListener<()>, BoxError> {
        TcpListenerBuilder::default().bind_address(addr).await
    }

    #[cfg(any(windows, unix))]
    /// Creates a new TcpListener, which will be bound to the specified socket.
    ///
    /// The returned listener is ready for accepting connections.
    pub async fn bind_socket(
        socket: rama_net::socket::core::Socket,
    ) -> Result<TcpListener<()>, BoxError> {
        TcpListenerBuilder::default().bind_socket(socket).await
    }

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    /// Creates a new TcpListener, which will be bound to the specified (interface) device name.
    ///
    /// The returned listener is ready for accepting connections.
    pub async fn bind_device<N: TryInto<DeviceName, Error: Into<BoxError>> + Send + 'static>(
        name: N,
    ) -> Result<TcpListener<()>, BoxError> {
        TcpListenerBuilder::default().bind_device(name).await
    }

    /// Creates a new TcpListener, which will be bound to the specified interface.
    ///
    /// The returned listener is ready for accepting connections.
    pub async fn bind<I: TryInto<Interface, Error: Into<BoxError>>>(
        interface: I,
    ) -> Result<TcpListener<()>, BoxError> {
        TcpListenerBuilder::default().bind(interface).await
    }
}

fn bind_socket_internal<S>(
    state: S,
    socket: rama_net::socket::core::Socket,
) -> Result<TcpListener<S>, BoxError>
where
    S: Clone + Send + Sync + 'static,
{
    let listener = std::net::TcpListener::from(socket);
    listener
        .set_nonblocking(true)
        .context("set socket as non-blocking")?;
    Ok(TcpListener {
        inner: TokioTcpListener::from_std(listener)?,
        state,
    })
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

    /// Gets an exclusive reference to the listener's state.
    pub fn state_mut(&mut self) -> &mut S {
        &mut self.state
    }
}

impl From<TokioTcpListener> for TcpListener<()> {
    fn from(value: TokioTcpListener) -> Self {
        Self {
            inner: value,
            state: (),
        }
    }
}

#[cfg(any(windows, unix))]
impl TryFrom<rama_net::socket::core::Socket> for TcpListener<()> {
    type Error = std::io::Error;

    #[inline]
    fn try_from(value: rama_net::socket::core::Socket) -> Result<Self, Self::Error> {
        let listener = std::net::TcpListener::from(value);
        listener.try_into()
    }
}

impl TryFrom<std::net::TcpListener> for TcpListener<()> {
    type Error = std::io::Error;

    fn try_from(value: std::net::TcpListener) -> Result<Self, Self::Error> {
        value.set_nonblocking(true)?;
        Ok(Self {
            inner: TokioTcpListener::from_std(value)?,
            state: (),
        })
    }
}

impl TcpListener<()> {
    /// Define the TcpListener's state after it was created,
    /// useful in case it wasn't built using the builder.
    pub fn with_state<S>(self, state: S) -> TcpListener<S> {
        TcpListener {
            inner: self.inner,
            state,
        }
    }
}

impl<State> TcpListener<State>
where
    State: Clone + Send + Sync + 'static,
{
    /// Accept a single connection from this listener,
    /// what you can do with whatever you want.
    #[inline]
    pub async fn accept(&self) -> std::io::Result<(TcpStream, SocketAddress)> {
        let (stream, addr) = self.inner.accept().await?;
        Ok((stream, addr.into()))
    }

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

            let local_addr = socket.local_addr().ok();
            let trace_local_addr = local_addr
                .map(Into::into)
                .unwrap_or_else(|| SocketAddress::default_ipv4(0));

            let span = trace_root_span!(
                "tcp::serve",
                otel.kind = "server",
                network.local.port = %trace_local_addr.port(),
                network.local.address = %trace_local_addr.ip_addr(),
                network.peer.port = %peer_addr.port(),
                network.peer.address = %peer_addr.ip(),
                network.protocol.name = "tcp",
            );

            tokio::spawn(
                async move {
                    ctx.insert(SocketInfo::new(local_addr, peer_addr));

                    let _ = service.serve(ctx, socket).await;
                }
                .instrument(span),
            );
        }
    }

    /// Serve gracefully connections from this listener with the given service.
    ///
    /// This method does the same as [`Self::serve`] but it
    /// will respect the given [`rama_core::graceful::ShutdownGuard`], and also pass
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

                            let local_addr = socket.local_addr().ok();
                            let trace_local_addr = local_addr
                                .map(Into::into)
                                .unwrap_or_else(|| SocketAddress::default_ipv4(0));

                            let span = trace_root_span!(
                                "tcp::serve_graceful",
                                otel.kind = "server",
                                network.local.port = %trace_local_addr.port(),
                                network.local.address = %trace_local_addr.ip_addr(),
                                network.peer.port = %peer_addr.port(),
                                network.peer.address = %peer_addr.ip(),
                                network.protocol.name = "tcp",
                            );

                            guard.spawn_task(async move {
                                ctx.insert(SocketInfo::new(local_addr, peer_addr));
                                let _ = service.serve(ctx, socket).await;
                            }.instrument(span));
                        }
                        Err(err) => {
                            handle_accept_err(err).await;
                        }
                    }
                }
            }
        }
    }
}

async fn handle_accept_err(err: io::Error) {
    if rama_net::conn::is_connection_error(&err) {
        tracing::trace!("TCP accept error: connect error: {err:?}");
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
        tracing::error!("TCP accept error: {err:?}");
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}
