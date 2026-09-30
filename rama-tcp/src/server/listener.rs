use rama_core::Service;
use rama_core::error::BoxError;
use rama_core::error::ErrorContext;
use rama_core::extensions::ExtensionsRef;
use rama_core::rt::Executor;
use rama_core::telemetry::tracing::{self, Instrument, trace_root_span};
use rama_net::address::SocketAddress;
use rama_net::stream::Socket;
use rama_net::stream::SocketInfo;
use std::pin::pin;
use std::{io, net::SocketAddr};
use tokio::net::TcpListener as TokioTcpListener;

#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
use rama_net::socket::{DeviceName, SocketOptions, opts::Domain};

use crate::TcpStream;

#[derive(Clone, Debug)]
/// Builder for `TcpListener`.
pub struct TcpListenerBuilder {
    ttl: Option<u32>,
    tcp_no_delay: bool,
    exec: Executor,
}

impl TcpListenerBuilder {
    /// Create a new `TcpListenerBuilder` without a state.
    #[must_use]
    pub fn new(exec: Executor) -> Self {
        Self {
            ttl: None,
            tcp_no_delay: true,
            exec,
        }
    }
}

impl TcpListenerBuilder {
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

    rama_utils::macros::generate_set_and_with! {
        /// Set whether `TCP_NODELAY` (disable Nagle's algorithm) is applied to
        /// every accepted connection.
        ///
        /// Enabled by default, so that a response written in several segments
        /// is not held back by the interaction of Nagle's algorithm and the
        /// peer's delayed ACKs (a latency stall of tens of milliseconds
        /// on Linux). Pass `false` to leave accepted sockets as the operating
        /// system created them.
        pub fn tcp_no_delay(mut self, no_delay: bool) -> Self {
            self.tcp_no_delay = no_delay;
            self
        }
    }
}

impl TcpListenerBuilder {
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
    ) -> Result<TcpListener, BoxError> {
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
            exec: self.exec,
            tcp_no_delay: self.tcp_no_delay,
        })
    }

    #[cfg(any(target_os = "windows", target_family = "unix"))]
    #[cfg_attr(docsrs, doc(cfg(any(target_os = "windows", target_family = "unix"))))]
    #[inline(always)]
    /// Creates a new TcpListener, which will be bound to the specified socket.
    ///
    /// The returned listener is ready for accepting connections.
    pub async fn bind_socket(
        self,
        socket: rama_net::socket::core::Socket,
    ) -> Result<TcpListener, BoxError> {
        bind_socket_internal(socket, self.exec, self.tcp_no_delay)
    }

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    #[cfg_attr(
        docsrs,
        doc(cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))
    )]
    /// Creates a new TcpListener, which will be bound to the specified (interface) device name).
    ///
    /// The returned listener is ready for accepting connections.
    pub async fn bind_device<N: TryInto<DeviceName, Error: Into<BoxError>> + Send + 'static>(
        self,
        name: N,
        domain: Domain,
        backlog: Option<i32>,
    ) -> Result<TcpListener, BoxError> {
        let name = name.try_into().map_err(Into::<BoxError>::into)?;
        let socket = SocketOptions {
            device: Some(name),
            ..SocketOptions::default_tcp()
        }
        .try_build_socket(domain)
        .context("create tcp ipv4 socket attached to device")?;
        socket
            .listen(backlog.unwrap_or(4096))
            .context("mark the socket as ready to accept incoming connection requests")?;
        bind_socket_internal(socket, self.exec, self.tcp_no_delay)
    }
}

#[derive(Debug)]
/// A TCP socket server, listening for incoming connections once served
/// using one of the `serve` methods such as [`TcpListener::serve`].
///
/// Accepted connections have `TCP_NODELAY` set (Nagle's algorithm disabled)
/// by default, see [`TcpListenerBuilder::set_tcp_no_delay`] to opt out.
/// Connections obtained through [`TcpListener::into_inner`] are left untouched.
pub struct TcpListener {
    inner: TokioTcpListener,
    exec: Executor,
    tcp_no_delay: bool,
}

impl TcpListener {
    /// Create a new `TcpListenerBuilder` without a state,
    /// which can be used to configure a `TcpListener`.
    #[must_use]
    pub fn build(exec: Executor) -> TcpListenerBuilder {
        TcpListenerBuilder::new(exec)
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
        exec: Executor,
    ) -> Result<Self, BoxError> {
        TcpListenerBuilder::new(exec).bind_address(addr).await
    }

    #[cfg(any(target_os = "windows", target_family = "unix"))]
    #[cfg_attr(docsrs, doc(cfg(any(target_os = "windows", target_family = "unix"))))]
    /// Creates a new TcpListener, which will be bound to the specified socket.
    ///
    /// The returned listener is ready for accepting connections.
    pub async fn bind_socket(
        socket: rama_net::socket::core::Socket,
        exec: Executor,
    ) -> Result<Self, BoxError> {
        TcpListenerBuilder::new(exec).bind_socket(socket).await
    }

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    #[cfg_attr(
        docsrs,
        doc(cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))
    )]
    /// Creates a new TcpListener, which will be bound to the specified (interface) device name.
    ///
    /// The returned listener is ready for accepting connections.
    pub async fn bind_device<N: TryInto<DeviceName, Error: Into<BoxError>> + Send + 'static>(
        name: N,
        exec: Executor,
        domain: Domain,
        backlog: Option<i32>,
    ) -> Result<Self, BoxError> {
        TcpListenerBuilder::new(exec)
            .bind_device(name, domain, backlog)
            .await
    }
}

fn bind_socket_internal(
    socket: rama_net::socket::core::Socket,
    exec: Executor,
    tcp_no_delay: bool,
) -> Result<TcpListener, BoxError> {
    let listener = std::net::TcpListener::from(socket);
    listener
        .set_nonblocking(true)
        .context("set socket as non-blocking")?;
    Ok(TcpListener {
        inner: TokioTcpListener::from_std(listener)?,
        exec,
        tcp_no_delay,
    })
}

impl TcpListener {
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
    /// [`set_ttl`]: TcpListenerBuilder::set_ttl
    pub fn ttl(&self) -> io::Result<u32> {
        self.inner.ttl()
    }

    /// Sets the value for the `IP_TTL` option on this socket.
    ///
    /// This value sets the time-to-live field that is used in every packet sent
    /// from this socket.
    pub fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        self.inner.set_ttl(ttl)
    }

    /// Returns whether `TCP_NODELAY` is applied to accepted connections
    /// (the default).
    #[must_use]
    pub fn tcp_no_delay(&self) -> bool {
        self.tcp_no_delay
    }

    /// Set whether `TCP_NODELAY` (disable Nagle's algorithm) is applied to
    /// every connection accepted by [`TcpListener::accept`] and
    /// [`TcpListener::serve`].
    ///
    /// See [`TcpListenerBuilder::set_tcp_no_delay`] for the rationale
    /// behind the default of `true`.
    pub fn set_tcp_no_delay(&mut self, no_delay: bool) -> &mut Self {
        self.tcp_no_delay = no_delay;
        self
    }

    /// Consuming variant of [`TcpListener::set_tcp_no_delay`].
    #[must_use]
    pub fn with_tcp_no_delay(mut self, no_delay: bool) -> Self {
        self.tcp_no_delay = no_delay;
        self
    }

    /// Converts this [`TcpListener`] into a [`std::net::TcpListener`].
    ///
    /// The returned listener will be in blocking mode. To convert it back
    /// to non-blocking for use with Rama, use [`TryFrom<std::net::TcpListener>`].
    ///
    /// This is useful for zero-downtime restarts where listener file descriptors
    /// need to be passed between processes via `SCM_RIGHTS`.
    #[inline(always)]
    pub fn into_std(self) -> io::Result<std::net::TcpListener> {
        let std_listener = self.inner.into_std()?;
        std_listener.set_nonblocking(false)?;
        Ok(std_listener)
    }

    /// Consumes this [`TcpListener`] and returns the inner [`tokio::net::TcpListener`].
    #[inline(always)]
    pub fn into_inner(self) -> TokioTcpListener {
        self.inner
    }

    pub fn from_tokio_tcp_listener(listener: TokioTcpListener, exec: Executor) -> Self {
        Self {
            inner: listener,
            exec,
            tcp_no_delay: true,
        }
    }

    #[cfg(any(target_os = "windows", target_family = "unix"))]
    #[cfg_attr(docsrs, doc(cfg(any(target_os = "windows", target_family = "unix"))))]
    pub fn try_from_socket(
        socket: rama_net::socket::core::Socket,
        exec: Executor,
    ) -> Result<Self, std::io::Error> {
        let listener = std::net::TcpListener::from(socket);
        Self::try_from_std_tcp_listener(listener, exec)
    }

    pub fn try_from_std_tcp_listener(
        listener: std::net::TcpListener,
        exec: Executor,
    ) -> Result<Self, std::io::Error> {
        listener.set_nonblocking(true)?;
        Ok(Self {
            inner: TokioTcpListener::from_std(listener)?,
            exec,
            tcp_no_delay: true,
        })
    }
}

impl TcpListener {
    /// Accept a single connection from this listener,
    /// what you can do with whatever you want.
    #[inline]
    pub async fn accept(&self) -> std::io::Result<(TcpStream, SocketAddress)> {
        let (stream, addr) = self.inner.accept().await?;
        self.apply_stream_defaults(&stream);
        Ok((stream.into(), addr.into()))
    }

    /// Apply the listener's per-connection defaults to an accepted socket.
    ///
    /// A failure here (for example a peer that already reset the connection)
    /// is not fatal: the connection is served without the option.
    fn apply_stream_defaults(&self, stream: &tokio::net::TcpStream) {
        if self.tcp_no_delay
            && let Err(err) = stream.set_nodelay(true)
        {
            tracing::debug!("failed to set TCP_NODELAY on accepted tcp stream: {err:?}");
        }
    }

    /// Serve connections from this listener with the given service.
    ///
    /// This listener will spawn a task in which the inner service will
    /// handle the incomming connection. Cconnections will be served
    /// gracefully if the [`TcpListener`] is configured with a graceful [`Executor`].
    pub async fn serve<S>(self, service: S)
    where
        S: Service<TcpStream> + Clone,
    {
        let guard = self.exec.guard().cloned();
        let cancelled_fut = async {
            if let Some(guard) = guard {
                guard.cancelled().await;
            } else {
                // If there is no executor/guard, we never trigger shutdown this way
                std::future::pending::<()>().await;
            }
        };
        let mut cancelled_fut = pin!(cancelled_fut);

        loop {
            tokio::select! {
                _ = cancelled_fut.as_mut() => {
                    tracing::trace!("signal received: initiate graceful shutdown");
                    break;
                }
                result = self.inner.accept() => {
                    match result {
                        Ok((socket, peer_addr)) => {
                            self.apply_stream_defaults(&socket);
                            let socket = TcpStream::new(socket);
                            let service = service.clone();

                            let local_addr = socket.local_addr().ok();
                            let trace_local_addr = local_addr
                                .unwrap_or_else(|| SocketAddress::default_ipv4(0));

                            let span = trace_root_span!(
                                "tcp::serve_graceful",
                                otel.kind = "server",
                                network.local.port = trace_local_addr.port,
                                network.local.address = %trace_local_addr.ip_addr,
                                network.peer.port = %peer_addr.port(),
                                network.peer.address = %peer_addr.ip(),
                                network.protocol.name = "tcp",
                            );

                            socket.extensions().insert(SocketInfo::new(local_addr, peer_addr.into()));

                            self.exec.spawn_task(async move {
                                _ = service.serve(socket).await;
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

#[cfg(target_family = "unix")]
mod unix_fd {
    use super::TcpListener;
    use std::os::unix::io::{AsFd, AsRawFd, BorrowedFd, RawFd};

    impl AsRawFd for TcpListener {
        #[inline(always)]
        fn as_raw_fd(&self) -> RawFd {
            self.inner.as_raw_fd()
        }
    }

    impl AsFd for TcpListener {
        #[inline(always)]
        fn as_fd(&self) -> BorrowedFd<'_> {
            self.inner.as_fd()
        }
    }
}

#[cfg(target_os = "windows")]
mod windows_socket {
    use super::TcpListener;
    use std::os::windows::io::{AsRawSocket, AsSocket, BorrowedSocket, RawSocket};

    impl AsRawSocket for TcpListener {
        #[inline(always)]
        fn as_raw_socket(&self) -> RawSocket {
            self.inner.as_raw_socket()
        }
    }

    impl AsSocket for TcpListener {
        #[inline(always)]
        fn as_socket(&self) -> BorrowedSocket<'_> {
            self.inner.as_socket()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_core::service::service_fn;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::mpsc;

    async fn listener(exec: Executor) -> TcpListener {
        TcpListener::bind_address(SocketAddress::local_ipv4(0), exec)
            .await
            .unwrap()
    }

    async fn accepted_nodelay(listener: TcpListener) -> bool {
        let addr = listener.local_addr().unwrap();
        let (accepted, _client) = tokio::join!(listener.accept(), async {
            tokio::net::TcpStream::connect(addr).await.unwrap()
        });
        let (stream, _) = accepted.unwrap();
        stream.stream.nodelay().unwrap()
    }

    #[tokio::test]
    async fn accept_sets_tcp_nodelay_by_default() {
        let listener = listener(Executor::default()).await;
        assert!(listener.tcp_no_delay());
        assert!(accepted_nodelay(listener).await);
    }

    #[tokio::test]
    async fn accept_can_opt_out_of_tcp_nodelay() {
        let listener = listener(Executor::default()).await.with_tcp_no_delay(false);
        assert!(!listener.tcp_no_delay());
        assert!(!accepted_nodelay(listener).await);
    }

    #[tokio::test]
    async fn builder_can_opt_out_of_tcp_nodelay() {
        let listener = TcpListener::build(Executor::default())
            .with_tcp_no_delay(false)
            .bind_address(SocketAddress::local_ipv4(0))
            .await
            .unwrap();
        assert!(!listener.tcp_no_delay());
        assert!(!accepted_nodelay(listener).await);
    }

    #[tokio::test]
    async fn listener_from_std_and_tokio_default_to_tcp_nodelay() {
        let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let listener =
            TcpListener::try_from_std_tcp_listener(std_listener, Executor::default()).unwrap();
        assert!(accepted_nodelay(listener).await);

        let tokio_listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener = TcpListener::from_tokio_tcp_listener(tokio_listener, Executor::default());
        assert!(accepted_nodelay(listener).await);
    }

    async fn served_nodelay(listener: TcpListener) -> bool {
        let addr = listener.local_addr().unwrap();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let tx = Arc::new(tx);
        let server = tokio::spawn(listener.serve(service_fn(move |stream: TcpStream| {
            let tx = tx.clone();
            async move {
                _ = tx.send(stream.stream.nodelay().unwrap());
                Ok::<_, std::convert::Infallible>(())
            }
        })));
        let _client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let nodelay = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("serve did not call the service")
            .unwrap();
        server.abort();
        nodelay
    }

    #[tokio::test]
    async fn serve_sets_tcp_nodelay_by_default() {
        assert!(served_nodelay(listener(Executor::default()).await).await);
    }

    #[tokio::test]
    async fn stream_options_layer_overrides_the_listener_default() {
        use rama_core::Layer as _;
        use rama_net::stream::layer::{TcpStreamOptions, TcpStreamOptionsLayer};

        let listener = listener(Executor::default()).await;
        let addr = listener.local_addr().unwrap();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let tx = Arc::new(tx);
        let service = TcpStreamOptionsLayer::new(TcpStreamOptions {
            tcp_no_delay: Some(false),
            ..Default::default()
        })
        .into_layer(service_fn(move |stream: TcpStream| {
            let tx = tx.clone();
            async move {
                _ = tx.send(stream.stream.nodelay().unwrap());
                Ok::<_, std::convert::Infallible>(())
            }
        }));
        let server = tokio::spawn(listener.serve(service));
        let _client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let nodelay = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("serve did not call the service")
            .unwrap();
        server.abort();
        assert!(
            !nodelay,
            "an explicit per-stream option must win over the listener default"
        );
    }

    #[tokio::test]
    async fn serve_can_opt_out_of_tcp_nodelay() {
        assert!(
            !served_nodelay(listener(Executor::default()).await.with_tcp_no_delay(false)).await
        );
    }
}
