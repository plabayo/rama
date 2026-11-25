use rama_core::Service;
use rama_core::error::BoxError;
use rama_core::error::ErrorContext;
use rama_core::extensions::ExtensionsRef;
use rama_core::futures::Stream;
use rama_core::graceful::WeakScope;
use rama_core::graceful::attach_scope;
use rama_core::telemetry::tracing::{self, Instrument, trace_root_span};
use rama_net::address::SocketAddress;
use rama_net::conn::{AcceptBackoff, PolledAcceptBackoff};
use rama_net::socket::core::SockRef;
use rama_net::stream::Socket;
use rama_net::stream::SocketInfo;
use std::pin::{Pin, pin};
use std::task::{Context, Poll, ready};
use std::{io, net::SocketAddr};
use tokio::net::{TcpListener as TokioTcpListener, TcpStream as TokioTcpStream};

#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
use rama_net::socket::{DeviceName, SocketOptions, opts::Domain};

use crate::TcpStream;

#[derive(Clone, Debug)]
/// Builder for `TcpListener`.
pub struct TcpListenerBuilder {
    ttl: Option<u32>,
    scope: WeakScope,
}

impl TcpListenerBuilder {
    /// Create a new `TcpListenerBuilder` without a state.
    #[must_use]
    pub fn new(scope: impl Into<WeakScope>) -> Self {
        let scope = scope.into();
        Self { ttl: None, scope }
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
}

impl TcpListenerBuilder {
    /// Creates a new TcpListener, which will be bound to the specified socket address.
    ///
    /// The returned listener is ready for accepting connections.
    ///
    /// Binding with a port number of 0 will request that the OS assigns a port
    /// to this listener. The port allocated can be queried via the `local_addr`
    /// method.
    ///
    /// Accepted connections have `TCP_NODELAY` on. Bind a socket built with your
    /// own [`SocketOptions`](rama_net::socket::SocketOptions) via `bind_socket`, or
    /// apply `TcpStreamOptions` per accepted stream, to choose otherwise.
    pub async fn bind_address<A: TryInto<SocketAddress, Error: Into<BoxError>>>(
        self,
        addr: A,
    ) -> Result<TcpListener, BoxError> {
        let socket_addr = addr.try_into().map_err(Into::<BoxError>::into)?;
        let tokio_socket_addr: SocketAddr = socket_addr.into();
        let inner = TokioTcpListener::bind(tokio_socket_addr)
            .await
            .map_err(Into::<BoxError>::into)?;
        // Accepted sockets inherit it, matching `SocketOptions::default_tcp`.
        SockRef::from(&inner)
            .set_tcp_nodelay(true)
            .context("set TCP_NODELAY on tcp listener")?;

        if let Some(ttl) = self.ttl {
            inner.set_ttl(ttl).context("set ttl on tcp listener")?;
        }

        Ok(TcpListener {
            inner,
            scope: self.scope,
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
        bind_socket_internal(socket, self.scope)
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
        bind_socket_internal(socket, self.scope)
    }
}

#[derive(Debug)]
/// A TCP socket server, listening for incoming connections once served
/// using one of the `serve` methods such as [`TcpListener::serve`].
pub struct TcpListener {
    inner: TokioTcpListener,
    scope: WeakScope,
}

impl TcpListener {
    /// Create a new `TcpListenerBuilder` without a state,
    /// which can be used to configure a `TcpListener`.
    #[must_use]
    pub fn build(scope: impl Into<WeakScope>) -> TcpListenerBuilder {
        let scope = scope.into();
        TcpListenerBuilder::new(scope)
    }

    /// Creates a new TcpListener, which will be bound to the specified (socket) address.
    ///
    /// The returned listener is ready for accepting connections.
    ///
    /// Binding with a port number of 0 will request that the OS assigns a port
    /// to this listener. The port allocated can be queried via the `local_addr`
    /// method.
    ///
    /// Accepted connections have `TCP_NODELAY` on. Bind a socket built with your
    /// own [`SocketOptions`](rama_net::socket::SocketOptions) via `bind_socket`, or
    /// apply `TcpStreamOptions` per accepted stream, to choose otherwise.
    pub async fn bind_address<A: TryInto<SocketAddress, Error: Into<BoxError>>>(
        addr: A,
        scope: WeakScope,
    ) -> Result<Self, BoxError> {
        TcpListenerBuilder::new(scope).bind_address(addr).await
    }

    #[cfg(any(target_os = "windows", target_family = "unix"))]
    #[cfg_attr(docsrs, doc(cfg(any(target_os = "windows", target_family = "unix"))))]
    /// Creates a new TcpListener, which will be bound to the specified socket.
    ///
    /// The returned listener is ready for accepting connections.
    pub async fn bind_socket(
        socket: rama_net::socket::core::Socket,
        scope: WeakScope,
    ) -> Result<Self, BoxError> {
        TcpListenerBuilder::new(scope).bind_socket(socket).await
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
        scope: WeakScope,
        domain: Domain,
        backlog: Option<i32>,
    ) -> Result<Self, BoxError> {
        TcpListenerBuilder::new(scope)
            .bind_device(name, domain, backlog)
            .await
    }
}

fn bind_socket_internal(
    socket: rama_net::socket::core::Socket,
    scope: WeakScope,
) -> Result<TcpListener, BoxError> {
    let listener = std::net::TcpListener::from(socket);
    listener
        .set_nonblocking(true)
        .context("set socket as non-blocking")?;
    Ok(TcpListener {
        inner: TokioTcpListener::from_std(listener)?,
        scope,
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

    pub fn from_tokio_tcp_listener(
        listener: TokioTcpListener,
        scope: impl Into<WeakScope>,
    ) -> Self {
        let scope = scope.into();
        Self {
            inner: listener,
            scope,
        }
    }

    #[cfg(any(target_os = "windows", target_family = "unix"))]
    #[cfg_attr(docsrs, doc(cfg(any(target_os = "windows", target_family = "unix"))))]
    pub fn try_from_socket(
        socket: rama_net::socket::core::Socket,
        scope: impl Into<WeakScope>,
    ) -> Result<Self, std::io::Error> {
        let scope = scope.into();
        let listener = std::net::TcpListener::from(socket);
        Self::try_from_std_tcp_listener(listener, scope)
    }

    pub fn try_from_std_tcp_listener(
        listener: std::net::TcpListener,
        scope: impl Into<WeakScope>,
    ) -> Result<Self, std::io::Error> {
        let scope = scope.into();
        listener.set_nonblocking(true)?;
        Ok(Self {
            inner: TokioTcpListener::from_std(listener)?,
            scope,
        })
    }
}

impl From<TokioTcpListener> for TcpListener {
    fn from(listener: TokioTcpListener) -> Self {
        Self::from_tokio_tcp_listener(listener, WeakScope::detached())
    }
}

/// An accepted connection with its [`SocketInfo`], and its local address if known.
fn accepted(socket: TokioTcpStream, peer: SocketAddr) -> (TcpStream, Option<SocketAddress>) {
    let socket = TcpStream::new(socket);
    let local_addr = socket.local_addr().ok();
    socket
        .extensions()
        .insert(SocketInfo::new(local_addr, peer.into()));
    (socket, local_addr)
}

impl TcpListener {
    /// Accept a single connection from this listener,
    /// what you can do with whatever you want.
    ///
    /// The connection carries its [`SocketInfo`], as a served one does.
    #[inline]
    pub async fn accept(&self) -> std::io::Result<(TcpStream, SocketAddress)> {
        let (stream, peer) = self.inner.accept().await?;
        Ok((accepted(stream, peer).0, peer.into()))
    }

    /// Accept connections as a [`Stream`] of what [`Self::accept`] returns.
    #[must_use]
    pub fn into_stream(self) -> TcpListenerStream {
        TcpListenerStream {
            listener: self,
            backoff: PolledAcceptBackoff::new(),
        }
    }

    /// Serve connections from this listener with the given service.
    ///
    /// This listener will spawn a task in which the inner service will
    /// handle the incomming connection. Cconnections will be served
    /// gracefully if the [`TcpListener`] is configured with a graceful [`WeakScope`].
    pub async fn serve<S>(self, service: S)
    where
        S: Service<TcpStream> + Clone,
    {
        // Serving holds the scope, so every connection accepted until the cancel is admitted.
        let Ok(scope) = self.scope.try_hold() else {
            tracing::debug!("scope closed: not serving");
            return;
        };
        let mut cancelled_fut = pin!(self.scope.cancelled());
        let mut accept_backoff = AcceptBackoff::new();

        loop {
            tokio::select! {
                _ = cancelled_fut.as_mut() => {
                    tracing::trace!("signal received: initiate graceful shutdown");
                    break;
                }
                result = self.inner.accept() => {
                    match result {
                        Ok((socket, peer_addr)) => {
                            accept_backoff.reset();
                            let (socket, local_addr) = accepted(socket, peer_addr);
                            let service = service.clone();

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

                            attach_scope(socket.extensions(), &scope);

                            // Ended at the hard phase, whatever the service does by then.
                            scope.spawn_task(async move {
                                _ = service.serve(socket).await;
                            }.instrument(span));
                        }
                        Err(err) => match accept_backoff.on_error(&err) {
                            None => tracing::trace!("TCP accept error: connection error: {err:?}"),
                            Some(delay) => {
                                // Running out of file descriptors keeps the listener readable, so retrying at once spins.
                                tracing::error!("TCP accept error: {err:?}; pausing accept for {delay:?}");
                                tokio::select! {
                                    _ = cancelled_fut.as_mut() => {
                                        tracing::trace!("signal received: initiate graceful shutdown");
                                        break;
                                    }
                                    () = tokio::time::sleep(delay) => {}
                                }
                            }
                        },
                    }
                }
            }
        }
    }
}

/// The connections a [`TcpListener`] accepts, as [`TcpListener::accept`] returns them;
/// it never ends. After a listener error it pauses as [`TcpListener::serve`] does.
#[derive(Debug)]
pub struct TcpListenerStream {
    listener: TcpListener,
    backoff: PolledAcceptBackoff,
}

impl TcpListenerStream {
    /// The listener, to accept from or serve directly again.
    #[must_use]
    pub fn into_inner(self) -> TcpListener {
        self.listener
    }
}

impl Stream for TcpListenerStream {
    type Item = io::Result<(TcpStream, SocketAddress)>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let Self { listener, backoff } = self.get_mut();
        let result = ready!(backoff.poll_accept(cx, |cx| listener.inner.poll_accept(cx)));
        Poll::Ready(Some(
            result.map(|(stream, peer)| (accepted(stream, peer).0, peer.into())),
        ))
    }
}

impl AsRef<TcpListener> for TcpListenerStream {
    fn as_ref(&self) -> &TcpListener {
        &self.listener
    }
}

impl AsMut<TcpListener> for TcpListenerStream {
    fn as_mut(&mut self) -> &mut TcpListener {
        &mut self.listener
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
    use std::{convert::Infallible, time::Duration};

    use rama_core::{
        futures::StreamExt as _,
        graceful::{Cause, Scope},
        service::service_fn,
    };
    use rama_net::{
        socket::{AsSocketRef as _, SocketOptions, opts::Domain},
        stream::{DefaultExtensionsTransfer, NestedConnection, layer::TcpStreamOptions},
    };
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        sync::mpsc,
        time::timeout,
    };

    use super::*;

    const LIMIT: Duration = Duration::from_secs(10);

    #[tokio::test]
    async fn a_connection_nested_on_an_accepted_one_resolves_the_outer_socket_info() {
        // `SocketInfo` is flow scoped, so the nested connection, also by ingress, sees the outer peer.
        let listener = TokioTcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut accepted = TcpListener::from(listener).into_stream();
        let client = TokioTcpStream::connect(address).await.unwrap();
        let (server, peer) = timeout(LIMIT, accepted.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(peer, SocketAddress::from(client.local_addr().unwrap()));

        let nested = NestedConnection::new(server, &DefaultExtensionsTransfer::new());
        let info = nested.extensions().get_ref::<SocketInfo>().unwrap();
        assert_eq!(info.peer_addr(), peer);
        let ingress = SocketInfo::ingress(nested.extensions()).unwrap();
        assert_eq!(ingress.peer_addr(), peer);
    }

    #[tokio::test]
    async fn the_stream_yields_accepted_connections_with_their_socket_info() {
        let listener = TokioTcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut accepted = TcpListener::from(listener).into_stream();

        for byte in [1u8, 2] {
            let mut client = TokioTcpStream::connect(address).await.unwrap();
            client.write_all(&[byte]).await.unwrap();
            let (mut server, peer) = timeout(LIMIT, accepted.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            let client_address = SocketAddress::from(client.local_addr().unwrap());
            assert_eq!(peer, client_address);
            let info = server.extensions().get_ref::<SocketInfo>().unwrap();
            assert_eq!(info.peer_addr(), client_address);
            assert_eq!(info.local_addr(), Some(SocketAddress::from(address)));
            assert_eq!(server.read_u8().await.unwrap(), byte);
        }

        assert_eq!(accepted.as_ref().local_addr().unwrap(), address);
        let listener = accepted.into_inner();
        let _client = TokioTcpStream::connect(address).await.unwrap();
        let (server, _peer) = timeout(LIMIT, listener.accept()).await.unwrap().unwrap();
        assert!(server.extensions().get_ref::<SocketInfo>().is_some());
    }

    #[tokio::test]
    async fn a_served_connection_ends_at_the_hard_phase() {
        let scope = Scope::new();
        let weak = scope.clone_weak();
        let listener = TcpListener::bind_address("127.0.0.1:0", scope.clone_weak())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let (accepted, mut accepted_rx) = mpsc::unbounded_channel();
        let serving = tokio::spawn(listener.serve(service_fn(move |stream: TcpStream| {
            accepted.send(()).unwrap();
            async move {
                std::future::pending::<()>().await;
                drop(stream);
                Ok::<_, Infallible>(())
            }
        })));
        let _client = tokio::net::TcpStream::connect(addr).await.unwrap();
        accepted_rx.recv().await.unwrap();

        scope.cancel(Cause::Owner);
        timeout(LIMIT, serving).await.unwrap().unwrap();
        assert!(
            timeout(Duration::from_millis(100), weak.drained())
                .await
                .is_err(),
            "the served connection drains in the graceful phase"
        );
        scope.abort(Cause::Owner);
        drop(scope);
        timeout(LIMIT, weak.drained())
            .await
            .expect("the served task ends at the hard phase");
    }

    /// Whether `TCP_NODELAY` is on for the next connection `listener` accepts.
    async fn accepted_nodelay(listener: &TcpListener, options: Option<&TcpStreamOptions>) -> bool {
        let addr = listener.local_addr().unwrap();
        let _client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (stream, _) = timeout(LIMIT, listener.accept()).await.unwrap().unwrap();
        if let Some(options) = options {
            options.try_apply(&stream).unwrap();
        }
        stream.as_socket_ref().tcp_nodelay().unwrap()
    }

    #[tokio::test]
    async fn bound_address_accepts_with_nodelay() {
        let scope = Scope::new();
        let listener = TcpListener::bind_address("127.0.0.1:0", scope.clone_weak())
            .await
            .unwrap();
        assert!(accepted_nodelay(&listener, None).await);
    }

    #[tokio::test]
    async fn stream_options_override_the_nodelay_default() {
        let scope = Scope::new();
        let listener = TcpListener::bind_address("127.0.0.1:0", scope.clone_weak())
            .await
            .unwrap();
        let options = TcpStreamOptions {
            tcp_no_delay: Some(false),
            ..Default::default()
        };
        assert!(!accepted_nodelay(&listener, Some(&options)).await);
    }

    #[cfg(any(target_os = "windows", target_family = "unix"))]
    #[tokio::test]
    async fn a_bound_socket_keeps_its_own_nodelay() {
        let scope = Scope::new();
        for no_delay in [false, true] {
            let socket = SocketOptions {
                address: Some(SocketAddress::local_ipv4(0)),
                tcp_no_delay: Some(no_delay),
                ..SocketOptions::default_tcp()
            }
            .try_build_socket(Domain::IPv4)
            .unwrap();
            socket.listen(16).unwrap();
            let listener = TcpListener::build(scope.clone_weak())
                .bind_socket(socket)
                .await
                .unwrap();
            assert_eq!(accepted_nodelay(&listener, None).await, no_delay);
        }
    }
}
