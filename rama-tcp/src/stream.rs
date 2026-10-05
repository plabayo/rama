use pin_project_lite::pin_project;
use rama_core::{extensions::Extensions, extensions::ExtensionsRef, io::AbortIo};
use rama_net::{address::SocketAddress, stream::Socket};
use std::{
    io,
    mem::ManuallyDrop,
    ptr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
pub use tokio::net::TcpStream as TokioTcpStream;

#[cfg(any(target_os = "windows", target_family = "unix"))]
use rama_net::socket;

pin_project! {
    /// A TCP stream with its [`Extensions`].
    ///
    /// It publishes an [`AbortIo`] in its own extensions: once called, dropping the
    /// stream sends a TCP RST instead of a FIN: SO_LINGER 0 only takes effect on close, which
    /// is the owner's to do.
    #[derive(Debug)]
    pub struct TcpStream {
        #[pin]
        pub stream: TokioTcpStream,
        pub extensions: Extensions,
        abort: Arc<AtomicBool>,
    }

    impl PinnedDrop for TcpStream {
        fn drop(this: Pin<&mut Self>) {
            let this = this.project();
            if this.abort.load(Ordering::Acquire) {
                // SO_LINGER 0: the close discards unsent data and sends an RST.
                _ = this.stream.set_zero_linger();
            }
        }
    }
}

impl TcpStream {
    #[inline(always)]
    pub fn new(stream: TokioTcpStream) -> Self {
        Self::from_tokio_tcp_stream(stream, Extensions::new())
    }

    #[cfg(any(target_os = "windows", target_family = "unix"))]
    #[cfg_attr(docsrs, doc(cfg(any(target_os = "windows", target_family = "unix"))))]
    /// Convert an already usable TCP socket into a Rama [`TcpStream`].
    ///
    /// This is a synchronous adapter. It sets the socket to non-blocking mode
    /// and registers it with Tokio, but it does not complete a pending
    /// non-blocking `connect(2)`.
    ///
    /// Use [`TcpStream::try_from_connecting_socket`] when `connect` returned an
    /// in-progress error such as `EINPROGRESS` or `WouldBlock`; that async
    /// constructor waits for connect completion and checks the pending socket
    /// error before returning.
    pub fn try_from_socket(
        socket: socket::core::Socket,
        extensions: Extensions,
    ) -> Result<Self, io::Error> {
        let stream = std::net::TcpStream::from(socket);
        Self::try_from_std_tcp_stream(stream, extensions)
    }

    #[cfg(any(target_os = "windows", target_family = "unix"))]
    #[cfg_attr(docsrs, doc(cfg(any(target_os = "windows", target_family = "unix"))))]
    /// Convert a TCP socket with a pending non-blocking connect into a Rama
    /// [`TcpStream`], then wait for the connect attempt to complete.
    ///
    /// Call this after invoking `connect` on a non-blocking socket when the OS
    /// reports that the connect is in progress. This mirrors Tokio's own TCP
    /// connect flow: wait for write-readiness, then inspect the pending socket
    /// error with `SO_ERROR`.
    pub async fn try_from_connecting_socket(
        socket: socket::core::Socket,
        extensions: Extensions,
    ) -> Result<Self, io::Error> {
        Self::try_from_socket(socket, extensions)?
            .finish_connect()
            .await
    }

    #[cfg(any(target_os = "windows", target_family = "unix"))]
    #[cfg_attr(docsrs, doc(cfg(any(target_os = "windows", target_family = "unix"))))]
    /// Convert a TCP socket with a pending non-blocking connect into a Rama
    /// [`TcpStream`], then wait up to `timeout` for the connect attempt to
    /// complete.
    ///
    /// If the timeout elapses, the stream is dropped and
    /// [`io::ErrorKind::TimedOut`] is returned.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rama_core::extensions::Extensions;
    /// use rama_net::socket::core::{Domain, Protocol, Socket, Type};
    /// use rama_tcp::TcpStream;
    /// use std::{io, net::SocketAddr, time::Duration};
    ///
    /// async fn connect_with_bound() -> io::Result<TcpStream> {
    ///     // TEST-NET-1 documentation address; useful for examples because it
    ///     // should not identify a real Internet host.
    ///     let addr: SocketAddr = "192.0.2.1:80".parse().unwrap();
    ///     let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    ///     socket.set_nonblocking(true)?;
    ///
    ///     match socket.connect(&addr.into()) {
    ///         Ok(()) => {}
    ///         Err(err)
    ///             if matches!(
    ///                 err.kind(),
    ///                 io::ErrorKind::WouldBlock | io::ErrorKind::AlreadyExists
    ///             ) => {}
    ///         Err(err) => return Err(err),
    ///     }
    ///
    ///     TcpStream::try_from_connecting_socket_with_timeout(
    ///         socket,
    ///         Extensions::new(),
    ///         Duration::from_secs(10),
    ///     )
    ///     .await
    /// }
    /// ```
    pub async fn try_from_connecting_socket_with_timeout(
        socket: socket::core::Socket,
        extensions: Extensions,
        timeout: Duration,
    ) -> Result<Self, io::Error> {
        Self::try_from_socket(socket, extensions)?
            .finish_connect_with_timeout(timeout)
            .await
    }

    /// Wait for a pending non-blocking connect on this stream to complete.
    ///
    /// Write-readiness signals that the connect attempt has finished, either
    /// successfully or with an error. The pending socket error is checked before
    /// success is returned.
    pub async fn finish_connect(self) -> Result<Self, io::Error> {
        self.stream.writable().await?;
        if let Some(err) = self.stream.take_error()? {
            return Err(err);
        }
        Ok(self)
    }

    /// Wait up to `timeout` for a pending non-blocking connect on this stream
    /// to complete.
    ///
    /// If the timeout elapses, the stream is dropped and
    /// [`io::ErrorKind::TimedOut`] is returned.
    pub async fn finish_connect_with_timeout(self, timeout: Duration) -> Result<Self, io::Error> {
        match tokio::time::timeout(timeout, self.finish_connect()).await {
            Ok(result) => result,
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "tcp connect did not complete before timeout",
            )),
        }
    }

    /// Convert an already usable standard TCP stream into a Rama [`TcpStream`].
    ///
    /// This is a synchronous adapter. It does not complete a pending
    /// non-blocking connect; use [`TcpStream::finish_connect`] after conversion
    /// when the stream represents an in-progress connect attempt.
    pub fn try_from_std_tcp_stream(
        stream: std::net::TcpStream,
        extensions: Extensions,
    ) -> Result<Self, io::Error> {
        stream.set_nonblocking(true)?;
        let stream = TokioTcpStream::from_std(stream)?;
        Ok(Self::from_tokio_tcp_stream(stream, extensions))
    }

    pub fn from_tokio_tcp_stream(stream: TokioTcpStream, extensions: Extensions) -> Self {
        let abort = Arc::new(AtomicBool::new(false));
        extensions.insert(AbortIo::new({
            let abort = abort.clone();
            move || abort.store(true, Ordering::Release)
        }));
        Self {
            stream,
            extensions,
            abort,
        }
    }
}

impl From<TokioTcpStream> for TcpStream {
    fn from(value: TokioTcpStream) -> Self {
        Self::new(value)
    }
}

impl From<TcpStream> for TokioTcpStream {
    /// The caller takes over the socket, and with it how it closes.
    fn from(value: TcpStream) -> Self {
        // Every field is read exactly once and `value` itself is never dropped.
        let value = ManuallyDrop::new(value);
        // SAFETY: read once, see above.
        drop(unsafe { ptr::read(&value.extensions) });
        // SAFETY: read once, see above.
        drop(unsafe { ptr::read(&value.abort) });
        // SAFETY: read once, see above.
        unsafe { ptr::read(&value.stream) }
    }
}

impl ExtensionsRef for TcpStream {
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

rama_net::stream::rama_delegate_async_read_write!(TcpStream => stream);

impl Socket for TcpStream {
    #[inline]
    fn local_addr(&self) -> std::io::Result<SocketAddress> {
        self.stream.local_addr().map(Into::into)
    }

    #[inline]
    fn peer_addr(&self) -> std::io::Result<SocketAddress> {
        self.stream.peer_addr().map(Into::into)
    }
}

#[cfg(any(target_os = "windows", target_family = "unix"))]
impl rama_net::socket::AsSocketRef for TcpStream {
    #[inline]
    fn as_socket_ref(&self) -> rama_net::socket::core::SockRef<'_> {
        rama_net::socket::AsSocketRef::as_socket_ref(&self.stream)
    }
}

#[cfg(target_family = "unix")]
mod unix {
    use super::TcpStream;
    use std::os::fd::{AsFd, AsRawFd};

    impl AsFd for TcpStream {
        #[inline(always)]
        fn as_fd(&self) -> std::os::unix::prelude::BorrowedFd<'_> {
            self.stream.as_fd()
        }
    }

    impl AsRawFd for TcpStream {
        #[inline(always)]
        fn as_raw_fd(&self) -> std::os::unix::prelude::RawFd {
            self.stream.as_raw_fd()
        }
    }
}

#[cfg(target_os = "windows")]
mod windows {
    use super::TcpStream;
    use std::os::windows::io::{AsRawSocket, AsSocket, BorrowedSocket, RawSocket};

    impl AsSocket for TcpStream {
        #[inline(always)]
        fn as_socket(&self) -> BorrowedSocket<'_> {
            self.stream.as_socket()
        }
    }

    impl AsRawSocket for TcpStream {
        #[inline(always)]
        fn as_raw_socket(&self) -> RawSocket {
            self.stream.as_raw_socket()
        }
    }
}

#[cfg(all(test, any(target_os = "windows", target_family = "unix")))]
mod tests {
    use super::*;
    use rama_net::socket::core::{Domain, Protocol, Socket as CoreSocket, Type};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    /// A connected loopback pair: our [`TcpStream`] and the peer's plain socket.
    async fn pair() -> io::Result<(TcpStream, TokioTcpStream)> {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
        let ours = TokioTcpStream::connect(listener.local_addr()?).await?;
        let (peer, _) = listener.accept().await?;
        Ok((TcpStream::new(ours), peer))
    }

    #[tokio::test]
    async fn an_aborted_stream_resets_its_peer_on_drop() {
        let (stream, mut peer) = pair().await.unwrap();
        let abort = stream.extensions().self_get_arc::<AbortIo>().unwrap();
        abort.abort();
        drop(stream);
        let error = peer.read(&mut [0; 8]).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
    }

    #[tokio::test]
    async fn a_dropped_stream_still_ends_in_order() {
        let (mut stream, mut peer) = pair().await.unwrap();
        stream.write_all(b"whole").await.unwrap();
        drop(stream);
        let mut received = Vec::new();
        peer.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"whole");
    }

    #[tokio::test]
    async fn taking_the_tokio_stream_out_keeps_it_open() {
        let (stream, mut peer) = pair().await.unwrap();
        stream
            .extensions()
            .self_get_arc::<AbortIo>()
            .unwrap()
            .abort();
        // The caller owns the socket now: neither a close nor a reset happens here.
        let mut ours = TokioTcpStream::from(stream);
        ours.write_all(b"still").await.unwrap();
        let mut buf = [0; 5];
        peer.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"still");
    }

    #[tokio::test]
    async fn try_from_connecting_socket_finishes_manual_nonblocking_connect() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        let socket = CoreSocket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
        socket.set_nonblocking(true).unwrap();
        match socket.connect(&addr.into()) {
            Ok(()) => {}
            Err(err) if nonblocking_connect_in_progress(&err) => {}
            Err(err) => panic!("manual nonblocking connect failed: {err:?}"),
        }

        let stream = TcpStream::try_from_connecting_socket(socket, Extensions::new())
            .await
            .unwrap();

        assert_eq!(stream.stream.peer_addr().unwrap(), addr);
        drop(stream);
        drop(listener);
    }

    #[tokio::test]
    async fn try_from_connecting_socket_with_timeout_bounds_documentation_address() {
        let addr: std::net::SocketAddr = "192.0.2.1:80".parse().unwrap();
        let socket = CoreSocket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
        socket.set_nonblocking(true).unwrap();

        match socket.connect(&addr.into()) {
            Ok(()) => return,
            Err(err) if nonblocking_connect_in_progress(&err) => {}
            Err(err) if immediate_connect_failure(&err) => return,
            Err(err) => panic!("manual nonblocking connect failed: {err:?}"),
        }

        match TcpStream::try_from_connecting_socket_with_timeout(
            socket,
            Extensions::new(),
            Duration::from_nanos(1),
        )
        .await
        {
            Err(err) if err.kind() == io::ErrorKind::TimedOut => {}
            Err(err) if immediate_connect_failure(&err) => {}
            Err(err) => panic!("unexpected connect completion error: {err:?}"),
            Ok(_) => panic!("documentation address unexpectedly connected"),
        }
    }

    fn nonblocking_connect_in_progress(err: &io::Error) -> bool {
        matches!(
            err.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::AlreadyExists
        ) || nonblocking_connect_in_progress_os(err)
    }

    fn immediate_connect_failure(err: &io::Error) -> bool {
        matches!(
            err.kind(),
            io::ErrorKind::AddrNotAvailable
                | io::ErrorKind::ConnectionRefused
                | io::ErrorKind::HostUnreachable
                | io::ErrorKind::NetworkUnreachable
        )
    }

    #[cfg(target_family = "unix")]
    fn nonblocking_connect_in_progress_os(err: &io::Error) -> bool {
        matches!(err.raw_os_error(), Some(libc::EINPROGRESS | libc::EALREADY))
    }

    #[cfg(not(target_family = "unix"))]
    fn nonblocking_connect_in_progress_os(_err: &io::Error) -> bool {
        false
    }
}
