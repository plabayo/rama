use crate::UdpFramed;
use rama_core::bytes::BufMut;
use rama_core::error::{BoxError, ErrorContext};
use rama_net::{address::SocketAddress, socket::Interface};
use std::task::{Context, Poll};
use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
};
use tokio::io::ReadBuf;
use tokio::net::UdpSocket as TokioUdpSocket;

#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
use rama_net::socket::{DeviceName, SocketOptions};

/// A UDP socket.
///
/// UDP is "connectionless", unlike TCP. Meaning, regardless of what address you've bound to, a `UdpSocket`
/// is free to communicate with many different remotes. In tokio there are basically two main ways to use `UdpSocket`:
///
/// * one to many: [`bind`](`UdpSocket::bind`) and use [`send_to`](`UdpSocket::send_to`)
///   and [`recv_from`](`UdpSocket::recv_from`) to communicate with many different addresses
/// * one to one: [`connect`](`UdpSocket::connect`) and associate with a single address, using [`send`](`UdpSocket::send`)
///   and [`recv`](`UdpSocket::recv`) to communicate only with that remote address
///
/// This type does not provide a `split` method, because this functionality
/// can be achieved by instead wrapping the socket in an [`Arc`]. Note that
/// you do not need a `Mutex` to share the `UdpSocket` — an `Arc<UdpSocket>`
/// is enough. This is because all of the methods take `&self` instead of
/// `&mut self`. Once you have wrapped it in an `Arc`, you can call
/// `.clone()` on the `Arc<UdpSocket>` to get multiple shared handles to the
/// same socket. An example of such usage can be found further down.
///
/// [`Arc`]: std::sync::Arc
#[derive(Debug)]
pub struct UdpSocket {
    inner: TokioUdpSocket,
}

impl UdpSocket {
    /// Creates a new [`UdpSocket`], which will be bound to the specified address.
    ///
    /// The returned socket is ready for accepting connections and connecting to others.
    ///
    /// Binding with a port number of 0 will request that the OS assigns a port
    /// to this listener. The port allocated can be queried via the `local_addr`
    /// method.
    pub async fn bind_address<A: TryInto<SocketAddress, Error: Into<BoxError>>>(
        addr: A,
    ) -> Result<Self, BoxError> {
        let socket_addr = addr.try_into().map_err(Into::into)?;
        let tokio_socket_addr: SocketAddr = socket_addr.into();
        let inner = TokioUdpSocket::bind(tokio_socket_addr)
            .await
            .context("bind to udp socket")?;
        Ok(Self { inner })
    }

    #[cfg(any(windows, unix))]
    /// Creates a new [`UdpSocket`], which will be bound to the specified socket.
    ///
    /// The returned socket is ready for accepting connections and connecting to others.
    pub async fn bind_socket(socket: rama_net::socket::core::Socket) -> Result<Self, BoxError> {
        tokio::task::spawn_blocking(|| bind_socket_internal(socket))
            .await
            .context("await blocking bind socket task")?
    }

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    /// Creates a new [`UdpSocket`], which will be bound to the specified (interface) device name).
    ///
    /// The returned socket is ready for accepting connections and connecting to others.
    pub async fn bind_device<N: TryInto<DeviceName, Error: Into<BoxError>> + Send + 'static>(
        name: N,
    ) -> Result<Self, BoxError> {
        tokio::task::spawn_blocking(|| {
            let name = name.try_into().map_err(Into::<BoxError>::into)?;
            let socket = SocketOptions {
                device: Some(name),
                ..SocketOptions::default_udp()
            }
            .try_build_socket()
            .context("create udp ipv4 socket attached to device")?;
            bind_socket_internal(socket)
        })
        .await
        .context("await blocking bind socket task")?
    }

    /// Creates a new UdpSocket, which will be bound to the specified interface.
    ///
    /// The returned socket is ready for accepting connections and connecting to others.
    pub async fn bind<I: TryInto<Interface, Error: Into<BoxError>>>(
        interface: I,
    ) -> Result<Self, BoxError> {
        match interface.try_into().map_err(Into::<BoxError>::into)? {
            Interface::Address(addr) => Self::bind_address(addr).await,
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            Interface::Device(name) => Self::bind_device(name).await,
            Interface::Socket(opts) => {
                let socket = opts
                    .try_build_socket()
                    .context("build udp socket from options")?;
                Self::bind_socket(socket).await
            }
        }
    }

    /// Creates new `UdpSocket` from a previously bound `std::net::UdpSocket`.
    ///
    /// This function is intended to be used to wrap a UDP socket from the
    /// standard library in the Tokio equivalent.
    ///
    /// This can be used in conjunction with `rama_net::socket::core::Socket` interface to
    /// configure a socket before it's handed off, such as setting options like
    /// `reuse_address` or binding to multiple addresses.
    ///
    /// # Panics
    ///
    /// This function panics if thread-local runtime is not set.
    ///
    /// The runtime is usually set implicitly when this function is called
    /// from a future driven by a tokio runtime, otherwise runtime can be set
    /// explicitly with [`Runtime::enter`](crate::runtime::Runtime::enter) function.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rama_udp::UdpSocket;
    /// # use std::{io, net::SocketAddr};
    ///
    /// # #[tokio::main]
    /// # async fn main() -> io::Result<()> {
    /// let addr = "0.0.0.0:8080".parse::<SocketAddr>().unwrap();
    /// let std_sock = std::net::UdpSocket::bind(addr)?;
    /// let sock = UdpSocket::from_std(std_sock)?;
    /// // use `sock`
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    pub fn from_std(socket: std::net::UdpSocket) -> io::Result<Self> {
        socket.set_nonblocking(true)?;
        Ok(TokioUdpSocket::from_std(socket)?.into())
    }

    /// Turns a [`UdpSocket`] into a [`std::net::UdpSocket`].
    ///
    /// The returned [`std::net::UdpSocket`] will have nonblocking mode set as
    /// `true`.  Use [`set_nonblocking`] to change the blocking mode if needed.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use rama_core::error::BoxError;
    /// use rama_net::address::SocketAddress;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), BoxError> {
    ///     let socket = rama_udp::UdpSocket::bind(SocketAddress::local_ipv4(0)).await?;
    ///     let std_socket = socket.into_std()?;
    ///     std_socket.set_nonblocking(false)?;
    ///     Ok(())
    /// }
    /// ```
    ///
    /// [`std::net::UdpSocket`]: std::net::UdpSocket
    /// [`set_nonblocking`]: fn@std::net::UdpSocket::set_nonblocking
    #[inline]
    pub fn into_std(self) -> io::Result<std::net::UdpSocket> {
        self.inner.into_std()
    }

    /// Expose a reference to `self` as a [`rama_net::socket::core::SockRef`].
    #[cfg(any(windows, unix))]
    #[inline]
    pub fn as_socket(&self) -> rama_net::socket::core::SockRef<'_> {
        rama_net::socket::core::SockRef::from(self)
    }

    /// Returns the local address that this socket is bound to.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rama_udp::UdpSocket;
    /// use rama_core::error::BoxError;
    /// use rama_net::address::SocketAddress;
    /// # use std::io;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), BoxError> {
    /// let addr = SocketAddress::local_ipv4(8080);
    /// let sock = UdpSocket::bind(addr).await?;
    /// // the address the socket is bound to
    /// let local_addr = sock.local_addr()?;
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// Returns the socket address of the remote peer this socket was connected to.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rama_udp::UdpSocket;
    /// use rama_core::error::BoxError;
    /// use rama_net::address::SocketAddress;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), BoxError> {
    /// let addr = SocketAddress::local_ipv4(8080);
    /// let peer = SocketAddress::local_ipv4(11100);
    /// let sock = UdpSocket::bind(addr).await?;
    /// sock.connect(peer).await?;
    /// assert_eq!(peer, sock.peer_addr()?.into());
    /// #    Ok(())
    /// # }
    /// ```
    #[inline]
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.inner.peer_addr()
    }

    /// Connects the UDP socket setting the default destination for send() and
    /// limiting packets that are read via `recv` from the address specified in
    /// `addr`.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rama_udp::UdpSocket;
    /// use rama_core::error::BoxError;
    /// use rama_net::address::SocketAddress;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), BoxError> {
    /// let sock = UdpSocket::bind(SocketAddress::default_ipv4(8080)).await?;
    ///
    /// let remote_addr = SocketAddress::local_ipv4(59600);
    /// sock.connect(remote_addr).await?;
    /// let mut buf = [0u8; 32];
    /// // recv from remote_addr
    /// let len = sock.recv(&mut buf).await?;
    /// // send to remote_addr
    /// let _len = sock.send(&buf[..len]).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    pub async fn connect<A: TryInto<SocketAddress, Error: Into<BoxError>>>(
        &self,
        addr: A,
    ) -> Result<(), BoxError> {
        let socket_addr = addr.try_into().map_err(Into::into)?;
        let tokio_socket_addr: SocketAddr = socket_addr.into();
        self.inner.connect(tokio_socket_addr).await?;
        Ok(())
    }

    /// Sends data on the socket to the remote address that the socket is
    /// connected to.
    ///
    /// The [`connect`] method will connect this socket to a remote address.
    /// This method will fail if the socket is not connected.
    ///
    /// [`connect`]: method@Self::connect
    ///
    /// # Return
    ///
    /// On success, the number of bytes sent is returned, otherwise, the
    /// encountered error is returned.
    ///
    /// # Cancel safety
    ///
    /// This method is cancel safe. If `send` is used as the event in a
    /// [`tokio::select!`] statement and some other branch
    /// completes first, then it is guaranteed that the message was not sent.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rama_core::error::BoxError;
    /// use rama_udp::UdpSocket;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), BoxError> {
    ///     let socket = UdpSocket::bind("127.0.0.1:8080").await?;
    ///     socket.connect("127.0.0.1:8081").await?;
    ///
    ///     // Send a message
    ///     socket.send(b"hello world").await?;
    ///
    ///     Ok(())
    /// }
    /// ```
    #[inline]
    pub async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.inner.send(buf).await
    }

    /// Same as [`Self::send`] but polled.
    ///
    /// Note that on multiple calls to a `poll_*` method in the send direction,
    /// only the `Waker` from the `Context` passed to the most recent call will
    /// be scheduled to receive a wakeup.
    ///
    /// # Return value
    ///
    /// The function returns:
    ///
    /// * `Poll::Pending` if the socket is not available to write
    /// * `Poll::Ready(Ok(n))` `n` is the number of bytes sent
    /// * `Poll::Ready(Err(e))` if an error is encountered.
    ///
    /// # Errors
    ///
    /// This function may encounter any standard I/O error except `WouldBlock`.
    #[inline]
    pub fn poll_send(&self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.inner.poll_send(cx, buf)
    }

    /// Receives a single datagram message on the socket from the remote address
    /// to which it is connected. On success, returns the number of bytes read.
    ///
    /// The function must be called with valid byte array `buf` of sufficient
    /// size to hold the message bytes. If a message is too long to fit in the
    /// supplied buffer, excess bytes may be discarded.
    ///
    /// The [`connect`] method will connect this socket to a remote address.
    /// This method will fail if the socket is not connected.
    ///
    /// # Cancel safety
    ///
    /// This method is cancel safe. If `recv` is used as the event in a
    /// [`tokio::select!`] statement and some other branch
    /// completes first, it is guaranteed that no messages were received on this
    /// socket.
    ///
    /// [`connect`]: method@Self::connect
    ///
    /// ```no_run
    /// use rama_udp::UdpSocket;
    /// use rama_core::error::BoxError;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), BoxError> {
    ///     // Bind socket
    ///     let socket = UdpSocket::bind("127.0.0.1:8080").await?;
    ///     socket.connect("127.0.0.1:8081").await?;
    ///
    ///     let mut buf = vec![0; 10];
    ///     let n = socket.recv(&mut buf).await?;
    ///
    ///     println!("received {} bytes {:?}", n, &buf[..n]);
    ///
    ///     Ok(())
    /// }
    /// ```
    #[inline]
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.recv(buf).await
    }

    /// Same as [`Self::recv`] but polled.
    ///
    /// Note that on multiple calls to a `poll_*` method in the `recv` direction, only the
    /// `Waker` from the `Context` passed to the most recent call will be scheduled to
    /// receive a wakeup.
    ///
    /// # Return value
    ///
    /// The function returns:
    ///
    /// * `Poll::Pending` if the socket is not ready to read
    /// * `Poll::Ready(Ok(()))` reads data `ReadBuf` if the socket is ready
    /// * `Poll::Ready(Err(e))` if an error is encountered.
    ///
    /// # Errors
    ///
    /// This function may encounter any standard I/O error except `WouldBlock`.
    #[inline]
    pub fn poll_recv(&self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.inner.poll_recv(cx, buf)
    }

    /// Receives a single datagram message on the socket from the remote address
    /// to which it is connected, advancing the buffer's internal cursor,
    /// returning how many bytes were read.
    ///
    /// This method must be called with valid byte array `buf` of sufficient size
    /// to hold the message bytes. If a message is too long to fit in the
    /// supplied buffer, excess bytes may be discarded.
    ///
    /// This method can be used even if `buf` is uninitialized.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rama_udp::UdpSocket;
    /// use rama_core::error::BoxError;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), BoxError> {
    ///     let socket = UdpSocket::bind("127.0.0.1:8080").await?;
    ///     socket.connect("127.0.0.1:8081").await?;
    ///
    ///     let mut buf = Vec::with_capacity(512);
    ///     let len = socket.recv_buf(&mut buf).await?;
    ///
    ///     println!("received {} bytes {:?}", len, &buf[..len]);
    ///
    ///     Ok(())
    /// }
    /// ```
    pub async fn recv_buf<B: BufMut>(&self, buf: &mut B) -> io::Result<usize> {
        self.inner.recv_buf(buf).await
    }

    /// Receives a single datagram message on the socket, advancing the
    /// buffer's internal cursor, returning how many bytes were read and the origin.
    ///
    /// This method must be called with valid byte array `buf` of sufficient size
    /// to hold the message bytes. If a message is too long to fit in the
    /// supplied buffer, excess bytes may be discarded.
    ///
    /// This method can be used even if `buf` is uninitialized.
    ///
    /// # Notes
    /// Note that the socket address **cannot** be implicitly trusted, because it is relatively
    /// trivial to send a UDP datagram with a spoofed origin in a [packet injection attack].
    /// Because UDP is stateless and does not validate the origin of a packet,
    /// the attacker does not need to be able to intercept traffic in order to interfere.
    /// It is important to be aware of this when designing your application-level protocol.
    ///
    /// [packet injection attack]: https://en.wikipedia.org/wiki/Packet_injection
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rama_udp::UdpSocket;
    /// use rama_core::error::BoxError;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), BoxError> {
    ///     let socket = UdpSocket::bind("127.0.0.1:8080").await?;
    ///     socket.connect("127.0.0.1:8081").await?;
    ///
    ///     let mut buf = Vec::with_capacity(512);
    ///     let (len, addr) = socket.recv_buf_from(&mut buf).await?;
    ///
    ///     println!("received {:?} bytes from {:?}", len, addr);
    ///
    ///     Ok(())
    /// }
    /// ```
    #[inline]
    pub async fn recv_buf_from<B: BufMut>(
        &self,
        buf: &mut B,
    ) -> io::Result<(usize, SocketAddress)> {
        let (n, addr) = self.inner.recv_buf_from(buf).await?;
        Ok((n, addr.into()))
    }

    /// Sends data on the socket to the given address. On success, returns the
    /// number of bytes written.
    ///
    /// # Cancel safety
    ///
    /// This method is cancel safe. If `send_to` is used as the event in a
    /// [`tokio::select!`]- statement and some other branch
    /// completes first, then it is guaranteed that the message was not sent.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rama_udp::UdpSocket;
    /// use rama_core::error::BoxError;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), BoxError> {
    ///     let socket = UdpSocket::bind("127.0.0.1:8080").await?;
    ///     let len = socket.send_to(b"hello world", "127.0.0.1:8081").await?;
    ///
    ///     println!("Sent {} bytes", len);
    ///
    ///     Ok(())
    /// }
    /// ```
    #[inline]
    pub async fn send_to<A: TryInto<SocketAddress, Error: Into<BoxError>>>(
        &self,
        buf: &[u8],
        addr: A,
    ) -> Result<usize, BoxError> {
        let socket_addr = addr.try_into().map_err(Into::into)?;
        let tokio_socket_addr: SocketAddr = socket_addr.into();
        Ok(self.inner.send_to(buf, tokio_socket_addr).await?)
    }

    #[inline]
    /// Same as [`Self::send_to`] but polled.
    ///
    /// Note that on multiple calls to a `poll_*` method in the send direction, only the
    /// `Waker` from the `Context` passed to the most recent call will be scheduled to
    /// receive a wakeup.
    ///
    /// # Return value
    ///
    /// The function returns:
    ///
    /// * `Poll::Pending` if the socket is not ready to write
    /// * `Poll::Ready(Ok(n))` `n` is the number of bytes sent.
    /// * `Poll::Ready(Err(e))` if an error is encountered.
    ///
    /// # Errors
    ///
    /// This function may encounter any standard I/O error except `WouldBlock`.
    pub fn poll_send_to<A: TryInto<SocketAddress, Error: Into<BoxError>>>(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        addr: A,
    ) -> Poll<Result<usize, BoxError>> {
        let socket_addr = addr.try_into().map_err(Into::into)?;
        let tokio_socket_addr: SocketAddr = socket_addr.into();
        self.inner
            .poll_send_to(cx, buf, tokio_socket_addr)
            .map_err(BoxError::from)
    }

    /// Receives a single datagram message on the socket. On success, returns
    /// the number of bytes read and the origin.
    ///
    /// The function must be called with valid byte array `buf` of sufficient
    /// size to hold the message bytes. If a message is too long to fit in the
    /// supplied buffer, excess bytes may be discarded.
    ///
    /// # Cancel safety
    ///
    /// This method is cancel safe. If `recv_from` is used as the event in a
    /// [`tokio::select!`] statement and some other branch
    /// completes first, it is guaranteed that no messages were received on this
    /// socket.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rama_udp::UdpSocket;
    /// use rama_core::error::BoxError;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), BoxError> {
    ///     let socket = UdpSocket::bind("127.0.0.1:8080").await?;
    ///
    ///     let mut buf = vec![0u8; 32];
    ///     let (len, addr) = socket.recv_from(&mut buf).await?;
    ///
    ///     println!("received {:?} bytes from {:?}", len, addr);
    ///
    ///     Ok(())
    /// }
    /// ```
    ///
    /// # Notes
    /// Note that the socket address **cannot** be implicitly trusted, because it is relatively
    /// trivial to send a UDP datagram with a spoofed origin in a [packet injection attack].
    /// Because UDP is stateless and does not validate the origin of a packet,
    /// the attacker does not need to be able to intercept traffic in order to interfere.
    /// It is important to be aware of this when designing your application-level protocol.
    ///
    /// [packet injection attack]: https://en.wikipedia.org/wiki/Packet_injection
    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddress)> {
        let (n, addr) = self.inner.recv_from(buf).await?;
        Ok((n, addr.into()))
    }

    /// Same as [`Self::recv_from`] but polled.
    pub fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<SocketAddress>> {
        self.inner.poll_recv_from(cx, buf).map_ok(Into::into)
    }

    /// Receives a single datagram from the connected address without removing it from the queue.
    /// On success, returns the number of bytes read from whence the data came.
    ///
    /// # Notes
    ///
    /// On Windows, if the data is larger than the buffer specified, the buffer
    /// is filled with the first part of the data, and `peek_from` returns the error
    /// `WSAEMSGSIZE(10040)`. The excess data is lost.
    /// Make sure to always use a sufficiently large buffer to hold the
    /// maximum UDP packet size, which can be up to 65536 bytes in size.
    ///
    /// MacOS will return an error if you pass a zero-sized buffer.
    ///
    /// If you're merely interested in learning the sender of the data at the head of the queue,
    /// try [`peek_sender`].
    ///
    /// Note that the socket address **cannot** be implicitly trusted, because it is relatively
    /// trivial to send a UDP datagram with a spoofed origin in a [packet injection attack].
    /// Because UDP is stateless and does not validate the origin of a packet,
    /// the attacker does not need to be able to intercept traffic in order to interfere.
    /// It is important to be aware of this when designing your application-level protocol.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rama_udp::UdpSocket;
    /// use rama_core::error::BoxError;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), BoxError> {
    ///     let socket = UdpSocket::bind("127.0.0.1:8080").await?;
    ///
    ///     let mut buf = vec![0u8; 32];
    ///     let len = socket.peek(&mut buf).await?;
    ///
    ///     println!("peeked {:?} bytes", len);
    ///
    ///     Ok(())
    /// }
    /// ```
    ///
    /// [`peek_sender`]: method@Self::peek_sender
    /// [packet injection attack]: https://en.wikipedia.org/wiki/Packet_injection
    #[inline]
    pub async fn peek(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.peek(buf).await
    }

    /// Receives data from the socket, without removing it from the input queue.
    /// On success, returns the number of bytes read and the address from whence
    /// the data came.
    ///
    /// # Notes
    ///
    /// On Windows, if the data is larger than the buffer specified, the buffer
    /// is filled with the first part of the data, and `peek_from` returns the error
    /// `WSAEMSGSIZE(10040)`. The excess data is lost.
    /// Make sure to always use a sufficiently large buffer to hold the
    /// maximum UDP packet size, which can be up to 65536 bytes in size.
    ///
    /// MacOS will return an error if you pass a zero-sized buffer.
    ///
    /// If you're merely interested in learning the sender of the data at the head of the queue,
    /// try [`peek_sender`].
    ///
    /// Note that the socket address **cannot** be implicitly trusted, because it is relatively
    /// trivial to send a UDP datagram with a spoofed origin in a [packet injection attack].
    /// Because UDP is stateless and does not validate the origin of a packet,
    /// the attacker does not need to be able to intercept traffic in order to interfere.
    /// It is important to be aware of this when designing your application-level protocol.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rama_udp::UdpSocket;
    /// use rama_core::error::BoxError;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), BoxError> {
    ///     let socket = UdpSocket::bind("127.0.0.1:8080").await?;
    ///
    ///     let mut buf = vec![0u8; 32];
    ///     let (len, addr) = socket.peek_from(&mut buf).await?;
    ///
    ///     println!("peeked {:?} bytes from {:?}", len, addr);
    ///
    ///     Ok(())
    /// }
    /// ```
    ///
    /// [`peek_sender`]: method@Self::peek_sender
    /// [packet injection attack]: https://en.wikipedia.org/wiki/Packet_injection
    #[inline]
    pub async fn peek_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddress)> {
        let (n, addr) = self.inner.peek_from(buf).await?;
        Ok((n, addr.into()))
    }

    /// Retrieve the sender of the data at the head of the input queue, waiting if empty.
    ///
    /// This is equivalent to calling [`peek_from`] with a zero-sized buffer,
    /// but suppresses the `WSAEMSGSIZE` error on Windows and the "invalid argument" error on macOS.
    ///
    /// Note that the socket address **cannot** be implicitly trusted, because it is relatively
    /// trivial to send a UDP datagram with a spoofed origin in a [packet injection attack].
    /// Because UDP is stateless and does not validate the origin of a packet,
    /// the attacker does not need to be able to intercept traffic in order to interfere.
    /// It is important to be aware of this when designing your application-level protocol.
    ///
    /// [`peek_from`]: method@Self::peek_from
    /// [packet injection attack]: https://en.wikipedia.org/wiki/Packet_injection
    #[inline]
    pub async fn peek_sender(&self) -> io::Result<SocketAddress> {
        Ok(self.inner.peek_sender().await?.into())
    }

    /// Gets the value of the `SO_BROADCAST` option for this socket.
    ///
    /// For more information about this option, see [`set_broadcast`].
    ///
    /// [`set_broadcast`]: method@Self::set_broadcast
    #[inline]
    pub fn broadcast(&self) -> io::Result<bool> {
        self.inner.broadcast()
    }

    /// Sets the value of the `SO_BROADCAST` option for this socket.
    ///
    /// When enabled, this socket is allowed to send packets to a broadcast
    /// address.
    #[inline]
    pub fn set_broadcast(&self, on: bool) -> io::Result<()> {
        self.inner.set_broadcast(on)
    }

    /// Gets the value of the `IP_MULTICAST_LOOP` option for this socket.
    ///
    /// For more information about this option, see [`set_multicast_loop_v4`].
    ///
    /// [`set_multicast_loop_v4`]: method@Self::set_multicast_loop_v4
    #[inline]
    pub fn multicast_loop_v4(&self) -> io::Result<bool> {
        self.inner.multicast_loop_v4()
    }

    /// Sets the value of the `IP_MULTICAST_LOOP` option for this socket.
    ///
    /// If enabled, multicast packets will be looped back to the local socket.
    ///
    /// # Note
    ///
    /// This may not have any affect on IPv6 sockets.
    #[inline]
    pub fn set_multicast_loop_v4(&self, on: bool) -> io::Result<()> {
        self.inner.set_multicast_loop_v4(on)
    }

    /// Gets the value of the `IP_MULTICAST_TTL` option for this socket.
    ///
    /// For more information about this option, see [`set_multicast_ttl_v4`].
    ///
    /// [`set_multicast_ttl_v4`]: method@Self::set_multicast_ttl_v4
    #[inline]
    pub fn multicast_ttl_v4(&self) -> io::Result<u32> {
        self.inner.multicast_ttl_v4()
    }

    /// Sets the value of the `IP_MULTICAST_TTL` option for this socket.
    ///
    /// Indicates the time-to-live value of outgoing multicast packets for
    /// this socket. The default value is 1 which means that multicast packets
    /// don't leave the local network unless explicitly requested.
    ///
    /// # Note
    ///
    /// This may not have any affect on IPv6 sockets.
    #[inline]
    pub fn set_multicast_ttl_v4(&self, ttl: u32) -> io::Result<()> {
        self.inner.set_multicast_ttl_v4(ttl)
    }

    /// Gets the value of the `IPV6_MULTICAST_LOOP` option for this socket.
    ///
    /// For more information about this option, see [`set_multicast_loop_v6`].
    ///
    /// [`set_multicast_loop_v6`]: method@Self::set_multicast_loop_v6
    #[inline]
    pub fn multicast_loop_v6(&self) -> io::Result<bool> {
        self.inner.multicast_loop_v6()
    }

    /// Sets the value of the `IPV6_MULTICAST_LOOP` option for this socket.
    ///
    /// Controls whether this socket sees the multicast packets it sends itself.
    ///
    /// # Note
    ///
    /// This may not have any affect on IPv4 sockets.
    #[inline]
    pub fn set_multicast_loop_v6(&self, on: bool) -> io::Result<()> {
        self.inner.set_multicast_loop_v6(on)
    }

    /// Gets the value of the `IP_TTL` option for this socket.
    ///
    /// For more information about this option, see [`set_ttl`].
    ///
    /// [`set_ttl`]: method@Self::set_ttl
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rama_udp::UdpSocket;
    /// use rama_core::error::BoxError;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), BoxError> {
    /// let sock = UdpSocket::bind("127.0.0.1:8080").await?;
    ///
    /// println!("{:?}", sock.ttl()?);
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    pub fn ttl(&self) -> io::Result<u32> {
        self.inner.ttl()
    }

    /// Sets the value for the `IP_TTL` option on this socket.
    ///
    /// This value sets the time-to-live field that is used in every packet sent
    /// from this socket.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rama_udp::UdpSocket;
    /// use rama_core::error::BoxError;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), BoxError> {
    /// let sock = UdpSocket::bind("127.0.0.1:8080").await?;
    /// sock.set_ttl(60)?;
    ///
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    pub fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        self.inner.set_ttl(ttl)
    }

    /// Executes an operation of the `IP_ADD_MEMBERSHIP` type.
    ///
    /// This function specifies a new multicast group for this socket to join.
    /// The address must be a valid multicast address, and `interface` is the
    /// address of the local interface with which the system should join the
    /// multicast group. If it's equal to `INADDR_ANY` then an appropriate
    /// interface is chosen by the system.
    #[inline]
    pub fn join_multicast_v4(&self, multiaddr: Ipv4Addr, interface: Ipv4Addr) -> io::Result<()> {
        self.inner.join_multicast_v4(multiaddr, interface)
    }

    /// Executes an operation of the `IPV6_ADD_MEMBERSHIP` type.
    ///
    /// This function specifies a new multicast group for this socket to join.
    /// The address must be a valid multicast address, and `interface` is the
    /// index of the interface to join/leave (or 0 to indicate any interface).
    #[inline]
    pub fn join_multicast_v6(&self, multiaddr: Ipv6Addr, interface: u32) -> io::Result<()> {
        self.inner.join_multicast_v6(&multiaddr, interface)
    }

    /// Executes an operation of the `IP_DROP_MEMBERSHIP` type.
    ///
    /// For more information about this option, see [`join_multicast_v4`].
    ///
    /// [`join_multicast_v4`]: method@Self::join_multicast_v4
    #[inline]
    pub fn leave_multicast_v4(&self, multiaddr: Ipv4Addr, interface: Ipv4Addr) -> io::Result<()> {
        self.inner.leave_multicast_v4(multiaddr, interface)
    }

    /// Executes an operation of the `IPV6_DROP_MEMBERSHIP` type.
    ///
    /// For more information about this option, see [`join_multicast_v6`].
    ///
    /// [`join_multicast_v6`]: method@Self::join_multicast_v6
    #[inline]
    pub fn leave_multicast_v6(&self, multiaddr: Ipv6Addr, interface: u32) -> io::Result<()> {
        self.inner.leave_multicast_v6(&multiaddr, interface)
    }

    /// Returns the value of the `SO_ERROR` option.
    ///
    /// # Examples
    /// ```no_run
    /// use rama_udp::UdpSocket;
    /// use rama_core::error::BoxError;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), BoxError> {
    ///     let socket = UdpSocket::bind("0.0.0.0:8080").await?;
    ///
    ///     if let Ok(Some(err)) = socket.take_error() {
    ///         println!("Got error: {:?}", err);
    ///     }
    ///
    ///     Ok(())
    /// }
    /// ```
    #[inline]
    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        self.inner.take_error()
    }

    /// Consume this [`UdpSocket`] into a [`UdpFramed`] using the given `C` codec.
    pub fn into_framed<C>(self, codec: C) -> UdpFramed<C> {
        UdpFramed::new(self.inner, codec)
    }
}

fn bind_socket_internal(socket: rama_net::socket::core::Socket) -> Result<UdpSocket, BoxError> {
    let socket = std::net::UdpSocket::from(socket);
    socket
        .set_nonblocking(true)
        .context("set socket as non-blocking")?;
    Ok(UdpSocket {
        inner: TokioUdpSocket::from_std(socket)?,
    })
}

#[cfg(any(windows, unix))]
impl TryFrom<rama_net::socket::core::Socket> for UdpSocket {
    type Error = std::io::Error;

    #[inline]
    fn try_from(value: rama_net::socket::core::Socket) -> Result<Self, Self::Error> {
        let socket = std::net::UdpSocket::from(value);
        socket.try_into()
    }
}

impl TryFrom<std::net::UdpSocket> for UdpSocket {
    type Error = io::Error;

    /// Consumes stream, returning the tokio I/O object.
    ///
    /// This is equivalent to
    /// [`UdpSocket::from_std(stream)`](UdpSocket::from_std).
    #[inline]
    fn try_from(stream: std::net::UdpSocket) -> Result<Self, Self::Error> {
        Self::from_std(stream)
    }
}

impl TryFrom<UdpSocket> for std::net::UdpSocket {
    type Error = io::Error;

    /// Consumes stream, returning it as a [`std::net::UdpSocket`].
    ///
    /// This is equivalent to [`UdpSocket::into_std`].
    #[inline]
    fn try_from(stream: UdpSocket) -> Result<Self, Self::Error> {
        stream.into_std()
    }
}

impl From<TokioUdpSocket> for UdpSocket {
    fn from(value: TokioUdpSocket) -> Self {
        Self { inner: value }
    }
}

impl From<UdpSocket> for TokioUdpSocket {
    fn from(value: UdpSocket) -> Self {
        value.inner
    }
}

#[cfg(unix)]
mod sys {
    use super::UdpSocket;
    use std::os::unix::prelude::*;

    impl AsRawFd for UdpSocket {
        #[inline]
        fn as_raw_fd(&self) -> RawFd {
            self.inner.as_raw_fd()
        }
    }

    impl AsFd for UdpSocket {
        #[inline]
        fn as_fd(&self) -> BorrowedFd<'_> {
            self.inner.as_fd()
        }
    }
}

#[cfg(windows)]
mod sys {
    use super::UdpSocket;
    use std::os::windows::prelude::*;

    impl AsRawSocket for UdpSocket {
        #[inline]
        fn as_raw_socket(&self) -> RawSocket {
            self.inner.as_raw_socket()
        }
    }

    impl AsSocket for UdpSocket {
        #[inline]
        fn as_socket(&self) -> BorrowedSocket<'_> {
            self.inner.as_socket()
        }
    }
}
