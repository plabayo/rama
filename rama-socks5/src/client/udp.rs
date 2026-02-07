use rama_core::bytes::{BufMut, BytesMut};
use rama_core::error::{BoxError, ErrorContext as _, ErrorExt as _};
use rama_core::futures::Sink;
use rama_core::futures::Stream;
use rama_core::stream::codec::{Decoder, Encoder};
use rama_core::telemetry::tracing;
use rama_net::address::HostWithPort;
use rama_net::{address::SocketAddress, socket::Interface};
use rama_udp::{UdpSocket, bind_udp};
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::{fmt, io, net::SocketAddr};
use tokio::io::ReadBuf;

use crate::proto::{Command, ProtocolVersion, ReplyKind, client::Request, server, udp::UdpHeader};

use super::core::HandshakeError;

/// Udp Associate binder ready to create a
/// [`UdpSocketRelay`] ready to proxy udp packets via the socks5
/// server
pub struct UdpSocketRelayBinder<S> {
    stream: S,
}

impl<S: rama_core::stream::Stream + Unpin> UdpSocketRelayBinder<S> {
    pub(crate) fn new(stream: S) -> Self {
        Self { stream }
    }

    /// Bind the relay as an Udp socket on the given interface,
    /// and complete the association handshake with as goal
    /// to have a relay proxy udp connection established at the end
    /// of this bind fn call.
    pub async fn bind(
        mut self,
        interface: impl TryInto<Interface, Error: Into<BoxError>>,
    ) -> Result<UdpSocketRelay<S>, HandshakeError> {
        let socket = bind_udp(interface).await.map_err(|err| {
            HandshakeError::other(err).with_context("bind udp socket ready for sending")
        })?;

        let socket_addr = socket.local_addr().map_err(|err| {
            HandshakeError::other(err).with_context("get local address from udp sender socker")
        })?;

        let request = Request {
            version: ProtocolVersion::Socks5,
            command: Command::UdpAssociate,
            destination: socket_addr.into(),
        };

        request.write_to(&mut self.stream).await.map_err(|err| {
            HandshakeError::io(err).with_context("write client request: UDP Associate")
        })?;

        tracing::trace!(
            network.local.address = %socket_addr.ip(),
            network.local.port = %socket_addr.port(),
            "socks5 client: udp associate handshake initiated"
        );

        let server_reply = server::Reply::read_from(&mut self.stream)
            .await
            .map_err(|err| HandshakeError::protocol(err).with_context("read server reply"))?;
        if server_reply.reply != ReplyKind::Succeeded {
            return Err(HandshakeError::reply_kind(server_reply.reply)
                .with_context("server responded with non-success reply"));
        }

        let HostWithPort { host, port } = server_reply.bind_address;
        let bind_address: SocketAddress = match host {
            rama_net::address::Host::Name(_) => {
                return Err(
                    HandshakeError::reply_kind(ReplyKind::AddressTypeNotSupported).with_context(
                        "server responded with named address: incompatible for udp bind",
                    ),
                );
            }
            rama_net::address::Host::Address(ip_addr) => (ip_addr, port).into(),
        };

        socket
            .connect(bind_address.into_std())
            .await
            .map_err(|err| {
                HandshakeError::other(err).with_context("connect to socks5 udp association socket")
            })?;

        tracing::trace!(
            network.local.address = %socket_addr.ip(),
            network.local.port = %socket_addr.port(),
            "socks5 client: socks5 server ready to bind at {bind_address} for udp purposes",
        );

        Ok(UdpSocketRelay {
            stream: self.stream,
            socket,
            write_buffer: BytesMut::with_capacity(1024),
        })
    }
}

/// [`UdpSocketRelay`] ready to relay udp packets.
///
/// This relay is not designed to be shared,
/// as such it cannot be cloned and requires exclusive access.
pub struct UdpSocketRelay<S> {
    // just here to keep the relay open
    stream: S,

    socket: UdpSocket,

    write_buffer: BytesMut,
}

impl<S: fmt::Debug> fmt::Debug for UdpSocketRelay<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpSocketRelay")
            .field("stream", &self.stream)
            .field("socket", &self.socket)
            .field("write_buffer", &self.write_buffer)
            .finish()
    }
}

impl<S: rama_core::stream::Stream + Unpin> UdpSocketRelay<S> {
    /// Returns the local address that this socket is bound to.
    #[inline]
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Returns the address of the (socks5) server connected to.
    #[inline]
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.socket.peer_addr()
    }

    /// Sends data relayed via the socks5 udp associate proxy.
    /// On success, returns the number of bytes written.
    pub async fn send_to<A: TryInto<SocketAddress, Error: Into<BoxError>>>(
        &mut self,
        b: &[u8],
        addr: A,
    ) -> Result<usize, BoxError> {
        let socket_addr: SocketAddress = addr.try_into().into_box_error()?;
        let header = UdpHeader {
            fragment_number: 0,
            destination: socket_addr.into(),
        };

        self.write_buffer.truncate(0);

        header.write_to_buf(&mut self.write_buffer);
        self.write_buffer.extend_from_slice(b);

        Ok(self.socket.send(&self.write_buffer[..]).await?)
    }

    /// Same as [`Self::send_to`] but polled.
    pub fn poll_send_to<A: TryInto<SocketAddress, Error: Into<BoxError>>>(
        &mut self,
        cx: &mut Context<'_>,
        b: &[u8],
        addr: A,
    ) -> Poll<Result<usize, BoxError>> {
        let socket_addr: SocketAddress = addr.try_into().into_box_error()?;
        let header = UdpHeader {
            fragment_number: 0,
            destination: socket_addr.into(),
        };

        self.write_buffer.truncate(0);

        header.write_to_buf(&mut self.write_buffer);
        self.write_buffer.extend_from_slice(b);

        self.socket
            .poll_send(cx, &self.write_buffer[..])
            .map_err(Into::into)
            .map_ok(|n| n - header.serialized_len() + 1)
    }

    /// Receives a single datagram message from the socks5 udp associate proxy.
    /// On success, returns the number of bytes read and the origin.
    ///
    /// The function must be called with valid byte array `buf` of sufficient
    /// size to hold the message bytes. If a message is too long to fit in the
    /// supplied buffer, excess bytes may be discarded.
    pub async fn recv_from(&mut self, buf: &mut [u8]) -> Result<(usize, SocketAddress), BoxError> {
        let n = self.socket.recv(buf).await?;
        let header = UdpHeader::read_from(&mut &buf[..n]).await?;

        let (header_offset, from) = validate_udp_header(header)?;

        buf.copy_within(header_offset.., 0);
        Ok((n - header_offset, from))
    }

    /// Same as [`Self::recv_from`] but polled.
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
    /// * `Poll::Ready(Ok(addr))` reads data from `addr` into `ReadBuf` if the socket is ready
    /// * `Poll::Ready(Err(e))` if an error is encountered.
    ///
    /// # Errors
    ///
    /// This function may encounter any standard I/O error except `WouldBlock`.
    pub fn poll_recv_from(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<SocketAddress, BoxError>> {
        if let Err(err) = ready!(self.socket.poll_recv(cx, buf)) {
            return Poll::Ready(Err(err.into()));
        }

        let header = UdpHeader::read_from_sync(&mut buf.filled())?;
        let (header_offset, from) = validate_udp_header(header)?;

        let filled = buf.filled_mut();
        let len = filled.len();
        assert!(len > header_offset);
        filled.copy_within(header_offset.., 0);
        buf.set_filled(len - header_offset);

        Poll::Ready(Ok(from))
    }

    /// Consume this [`UdpSocketRelay`] into a [`UdpFramedRelay`] using the given `C` codec.
    pub fn into_framed<C>(self, codec: C) -> UdpFramedRelay<C, S> {
        UdpFramedRelay::new(self, codec)
    }
}

fn validate_udp_header(header: UdpHeader) -> Result<(usize, SocketAddress), BoxError> {
    if header.fragment_number != 0 {
        return Err(
            BoxError::from("UdpSocketRelay: fragment number != 0 is not supported")
                .context_field("fragment_number", header.fragment_number),
        );
    }

    let header_offset = header.serialized_len() - 1;

    let HostWithPort { host, port } = header.destination;
    let from: SocketAddress = match host {
        rama_net::address::Host::Name(domain) => {
            return Err(BoxError::from(
                "server responded with named address: incompatible for udp bind",
            )
            .context_field("domain", domain));
        }
        rama_net::address::Host::Address(ip_addr) => (ip_addr, port).into(),
    };

    Ok((header_offset, from))
}

impl<S: Send + Sync + 'static> rama_net::stream::Socket for UdpSocketRelay<S> {
    fn local_addr(&self) -> io::Result<SocketAddress> {
        self.socket.local_addr().map(Into::into)
    }

    fn peer_addr(&self) -> io::Result<SocketAddress> {
        self.socket.peer_addr().map(Into::into)
    }
}

/// A unified [`Stream`] and [`Sink`] interface to an underlying [`UdpSocketRelay`], using
/// the [`Encoder`] and [`Decoder`] traits to encode and decode frames.
///
/// Raw UDP sockets work with datagrams, but higher-level code usually wants to
/// batch these into meaningful chunks, called "frames". This method layers
/// framing on top of this socket by using the `Encoder` and `Decoder` traits to
/// handle encoding and decoding of messages frames. Note that the incoming and
/// outgoing frame types may be distinct.
///
/// This function returns a *single* object that is both [`Stream`] and [`Sink`];
/// grouping this into a single object is often useful for layering things which
/// require both read and write access to the underlying object.
///
/// If you want to work more directly with the streams and sink, consider
/// calling [`split`] on the `UdpFramed` returned by this method, which will break
/// them into separate objects, allowing them to interact more easily.
///
/// [`Stream`]: https://docs.rs/futures/latest/futures/stream/trait.Stream.html
/// [`Sink`]: https://docs.rs/futures/latest/futures/prelude/trait.Sink.html
/// [`split`]: https://docs.rs/futures/latest/futures/stream/trait.StreamExt.html#method.split
#[must_use = "sinks do nothing unless polled"]
pub struct UdpFramedRelay<C, S> {
    relay_socket: UdpSocketRelay<S>,
    codec: C,
    rd: BytesMut,
    wr: BytesMut,
    out_addr: SocketAddress,
    flushed: bool,
    current_addr: Option<SocketAddress>,
}

impl<C, S: rama_core::stream::Stream + Unpin> UdpFramedRelay<C, S> {
    /// Returns the local address that this relay's underlying [`UdpSocket`] is bound to.
    #[inline]
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.relay_socket.local_addr()
    }

    /// Returns the address of the (socks5) server's [`UdpSocket`] connected to.
    #[inline]
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.relay_socket.peer_addr()
    }
}

impl<C: fmt::Debug, S: fmt::Debug> fmt::Debug for UdpFramedRelay<C, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpFramedRelay")
            .field("relay_socket", &self.relay_socket)
            .field("codec", &self.relay_socket)
            .field("rd", &self.rd)
            .field("wr", &self.wr)
            .field("out_addr", &self.out_addr)
            .field("flushed", &self.flushed)
            .field("current_addr", &self.current_addr)
            .finish()
    }
}

impl<C: Send + Sync + 'static, S: Send + Sync + 'static> rama_net::stream::Socket
    for UdpFramedRelay<C, S>
{
    fn local_addr(&self) -> io::Result<SocketAddress> {
        self.relay_socket.local_addr()
    }

    fn peer_addr(&self) -> io::Result<SocketAddress> {
        self.relay_socket.peer_addr()
    }
}

const INITIAL_RD_CAPACITY: usize = 64 * 1024;
const INITIAL_WR_CAPACITY: usize = 8 * 1024;

impl<C, S: Unpin> Unpin for UdpFramedRelay<C, S> {}

impl<C, S> Stream for UdpFramedRelay<C, S>
where
    C: Decoder<Error: Into<BoxError>>,
    S: rama_core::stream::Stream + Unpin,
{
    type Item = Result<(C::Item, SocketAddress), BoxError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let pin = self.get_mut();

        pin.rd.reserve(INITIAL_RD_CAPACITY);

        loop {
            // Are there still bytes left in the read buffer to decode?
            if let Some(current_addr) = pin.current_addr {
                if let Some(frame) = pin.codec.decode_eof(&mut pin.rd).into_box_error()? {
                    return Poll::Ready(Some(Ok((frame, current_addr))));
                }

                // if this line has been reached then decode has returned `None`.
                pin.current_addr = None;
                pin.rd.clear();
            }

            // We're out of data. Try and fetch more data to decode
            let addr = {
                // Safety: `chunk_mut()` returns a `&mut UninitSlice`, and `UninitSlice` is a
                // transparent wrapper around `[MaybeUninit<u8>]`.
                let buf = unsafe { pin.rd.chunk_mut().as_uninit_slice_mut() };
                let mut read = ReadBuf::uninit(buf);
                let ptr = read.filled().as_ptr();
                let res = ready!(pin.relay_socket.poll_recv_from(cx, &mut read));

                assert_eq!(ptr, read.filled().as_ptr());
                let addr = res?;

                let filled = read.filled().len();
                // Safety: This is guaranteed to be the number of initialized (and read) bytes due
                // to the invariants provided by `ReadBuf::filled`.
                unsafe { pin.rd.advance_mut(filled) };

                addr
            };

            pin.current_addr = Some(addr);
        }
    }
}

impl<I, C, S> Sink<(I, SocketAddr)> for UdpFramedRelay<C, S>
where
    C: Encoder<I, Error: Into<BoxError>>,
    S: rama_core::stream::Stream + Unpin,
{
    type Error = BoxError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if !self.flushed {
            match self.poll_flush(cx)? {
                Poll::Ready(()) => {}
                Poll::Pending => return Poll::Pending,
            }
        }

        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: (I, SocketAddr)) -> Result<(), Self::Error> {
        let (frame, out_addr) = item;

        let pin = self.get_mut();

        pin.codec.encode(frame, &mut pin.wr).into_box_error()?;
        pin.out_addr = out_addr.into();
        pin.flushed = false;

        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.flushed {
            return Poll::Ready(Ok(()));
        }

        let Self {
            ref mut relay_socket,
            ref mut out_addr,
            ref mut wr,
            ..
        } = *self;

        let n = ready!(relay_socket.poll_send_to(cx, wr, *out_addr))?;

        let wr_n = self.wr.len();
        let wrote_all = n == wr_n;

        self.wr.clear();
        self.flushed = true;

        let res = if wrote_all {
            Ok(())
        } else {
            tracing::debug!(
                "failed to write entire datagram to socket: len = {n}; wr len = {wr_n}"
            );
            Err(io::Error::other("failed to write entire datagram to socket").into())
        };

        Poll::Ready(res)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.poll_flush(cx))?;
        Poll::Ready(Ok(()))
    }
}

impl<C, S> UdpFramedRelay<C, S> {
    fn new(relay_socket: UdpSocketRelay<S>, codec: C) -> Self {
        Self {
            relay_socket,
            codec,
            out_addr: SocketAddress::default_ipv4(0),
            rd: BytesMut::with_capacity(INITIAL_RD_CAPACITY),
            wr: BytesMut::with_capacity(INITIAL_WR_CAPACITY),
            flushed: true,
            current_addr: None,
        }
    }

    /// Returns a reference to the underlying codec wrapped by
    /// `UdpFramedRelay`.
    ///
    /// Note that care should be taken to not tamper with the underlying codec
    /// as it may corrupt the stream of frames otherwise being worked with.
    pub fn codec(&self) -> &C {
        &self.codec
    }

    /// Returns a mutable reference to the underlying codec wrapped by
    /// `UdpFramedRelay`.
    ///
    /// Note that care should be taken to not tamper with the underlying codec
    /// as it may corrupt the stream of frames otherwise being worked with.
    pub fn codec_mut(&mut self) -> &mut C {
        &mut self.codec
    }
}
