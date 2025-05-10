use bytes::BytesMut;
use rama_core::error::{BoxError, OpaqueError};
use rama_net::{address::SocketAddress, socket::Interface, stream::Stream};
use rama_udp::UdpSocket;
use std::{fmt, io, net::SocketAddr};

use crate::proto::{Command, ProtocolVersion, ReplyKind, client::Request, server, udp::UdpHeader};

use super::core::HandshakeError;

/// Udp Associate binder ready to create a
/// [`UdpSocketRelay`] ready to proxy udp packets via the socks5
/// server
pub struct UdpSocketRelayBinder<S> {
    stream: S,
}

impl<S: Stream + Unpin> UdpSocketRelayBinder<S> {
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
        let socket = UdpSocket::bind(interface).await.map_err(|err| {
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
            %socket_addr,
            "socks5 client: udp associate handshake initiated"
        );

        let server_reply = server::Reply::read_from(&mut self.stream)
            .await
            .map_err(|err| HandshakeError::protocol(err).with_context("read server reply"))?;
        if server_reply.reply != ReplyKind::Succeeded {
            return Err(HandshakeError::reply_kind(server_reply.reply)
                .with_context("server responded with non-success reply"));
        }

        let (host, port) = server_reply.bind_address.into_parts();
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

        socket.connect(bind_address).await.map_err(|err| {
            HandshakeError::other(err).with_context("connect to socks5 udp association socket")
        })?;

        tracing::trace!(
            %socket_addr,
            %bind_address,
            "socks5 client: socks5 server ready to bind for udp purposes",
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

impl<S> UdpSocketRelay<S> {
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
        let socket_addr: SocketAddress = addr.try_into().map_err(Into::into)?;
        let header = UdpHeader {
            fragment_number: 0,
            destination: socket_addr.into(),
        };

        self.write_buffer.clear();

        header.write_to_buf(&mut self.write_buffer);
        self.write_buffer.extend_from_slice(b);

        Ok(self.socket.send(&self.write_buffer).await?)
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
        if header.fragment_number != 0 {
            return Err(OpaqueError::from_display(
                "UdpSocketRelay: fragment number != 0 is not supported",
            )
            .into_boxed());
        }

        let header_len = header.serialized_len();

        let (host, port) = header.destination.into_parts();
        let from: SocketAddress = match host {
            rama_net::address::Host::Name(_) => {
                return Err(OpaqueError::from_display(
                    "server responded with named address: incompatible for udp bind",
                )
                .into_boxed());
            }
            rama_net::address::Host::Address(ip_addr) => (ip_addr, port).into(),
        };

        buf.copy_within(header_len.., 0);
        Ok((n - header_len, from))
    }
}

impl<S: Send + Sync + 'static> rama_net::stream::Socket for UdpSocketRelay<S> {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.socket.peer_addr()
    }
}
