//! Frame-level duplex over a *connected* [`UdpSocket`].
//!
//! [`tokio_util::udp::UdpFramed`] (which rama-udp re-exports) is designed
//! for *unconnected* UDP sockets: it carries a `SocketAddr` alongside every
//! frame on both the read and write side so the caller can specify the peer
//! per datagram. When the socket has been [`UdpSocket::connect`]-ed to a
//! single peer, that address is redundant — every recv comes from the
//! connected peer and every send goes to it.
//!
//! [`ConnectedUdpFramed`] is the dedicated wrapper for this case. It exposes
//! `Stream<Item = Result<C::Item, C::Error>>` and `Sink<I, Error = C::Error>`
//! without the address baggage, so two such endpoints (or a connected UDP
//! endpoint and any other byte-frame stream like
//! `tokio_util::codec::Framed<TcpStream, LengthDelimitedCodec>`) bridge
//! cleanly through [`rama_core::stream::StreamForwardService`].
//!
//! The socket **must** be connected before construction. This is a runtime
//! requirement (matching `tokio_util::udp::UdpFramed`'s "you must `bind`"
//! contract); using an unconnected socket here will cause `send` to fail
//! with `ENOTCONN` on every datagram.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::{BufMut, BytesMut};
use futures::{Sink, Stream};
use tokio::net::UdpSocket;
use tokio_util::codec::{Decoder, Encoder};

const INITIAL_RD_CAPACITY: usize = 64 * 1024;
const INITIAL_WR_CAPACITY: usize = 8 * 1024;

/// A unified [`Stream`] and [`Sink`] of frames over a connected [`UdpSocket`].
///
/// Like [`tokio_util::udp::UdpFramed`], but for sockets that have already
/// been [`UdpSocket::connect`]-ed to a single peer. The peer address is
/// implicit on every send and recv, so the frame type is just the codec's
/// `Item` / sink input — no `SocketAddr` tuple.
///
/// # Example
///
/// ```no_run
/// use std::net::Ipv4Addr;
/// use rama_udp::{ConnectedUdpFramed, bind_udp_socket_with_connect_default_dns};
/// use tokio_util::codec::BytesCodec;
///
/// # async fn _example() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
/// let socket = bind_udp_socket_with_connect_default_dns(
///     (Ipv4Addr::LOCALHOST, 51820),
///     None,
/// ).await?;
/// let framed = ConnectedUdpFramed::new(socket, BytesCodec::new());
/// // `framed` is now Stream<Item = io::Result<BytesMut>> + Sink<Bytes, Error = io::Error>.
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct ConnectedUdpFramed<C> {
    socket: UdpSocket,
    codec: C,
    rd: BytesMut,
    wr: BytesMut,
    flushed: bool,
    is_readable: bool,
}

impl<C> ConnectedUdpFramed<C> {
    /// Create a new [`ConnectedUdpFramed`] wrapping a connected
    /// [`UdpSocket`] and a codec.
    ///
    /// **The socket must already be connected**, e.g. via
    /// [`UdpSocket::connect`] or [`bind_udp_socket_with_connect`].
    ///
    /// [`bind_udp_socket_with_connect`]: crate::bind_udp_socket_with_connect
    pub fn new(socket: UdpSocket, codec: C) -> Self {
        Self {
            socket,
            codec,
            rd: BytesMut::with_capacity(INITIAL_RD_CAPACITY),
            wr: BytesMut::with_capacity(INITIAL_WR_CAPACITY),
            flushed: true,
            is_readable: false,
        }
    }

    /// A reference to the underlying socket.
    #[must_use]
    pub fn get_ref(&self) -> &UdpSocket {
        &self.socket
    }

    /// A mutable reference to the underlying socket.
    pub fn get_mut(&mut self) -> &mut UdpSocket {
        &mut self.socket
    }

    /// A reference to the codec.
    #[must_use]
    pub fn codec(&self) -> &C {
        &self.codec
    }

    /// A mutable reference to the codec.
    pub fn codec_mut(&mut self) -> &mut C {
        &mut self.codec
    }

    /// Consume the framed wrapper and return the underlying socket and codec.
    pub fn into_parts(self) -> (UdpSocket, C) {
        (self.socket, self.codec)
    }
}

impl<C> Stream for ConnectedUdpFramed<C>
where
    C: Decoder + Unpin,
{
    type Item = Result<C::Item, C::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            // Drain any pending frame from the read buffer first.
            if this.is_readable {
                if let Some(frame) = this.codec.decode_eof(&mut this.rd)? {
                    return Poll::Ready(Some(Ok(frame)));
                }
                // No more frames in this datagram — reset and recv another.
                this.is_readable = false;
                this.rd.clear();
            }

            // Make sure the read buffer has space for one MTU-ish datagram.
            // UDP datagrams above 64 KiB are unusual; reuse the initial
            // capacity as the per-datagram window.
            this.rd.reserve(INITIAL_RD_CAPACITY);

            // Bytes between len() and capacity() are uninit but we only
            // expose [0..filled.len()] back to the codec. This mirrors
            // tokio_util::udp::UdpFramed's approach.
            let n = {
                let dst = unsafe {
                    // SAFETY: chunk_mut points at uninit spare capacity we own.
                    let chunk = this.rd.chunk_mut();
                    std::slice::from_raw_parts_mut(chunk.as_mut_ptr().cast::<u8>(), chunk.len())
                };
                let mut read_buf = tokio::io::ReadBuf::new(dst);
                ready!(this.socket.poll_recv(cx, &mut read_buf))?;
                read_buf.filled().len()
            };
            // SAFETY: poll_recv filled `n` bytes into the spare capacity.
            unsafe { this.rd.set_len(this.rd.len() + n) };
            this.is_readable = true;
        }
    }
}

impl<I, C> Sink<I> for ConnectedUdpFramed<C>
where
    C: Encoder<I> + Unpin,
{
    type Error = C::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.flushed {
            return Poll::Ready(Ok(()));
        }
        self.poll_flush(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: I) -> Result<(), Self::Error> {
        let this = self.get_mut();
        this.codec.encode(item, &mut this.wr)?;
        this.flushed = false;
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        if this.flushed {
            return Poll::Ready(Ok(()));
        }
        let n = ready!(this.socket.poll_send(cx, &this.wr))?;
        let wrote_all = n == this.wr.len();
        this.wr.clear();
        this.flushed = true;
        // UDP is all-or-nothing per datagram; a short send is an error.
        if wrote_all {
            Poll::Ready(Ok(()))
        } else {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "udp socket sent short datagram",
            )
            .into()))
        }
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // UDP has no close handshake; flushing any pending write is enough.
        self.poll_flush(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use futures::{SinkExt, StreamExt};
    use std::time::Duration;
    use tokio_util::codec::BytesCodec;

    use crate::bind_udp_with_address;
    use rama_net::address::SocketAddress;

    async fn connected_pair() -> (
        ConnectedUdpFramed<BytesCodec>,
        ConnectedUdpFramed<BytesCodec>,
    ) {
        let a = bind_udp_with_address(SocketAddress::local_ipv4(0))
            .await
            .unwrap();
        let b = bind_udp_with_address(SocketAddress::local_ipv4(0))
            .await
            .unwrap();
        let a_addr = a.local_addr().unwrap();
        let b_addr = b.local_addr().unwrap();
        a.connect(b_addr).await.unwrap();
        b.connect(a_addr).await.unwrap();
        (
            ConnectedUdpFramed::new(a, BytesCodec::new()),
            ConnectedUdpFramed::new(b, BytesCodec::new()),
        )
    }

    #[tokio::test]
    async fn send_receive_roundtrip() {
        let (mut a, mut b) = connected_pair().await;

        a.send(Bytes::from_static(b"hello")).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(1), b.next())
            .await
            .expect("recv timed out")
            .unwrap()
            .unwrap();
        assert_eq!(&got[..], b"hello");

        b.send(Bytes::from_static(b"world")).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(1), a.next())
            .await
            .expect("recv timed out")
            .unwrap()
            .unwrap();
        assert_eq!(&got[..], b"world");
    }

    #[tokio::test]
    async fn preserves_datagram_boundaries() {
        let (mut a, mut b) = connected_pair().await;

        a.send(Bytes::from_static(b"one")).await.unwrap();
        a.send(Bytes::from_static(b"two")).await.unwrap();
        a.send(Bytes::from_static(b"three")).await.unwrap();

        let r1 = tokio::time::timeout(Duration::from_secs(1), b.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let r2 = tokio::time::timeout(Duration::from_secs(1), b.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let r3 = tokio::time::timeout(Duration::from_secs(1), b.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(&r1[..], b"one");
        assert_eq!(&r2[..], b"two");
        assert_eq!(&r3[..], b"three");
    }
}
