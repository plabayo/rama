//! Datagrams read ahead by an inspection, replayed before later input.

use std::{
    collections::VecDeque,
    fmt,
    io::{self, IoSliceMut},
    task::{Context, Poll},
};

use rama_core::{
    bytes::Bytes,
    extensions::{Extensions, ExtensionsRef},
    io::BridgeIo,
};
use rama_net::{address::SocketAddress, stream::Socket};

use crate::{DatagramCapabilities, DatagramError, DatagramMetadata, DatagramSocket};

/// A datagram read before its socket was handed on, kept with its receive metadata.
#[derive(Debug, Clone)]
pub struct RetainedDatagram {
    pub payload: Bytes,
    pub metadata: DatagramMetadata,
}

/// A [`DatagramSocket`] that first yields the datagrams an inspection read ahead, in order and
/// with their boundaries and metadata, and only then what `inner` receives.
///
/// Sending goes straight to `inner`.
pub struct PrefixedDatagramSocket<S> {
    inner: S,
    prefix: VecDeque<RetainedDatagram>,
}

impl<S> PrefixedDatagramSocket<S> {
    /// Replay `prefix` before anything `inner` receives later.
    pub fn new(inner: S, prefix: impl IntoIterator<Item = RetainedDatagram>) -> Self {
        Self {
            inner,
            prefix: prefix.into_iter().collect(),
        }
    }

    /// The datagrams not yet received from this socket.
    #[must_use]
    pub fn retained(&self) -> &VecDeque<RetainedDatagram> {
        &self.prefix
    }

    /// The underlying socket.
    pub fn get_ref(&self) -> &S {
        &self.inner
    }
}

impl<S: fmt::Debug> fmt::Debug for PrefixedDatagramSocket<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrefixedDatagramSocket")
            .field("inner", &self.inner)
            .field("retained", &self.prefix.len())
            .finish()
    }
}

impl<S: ExtensionsRef> ExtensionsRef for PrefixedDatagramSocket<S> {
    fn extensions(&self) -> &Extensions {
        self.inner.extensions()
    }
}

impl<S: Socket> Socket for PrefixedDatagramSocket<S> {
    fn local_addr(&self) -> io::Result<SocketAddress> {
        self.inner.local_addr()
    }

    fn peer_addr(&self) -> io::Result<SocketAddress> {
        self.inner.peer_addr()
    }
}

impl<S: DatagramSocket> DatagramSocket for PrefixedDatagramSocket<S> {
    type Sender = S::Sender;

    fn create_sender(&self) -> Self::Sender {
        self.inner.create_sender()
    }

    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
        buffers: &mut [IoSliceMut<'_>],
        metadata: &mut [DatagramMetadata],
    ) -> Poll<Result<usize, DatagramError>> {
        if buffers.len() != metadata.len() {
            return Poll::Ready(Err(DatagramError::ReceiveSlotMismatch {
                buffers: buffers.len(),
                metadata: metadata.len(),
            }));
        }
        let Some(first) = self.prefix.front() else {
            return self.inner.poll_recv(cx, buffers, metadata);
        };
        let Some(buffer) = buffers.first_mut() else {
            return Poll::Ready(Err(DatagramError::EmptyReceiveBatch));
        };
        // A retained datagram is never cut: it stays queued for a large enough buffer.
        if first.payload.len() > buffer.len() {
            return Poll::Ready(Err(DatagramError::PayloadTooLarge {
                len: first.payload.len(),
                max: buffer.len(),
            }));
        }
        buffer[..first.payload.len()].copy_from_slice(&first.payload);
        metadata[0] = first.metadata;
        let _replayed = self.prefix.pop_front();
        Poll::Ready(Ok(1))
    }

    fn capabilities(&self) -> DatagramCapabilities {
        let mut capabilities = self.inner.capabilities();
        capabilities.min_receive_buffer_size = capabilities.min_receive_buffer_size.max(
            self.prefix
                .iter()
                .map(|datagram| datagram.payload.len())
                .max()
                .unwrap_or(0),
        );
        capabilities
    }
}

/// An input whose ingress datagrams an inspection may read ahead: a [`DatagramSocket`] itself,
/// or the ingress side of a [`BridgeIo`] whose egress was already prepared.
pub trait DatagramPeekInput: Send + 'static {
    /// The socket an inspection reads from.
    type Socket: DatagramSocket;

    /// This input with its peeked socket replaced, usually by a [`PrefixedDatagramSocket`].
    type Mapped<Peeked: DatagramSocket>: Send + 'static;

    /// The socket an inspection reads from.
    fn peek_socket_mut(&mut self) -> &mut Self::Socket;

    /// Rebuild this input around `map`'s result for its peeked socket.
    fn map_peek_socket<Peeked, F>(self, map: F) -> Self::Mapped<Peeked>
    where
        Peeked: DatagramSocket,
        F: FnOnce(Self::Socket) -> Peeked;
}

impl<S: DatagramSocket> DatagramPeekInput for S {
    type Socket = S;
    type Mapped<Peeked: DatagramSocket> = Peeked;

    fn peek_socket_mut(&mut self) -> &mut Self::Socket {
        self
    }

    fn map_peek_socket<Peeked, F>(self, map: F) -> Self::Mapped<Peeked>
    where
        Peeked: DatagramSocket,
        F: FnOnce(Self::Socket) -> Peeked,
    {
        map(self)
    }
}

impl<Ingress, Egress> DatagramPeekInput for BridgeIo<Ingress, Egress>
where
    Ingress: DatagramSocket,
    Egress: Send + 'static,
{
    type Socket = Ingress;
    type Mapped<Peeked: DatagramSocket> = BridgeIo<Peeked, Egress>;

    fn peek_socket_mut(&mut self) -> &mut Self::Socket {
        let Self(ingress, _egress) = self;
        ingress
    }

    fn map_peek_socket<Peeked, F>(self, map: F) -> Self::Mapped<Peeked>
    where
        Peeked: DatagramSocket,
        F: FnOnce(Self::Socket) -> Peeked,
    {
        let Self(ingress, egress) = self;
        BridgeIo(map(ingress), egress)
    }
}

#[cfg(test)]
mod tests;
