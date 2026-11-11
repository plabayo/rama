use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

mod read;
#[doc(inline)]
pub use read::{ChainReader, HeapReader, ReplayReader, StackReader, discard};

mod lossy_utf8;
#[doc(inline)]
pub use lossy_utf8::LossyUtf8Reader;

mod prefix;
#[doc(inline)]
pub use prefix::PrefixedIo;

mod abort;
pub use abort::AbortIo;

mod abortable;
pub use abortable::AbortableIo;

pub mod peek;
pub mod rewind;
pub mod timeout;

#[cfg(test)]
mod test_util;

mod bridge;
pub use bridge::BridgeIo;

mod read_at;
#[doc(inline)]
pub use read_at::{BlockCache, BlockCacheConfig, FileIdentity, ReadAt, ReadAtFiles};

mod read_buf;
#[doc(inline)]
pub use read_buf::poll_read_limited;

mod owned;
#[doc(inline)]
pub use owned::{
    ArrayBuf, AsyncReadOwned, AsyncWriteOwned, BufResult, BufSlot, IoBuf, IoBufMut, SetLen, Slice,
    SplitIo, Uninit,
};

/// A generic transport of bytes is a type that implements `AsyncRead`, `AsyncWrite` and `Send`.
/// This is specific to Rama and is directly linked to the supertraits of `Tokio`.
pub trait Io: AsyncRead + AsyncWrite + Send + 'static {}

impl<T> Io for T where T: AsyncRead + AsyncWrite + Send + 'static {}

/// A higher level trait that can be used by services which
/// wish to peek into I/O, often as part of Deep Protocol Inspections (DPI).
///
/// It is implemented for any [`Io`], returning itself as ingress and
/// reporting no egress. [`BridgeIo`] also implements it, exposing its first
/// element as the ingress and its second element as the egress.
pub trait PeekIoProvider: Send + 'static {
    /// The ingress type that can be peeked.
    type PeekIo: Io;

    /// The egress type that can be peeked, [`NoPeekEgress`] when there is none.
    type PeekEgressIo: Io;

    /// The mapped `Self` type produced as a result of
    /// mapping the `PeekIo` and `PeekEgressIo` types.
    type Mapped<PeekedIo: Io, PeekedEgressIo: Io>: Send + 'static;

    /// Retrieve a mutable reference to the peekable ingress.
    fn peek_io_mut(&mut self) -> &mut Self::PeekIo;

    /// Retrieve mutable references to the peekable ingress and,
    /// if there is one, the peekable egress.
    fn peek_ios_mut(&mut self) -> (&mut Self::PeekIo, Option<&mut Self::PeekEgressIo>);

    /// Once peeking is finished one can reproduce `self`
    /// by mapping the peeked ingress and egress, usually with the
    /// peeked data in-memory as prefix.
    ///
    /// `map_egress` is only called when there is an egress.
    fn map_peek_io<PeekedIo, PeekedEgressIo, F, G>(
        self,
        map: F,
        map_egress: G,
    ) -> Self::Mapped<PeekedIo, PeekedEgressIo>
    where
        PeekedIo: Io,
        PeekedEgressIo: Io,
        F: FnOnce(Self::PeekIo) -> PeekedIo,
        G: FnOnce(Self::PeekEgressIo) -> PeekedEgressIo;
}

impl<T: Io> PeekIoProvider for T {
    type PeekIo = T;
    type PeekEgressIo = NoPeekEgress;
    type Mapped<PeekedIo: Io, PeekedEgressIo: Io> = PeekedIo;

    #[inline(always)]
    fn peek_io_mut(&mut self) -> &mut Self::PeekIo {
        self
    }

    #[inline(always)]
    fn peek_ios_mut(&mut self) -> (&mut Self::PeekIo, Option<&mut Self::PeekEgressIo>) {
        (self, None)
    }

    #[inline(always)]
    fn map_peek_io<PeekedIo, PeekedEgressIo, F, G>(
        self,
        map: F,
        _map_egress: G,
    ) -> Self::Mapped<PeekedIo, PeekedEgressIo>
    where
        PeekedIo: Io,
        PeekedEgressIo: Io,
        F: FnOnce(Self::PeekIo) -> PeekedIo,
        G: FnOnce(Self::PeekEgressIo) -> PeekedEgressIo,
    {
        map(self)
    }
}

/// The egress of a [`PeekIoProvider`] that has none.
///
/// It cannot be constructed.
#[derive(Debug)]
pub enum NoPeekEgress {}

impl AsyncRead for NoPeekEgress {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match *self {}
    }
}

impl AsyncWrite for NoPeekEgress {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match *self {}
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match *self {}
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match *self {}
    }
}
