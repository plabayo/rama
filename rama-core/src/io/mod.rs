use tokio::io::{AsyncRead, AsyncWrite};

mod read;
#[doc(inline)]
pub use read::{ChainReader, HeapReader, StackReader};

mod prefix;
#[doc(inline)]
pub use prefix::PrefixedIo;

pub mod peek;
pub mod rewind;
pub mod timeout;

mod bridge;
pub use bridge::BridgeIo;

/// A generic transport of bytes is a type that implements `AsyncRead`, `AsyncWrite` and `Send`.
/// This is specific to Rama and is directly linked to the supertraits of `Tokio`.
pub trait Io: AsyncRead + AsyncWrite + Send + 'static {}

impl<T> Io for T where T: AsyncRead + AsyncWrite + Send + 'static {}

/// A higher level trait that can be used by services which
/// wish to peek into I/O, often as part of Deep Protocol Inspections (DPI).
///
/// It is implemented for any [`Io`], returning itself.
/// [`BridgeIo`] also implements it, assuming that the first element
/// is the ingress side that is ok to be peeked.
pub trait PeekIoProvider: Send + 'static {
    /// The type that can be peeked.
    type PeekIo: Io;

    /// The mapped `Self` type produced as a result of
    /// mapping the `PeekIo` type.
    type Mapped<PeekedIo: Io>: Send + 'static;

    /// Retrieve a mutable reference to the Peekable type.
    fn peek_io_mut(&mut self) -> &mut Self::PeekIo;

    /// Once peeking is finished one can reproduce `self`
    /// by mapping the Peeked Io type and produce a new type,
    /// usually with the peeked data in-memory as prefix.
    fn map_peek_io<PeekedIo, F>(self, map: F) -> Self::Mapped<PeekedIo>
    where
        PeekedIo: Io,
        F: FnOnce(Self::PeekIo) -> PeekedIo;
}

impl<T: Io> PeekIoProvider for T {
    type PeekIo = T;
    type Mapped<PeekedIo: Io> = PeekedIo;

    #[inline(always)]
    fn peek_io_mut(&mut self) -> &mut Self::PeekIo {
        self
    }

    #[inline(always)]
    fn map_peek_io<PeekedIo, F>(self, map: F) -> Self::Mapped<PeekedIo>
    where
        PeekedIo: Io,
        F: FnOnce(Self::PeekIo) -> PeekedIo,
    {
        map(self)
    }
}
