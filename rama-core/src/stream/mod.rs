use tokio::io::{AsyncRead, AsyncWrite};

mod read;
#[doc(inline)]
pub use read::{ChainReader, HeapReader, StackReader};

mod peek;
#[doc(inline)]
pub use peek::PeekStream;

pub mod rewind;

pub mod json;

/// A stream is a type that implements `AsyncRead`, `AsyncWrite` and `Send`.
/// This is specific to Rama and is directly linked to the supertraits of `Tokio`.
pub trait Stream: AsyncRead + AsyncWrite + Send + 'static {}

impl<T> Stream for T where T: AsyncRead + AsyncWrite + Send + 'static {}

pub mod codec {
    //! Adaptors from `AsyncRead`/`AsyncWrite` to Stream/Sink
    //!
    //! Raw I/O objects work with byte sequences, but higher-level code usually
    //! wants to batch these into meaningful chunks, called "frames".
    //!
    //! Re-export of [`tokio_util::codec`].

    pub use tokio_util::codec::*;
}

pub mod io {
    //! Helpers for IO related tasks.
    //!
    //! Re-export of [`tokio_util::io`].

    pub use tokio_util::io::*;
}
