//! [`Stream`] trait and related utilities.

use tokio::io::{AsyncRead, AsyncWrite};

pub mod matcher;

pub mod layer;
pub mod service;

mod read;
#[doc(inline)]
pub use read::{ChainReader, HeapReader, StackReader};

mod peek;
#[doc(inline)]
pub use peek::PeekStream;

pub mod rewind;

/// A stream is a type that implements `AsyncRead`, `AsyncWrite` and `Send`.
/// This is specific to Rama and is directly linked to the supertraits of `Tokio`.
pub trait Stream: AsyncRead + AsyncWrite + Send + 'static {}

impl<T> Stream for T where T: AsyncRead + AsyncWrite + Send + 'static {}

mod socket;
#[doc(inline)]
pub use socket::{ClientSocketInfo, Socket, SocketInfo};

pub mod dep {
    //! Dependencies for rama stream modules.
    //!
    //! Exported for your convenience.

    pub mod ipnet {
        //! Re-export of the [`ipnet`] crate.
        //!
        //! Types for IPv4 and IPv6 network addresses.
        //!
        //! [`ipnet`]: https://docs.rs/ipnet

        #[doc(inline)]
        pub use ipnet::*;
    }
}
