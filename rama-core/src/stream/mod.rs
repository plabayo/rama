//! Utilities for [`Stream`]s and [`Sink`](futures::Sink)s.
//!
//! Without the `std` feature this holds the [`Stream`] trait and [`BytesFreeze`];
//! combinators for either mode live in [`crate::futures::stream`]. With `std` it also
//! re-exports [tokio-stream](https://docs.rs/tokio-stream) (its `sync`, `time`,
//! `io-util`, `fs` and `signal` wrappers), the codecs and the bridges built on tokio.

#[doc(inline)]
pub use ::futures::stream::Stream;

mod bytes_freeze;
#[doc(inline)]
pub use bytes_freeze::BytesFreeze;

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
pub mod json;

#[cfg(feature = "std")]
mod forward;
#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
#[doc(inline)]
pub use forward::{BridgeCloseReason, StreamBridge, StreamForwardService};

#[cfg(feature = "std")]
mod paced;
#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
#[doc(inline)]
pub use paced::{CostFn, DatagramCost, ItemCost, PacedSink};

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
pub mod codec {
    //! Adaptors from `AsyncRead`/`AsyncWrite` to Stream/Sink
    //!
    //! Raw I/O objects work with byte sequences, but higher-level code usually
    //! wants to batch these into meaningful chunks, called "frames".
    //!
    //! Re-export of [`tokio_util::codec`].

    pub use tokio_util::codec::*;
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
pub mod io {
    //! Helpers for IO related tasks.
    //!
    //! Re-export of [`tokio_util::io`].

    pub use tokio_util::io::*;
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
#[doc(inline)]
pub use ::tokio_stream::*;
