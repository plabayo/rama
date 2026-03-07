use tokio::io::{AsyncRead, AsyncWrite};

mod read;
#[doc(inline)]
pub use read::{ChainReader, HeapReader, StackReader};

mod prefix;
#[doc(inline)]
pub use prefix::PrefixedIo;

pub mod rewind;

mod bridge;
pub use bridge::BridgeIo;

/// A generic transport of bytes is a type that implements `AsyncRead`, `AsyncWrite` and `Send`.
/// This is specific to Rama and is directly linked to the supertraits of `Tokio`.
pub trait Io: AsyncRead + AsyncWrite + Send + 'static {}

impl<T> Io for T where T: AsyncRead + AsyncWrite + Send + 'static {}
