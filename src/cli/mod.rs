//! rama cli utilities

#[cfg(feature = "http")]
pub mod args;

#[cfg(all(feature = "http", feature = "net", feature = "haproxy"))]
pub mod service;

mod forward;
#[doc(inline)]
pub use forward::ForwardKind;
