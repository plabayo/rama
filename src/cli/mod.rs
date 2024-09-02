//! rama cli utilities

pub mod args;
pub mod service;

mod forward;
#[doc(inline)]
pub use forward::ForwardKind;

#[cfg(any(feature = "boring", feature = "rustls"))]
pub mod tls;
