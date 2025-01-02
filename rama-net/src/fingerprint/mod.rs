//! fingerprint implementations for the network surface

#[cfg(feature = "tls")]
mod ja3;

#[cfg(feature = "tls")]
pub use ja3::{Ja3, Ja3ComputeError};
