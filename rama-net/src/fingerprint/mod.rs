//! fingerprint implementations for the network surface

#[cfg(any(feature = "tls", feature = "http"))]
mod ja4;

#[cfg(feature = "http")]
pub use ja4::{Ja4H, Ja4HComputeError};

#[cfg(feature = "tls")]
pub use ja4::{Ja4, Ja4ComputeError};

#[cfg(feature = "tls")]
mod ja3;

#[cfg(feature = "tls")]
pub use ja3::{Ja3, Ja3ComputeError};
