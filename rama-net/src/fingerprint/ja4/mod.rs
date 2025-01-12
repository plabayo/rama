#[cfg(feature = "http")]
mod http;

#[cfg(feature = "http")]
pub use http::{Ja4H, Ja4HComputeError};

#[cfg(feature = "tls")]
mod tls;

#[cfg(feature = "tls")]
pub use tls::{Ja4, Ja4ComputeError};
