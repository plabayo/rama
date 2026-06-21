//! fingerprint implementations for the network surface

#[cfg(feature = "tls")]
mod ja4;

#[cfg(feature = "tls")]
#[cfg_attr(docsrs, doc(cfg(feature = "tls")))]
pub use ja4::{Ja4, Ja4ComputeError};

#[cfg(feature = "tls")]
mod peet;

#[cfg(feature = "tls")]
#[cfg_attr(docsrs, doc(cfg(feature = "tls")))]
pub use peet::{PeetComputeError, PeetPrint};

#[cfg(feature = "tls")]
mod ja3;

#[cfg(feature = "tls")]
#[cfg_attr(docsrs, doc(cfg(feature = "tls")))]
pub use ja3::{Ja3, Ja3ComputeError};
