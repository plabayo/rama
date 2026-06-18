#[cfg(feature = "http")]
mod h2;

#[cfg(feature = "http")]
#[cfg_attr(docsrs, doc(cfg(feature = "http")))]
pub use h2::{AkamaiH2, AkamaiH2ComputeError};
