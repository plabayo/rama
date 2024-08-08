//! CLI utilities for tls

pub mod rustls;

#[cfg(feature = "boring")]
pub mod boring;

#[cfg(feature = "boring")]
pub use boring::TlsServerCertKeyPair;
#[cfg(not(feature = "boring"))]
pub use tls::TlsServerCertKeyPair;
