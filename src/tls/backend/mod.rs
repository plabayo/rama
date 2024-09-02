//! tls implementations shipped with rama

#[cfg(feature = "rustls")]
pub mod rustls;

#[cfg(feature = "boring")]
pub mod boring;

#[cfg(all(feature = "rustls", not(feature = "boring")))]
pub use rustls as std;

#[cfg(feature = "boring")]
pub use boring as std;
