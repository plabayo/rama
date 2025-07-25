#[cfg(feature = "boring")]
#[doc(inline)]
pub use rama_tls_boring as boring;

#[cfg(feature = "rustls")]
#[doc(inline)]
pub use rama_tls_rustls as rustls;

// TODO support everything with boring also
#[cfg(feature = "rustls")]
pub mod acme;
