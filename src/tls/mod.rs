#[cfg(feature = "boring")]
#[doc(inline)]
pub use rama_tls_boring as boring;

#[cfg(feature = "rustls")]
#[doc(inline)]
pub use rama_tls_rustls as rustls;

// TODO heavily extend the functionality in this module
#[cfg(feature = "acme")]
pub mod acme {
    pub use ::rama_tls_acme::*;
}
