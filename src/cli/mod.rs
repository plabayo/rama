//! rama cli utilities

#[cfg(feature = "http")]
#[cfg_attr(docsrs, doc(cfg(feature = "http")))]
pub mod args;

#[cfg(all(feature = "http", feature = "net", feature = "haproxy"))]
#[cfg_attr(
    docsrs,
    doc(cfg(all(feature = "http", feature = "net", feature = "haproxy")))
)]
pub mod service;

mod forward;
#[doc(inline)]
pub use forward::ForwardKind;
