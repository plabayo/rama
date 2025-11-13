//! rama cli utilities

#[cfg(all(feature = "http", feature = "net", feature = "haproxy"))]
#[cfg_attr(
    docsrs,
    doc(cfg(all(feature = "http", feature = "net", feature = "haproxy")))
)]
pub mod service;

mod forward;
#[doc(inline)]
pub use forward::ForwardKind;
