//! Protocols that are often built on top of HTTP.
//!
//! Even if not strictly bound to HTTP, we still ship them here... for now.

#[cfg(feature = "html")]
#[cfg_attr(docsrs, doc(cfg(feature = "html")))]
pub mod html;

#[cfg(feature = "rss")]
#[cfg_attr(docsrs, doc(cfg(feature = "rss")))]
pub mod rss;
