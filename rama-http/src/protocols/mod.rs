//! Protocols that are often built on top of HTTP.
//!
//! Even if not strictly bound to HTTP, we still ship them here... for now.

#[cfg(feature = "html")]
#[cfg_attr(docsrs, doc(cfg(feature = "html")))]
pub mod html;

pub mod json_ld;

#[cfg(feature = "multipart")]
#[cfg_attr(docsrs, doc(cfg(feature = "multipart")))]
pub mod multipart;

#[cfg(feature = "rss")]
#[cfg_attr(docsrs, doc(cfg(feature = "rss")))]
pub mod rss;
