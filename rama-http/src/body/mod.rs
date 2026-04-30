//! extra http body types and utilities.

#[cfg(feature = "compression")]
mod zip_bomb;
#[cfg(feature = "compression")]
#[cfg_attr(docsrs, doc(cfg(feature = "compression")))]
pub use zip_bomb::ZipBomb;

#[doc(inline)]
pub use ::rama_http_types::body::*;
