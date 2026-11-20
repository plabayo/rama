//! http net support added as part of rama's net support
//!
//! See `rama-http` and `rama-http-backend` for most
//! http support. In this module lives only the stuff
//! directly connected to `rama-net` types.

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
pub mod server;

mod version;
#[doc(inline)]
pub use version::{
    FallbackHttpVersion, HttpRequestVersion, InvalidVersion, TargetHttpVersion, Version,
};
