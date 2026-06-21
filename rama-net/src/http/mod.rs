//! http net support added as part of rama's net support
//!
//! See `rama-http` and `rama-http-backend` for most
//! http support. In this module lives only the stuff
//! directly connected to `rama-net` types.

pub mod server;

pub mod uri;

mod version;
#[doc(inline)]
pub use version::{InvalidVersion, TargetHttpVersion, Version};
