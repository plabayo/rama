//! byte-slice utilities

pub mod ct;

mod ows;
#[doc(inline)]
pub use ows::{trim_ows, trim_ows_end, trim_ows_start};

/// Compact Serde representation for opaque bytes.
pub mod serde_base64;

/// Configurable hex Serde representation for opaque bytes.
pub mod serde_hex;
