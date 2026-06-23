//! Server Utilities
//!
//! Generic certificate generation (self-signed CA/leaf + MITM mirroring) lives
//! in [`rama_crypto::cert::boring`]

mod ocsp;
pub use self::ocsp::{MitmLeafOcspStatus, build_mitm_leaf_ocsp_response};
