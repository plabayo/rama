//! Server Utilities
//!
//! Generic certificate generation (self-signed CA/leaf + MITM mirroring) lives
//! in [`rama_crypto::cert::boring`]

mod crl;
pub use self::crl::build_mitm_ca_crl;

mod ocsp;
pub use self::ocsp::{MitmLeafOcspStatus, answer_ocsp_request, build_mitm_leaf_ocsp_response};
