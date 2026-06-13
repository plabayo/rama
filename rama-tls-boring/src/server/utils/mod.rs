//! Server Utilities

mod certs;
pub use self::certs::{
    self_signed_server_auth_gen_ca, self_signed_server_auth_gen_cert,
    self_signed_server_auth_mirror_cert,
};

mod ocsp;
pub use self::ocsp::{MitmLeafOcspStatus, build_mitm_leaf_ocsp_response};
