//! Server Utilities

mod certs;
pub use self::certs::{
    self_signed_server_auth_gen_ca, self_signed_server_auth_gen_cert,
    self_signed_server_auth_mirror_cert, self_signed_server_auth_mirror_cert_with_extensions,
};

mod crl;
pub use self::crl::build_mitm_ca_crl;

mod ocsp;
pub use self::ocsp::{MitmLeafOcspStatus, answer_ocsp_request, build_mitm_leaf_ocsp_response};
