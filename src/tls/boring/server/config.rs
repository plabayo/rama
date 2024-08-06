use crate::tls::boring::dep::boring::{
    pkey::{PKey, Private},
    x509::X509,
};
use crate::tls::ApplicationProtocol;

#[derive(Clone, Debug)]
/// Common configuration for a set of server sessions.
pub struct ServerConfig {
    /// Private Key of the server
    pub private_key: PKey<Private>,
    /// CA Cert of the server
    pub ca_cert: X509,
    /// Set the ALPN protocols supported by the service's inner application service.
    pub alpn_protocols: Vec<ApplicationProtocol>,
    /// Disable the superificial verification in this Tls acceptor.
    pub disable_verify: bool,
    /// Write logging information to facilitate tls interception.
    pub keylog_filename: Option<String>,
}

impl ServerConfig {
    /// Create a new [`ServerConfig`].
    pub fn new(private_key: PKey<Private>, ca_cert: X509) -> ServerConfig {
        ServerConfig {
            private_key,
            ca_cert,
            alpn_protocols: vec![],
            disable_verify: false,
            keylog_filename: None,
        }
    }
}
