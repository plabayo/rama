use crate::tls::ApplicationProtocol;

#[derive(Clone, Debug, Default)]
/// Common configuration for a set of server sessions.
pub struct ServerConfig {
    /// Set the ALPN protocols supported by the service's inner application service.
    pub alpn_protocols: Vec<ApplicationProtocol>,
    /// Disable the superificial verification in this Tls acceptor.
    pub disable_verify: bool,
    /// Write logging information to facilitate tls interception.
    pub keylog_filename: Option<String>,
}
