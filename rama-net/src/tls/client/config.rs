use super::ClientHelloExtension;
use crate::tls::{CipherSuite, CompressionAlgorithm, DataEncoding, KeyLogIntent};

#[derive(Debug, Clone, Default)]
/// Common API to configure a TLS Client
pub struct ClientConfig {
    /// optional intent for cipher suites to be used by client
    pub cipher_suites: Option<Vec<CipherSuite>>,
    /// optional intent for compression algorithms to be used by client
    pub compression_algorithms: Option<Vec<CompressionAlgorithm>>,
    /// optional intent for extensions to be used by client
    ///
    /// Commpon examples are:
    ///
    /// - [`super::ClientHelloExtension::ApplicationLayerProtocolNegotiation`]
    /// - [`super::ClientHelloExtension::SupportedVersions`]
    pub extensions: Option<Vec<ClientHelloExtension>>,
    /// optionally define how server should be verified by client
    pub server_verify_mode: ServerVerifyMode,
    /// optionally define raw (PEM-encoded) client auth certs
    pub client_auth: Option<ClientAuth>,
    /// optionally provide the option expose the client cert if one is defined
    ///
    /// this will effectively clone the memory to keep these at hand,
    /// so only enable this option if you need it for something specific
    ///
    /// Nop-operation in case client_auth is `None`.
    pub expose_client_cert: bool,
    /// key log intent
    pub key_logger: KeyLogIntent,
}

#[derive(Debug, Clone)]
/// The kind of client auth to be used.
pub enum ClientAuth {
    /// Request the tls implementation to generate self-signed single data
    SelfSigned,
    /// Single data provided by the configurator
    Single(ClientAuthData),
}

#[derive(Debug, Clone)]
/// Raw private key and certificate data to facilitate client authentication.
pub struct ClientAuthData {
    /// private key used by client
    pub private_key: DataEncoding,
    /// certificate chain as a companion to the private key
    pub cert_chain: DataEncoding,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// Mode of server verification by a (tls) client
pub enum ServerVerifyMode {
    #[default]
    /// Use the default verification approach as defined
    /// by the implementation of the used (tls) client
    Auto,
    /// Explicitly disable server verification (if possible)
    Disable,
}

impl From<super::ClientHello> for ClientConfig {
    fn from(value: super::ClientHello) -> Self {
        Self {
            cipher_suites: (!value.cipher_suites.is_empty()).then_some(value.cipher_suites),
            compression_algorithms: (!value.compression_algorithms.is_empty())
                .then_some(value.compression_algorithms),
            extensions: (!value.extensions.is_empty()).then_some(value.extensions),
            ..Default::default()
        }
    }
}
