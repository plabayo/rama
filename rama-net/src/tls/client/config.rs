use std::sync::Arc;

use super::{ClientHelloExtension, merge_client_hello_lists};
use crate::tls::{CipherSuite, CompressionAlgorithm, DataEncoding, KeyLogIntent, ProtocolVersion};

#[derive(Debug, Clone, Default)]
/// Common API to configure a Proxy TLS Client
///
/// See [`ClientConfig`] for more information,
/// this is only a new-type wrapper to be able to differentiate
/// the info found in context for a dynamic https client.
pub struct ProxyClientConfig(pub Arc<ClientConfig>);

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
    pub server_verify_mode: Option<ServerVerifyMode>,
    /// optionally define raw (PEM-encoded) client auth certs
    pub client_auth: Option<ClientAuth>,
    /// key log intent
    pub key_logger: Option<KeyLogIntent>,
    /// if enabled server certificates will be stored in [`NegotiatedTlsParameters`]
    pub store_server_certificate_chain: bool,
}

impl ClientConfig {
    /// Merge this [`ClientConfig`] with aother one.
    pub fn merge(&mut self, other: Self) {
        if let Some(cipher_suites) = other.cipher_suites {
            self.cipher_suites = Some(cipher_suites);
        }

        if let Some(compression_algorithms) = other.compression_algorithms {
            self.compression_algorithms = Some(compression_algorithms);
        }

        self.extensions = match (self.extensions.take(), other.extensions) {
            (Some(our_ext), Some(other_ext)) => Some(merge_client_hello_lists(our_ext, other_ext)),
            (None, Some(other_ext)) => Some(other_ext),
            (maybe_our_ext, None) => maybe_our_ext,
        };

        if let Some(server_verify_mode) = other.server_verify_mode {
            self.server_verify_mode = Some(server_verify_mode);
        }

        if let Some(client_auth) = other.client_auth {
            self.client_auth = Some(client_auth);
        }

        if let Some(key_logger) = other.key_logger {
            self.key_logger = Some(key_logger);
        }
    }
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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

impl From<ClientConfig> for super::ClientHello {
    fn from(value: ClientConfig) -> Self {
        Self {
            protocol_version: ProtocolVersion::TLSv1_2,
            cipher_suites: value.cipher_suites.unwrap_or_default(),
            compression_algorithms: value.compression_algorithms.unwrap_or_default(),
            extensions: value.extensions.unwrap_or_default(),
        }
    }
}
