//! TLS implementation agnostic client types
//!
//! [`ClientHello`] is used in Rama as the implementation agnostic type
//! to convey what client hello was set by the incoming TLS Connection,
//! if the server middleware is configured to store it.
//!
//! By being implementation agnostic we have the advantage to be able to bridge
//! easily between different implementations. Making it possible to run for example
//! a Rustls proxy service but establish connections using BoringSSL.

mod hello;
#[doc(inline)]
pub use hello::{ClientHello, ClientHelloExtension, ECHClientHello};

mod parser;
pub use parser::{
    extract_sni_from_client_hello_handshake, extract_sni_from_client_hello_record,
    parse_client_hello,
};

mod config;
#[doc(inline)]
pub use config::{
    ClientAuth, ClientAuthData, ClientConfig, ClientConfigChain, ProxyClientConfig,
    ServerVerifyMode, append_all_client_configs_to_extensions, append_client_config_to_extensions,
    extract_client_config_from_extensions,
};

use super::{ApplicationProtocol, DataEncoding, ProtocolVersion};

#[derive(Debug, Clone)]
/// Indicate (some) of the negotiated tls parameters that
/// can be added to the service context by Tls implementations.
pub struct NegotiatedTlsParameters {
    /// The used [`ProtocolVersion`].
    ///
    /// e.g. [`ProtocolVersion::TLSv1_3`]
    pub protocol_version: ProtocolVersion,
    /// Indicates the agreed upon [`ApplicationProtocol`]
    /// in case the tls implementation can surfice this
    /// AND there is such a protocol negotiated and agreed upon.
    ///
    /// e.g. [`ApplicationProtocol::HTTP_2`]
    pub application_layer_protocol: Option<ApplicationProtocol>,
    /// Certificate chain provided the peer (only stored if config requested this)
    pub peer_certificate_chain: Option<DataEncoding>,
}

/// Merge extension lists A and B, with
/// B overwriting any conflict with A, and otherwise push it to the back.
pub fn merge_client_hello_lists(
    a: impl AsRef<[ClientHelloExtension]>,
    b: impl AsRef<[ClientHelloExtension]>,
) -> Vec<ClientHelloExtension> {
    let a = a.as_ref();
    let b = b.as_ref();

    let mut output = Vec::with_capacity(a.len() + b.len());

    output.extend(a.iter().cloned());

    for ext in b.iter().cloned() {
        match output.iter_mut().find(|e| e.id() == ext.id()) {
            Some(old) => {
                *old = ext;
            }
            None => output.push(ext),
        }
    }

    output
}

#[cfg(test)]
mod tests {
    use crate::address::Domain;

    use super::*;

    #[test]
    fn test_merge_client_hello_lists_empty() {
        assert!(merge_client_hello_lists(vec![], vec![]).is_empty());
    }

    #[test]
    fn test_merge_client_hello_lists_zero_one() {
        let output = merge_client_hello_lists(&[], [ClientHelloExtension::ServerName(None)]);
        assert_eq!(1, output.len());
        assert!(matches!(output[0], ClientHelloExtension::ServerName(_)))
    }

    #[test]
    fn test_merge_client_hello_lists_one_zero() {
        let output = merge_client_hello_lists(vec![ClientHelloExtension::ServerName(None)], &[]);
        assert_eq!(1, output.len());
        assert!(matches!(output[0], ClientHelloExtension::ServerName(_)))
    }

    #[test]
    fn test_merge_client_hello_lists_one_one() {
        let output = merge_client_hello_lists(
            vec![ClientHelloExtension::ServerName(None)],
            &[ClientHelloExtension::SupportedVersions(vec![])],
        );
        assert_eq!(2, output.len());
        assert!(matches!(output[0], ClientHelloExtension::ServerName(_)));
        assert!(matches!(
            output[1],
            ClientHelloExtension::SupportedVersions(_)
        ));
    }

    #[test]
    fn test_merge_client_hello_lists_two_two_with_one_conflict() {
        let output = merge_client_hello_lists(
            vec![
                ClientHelloExtension::ServerName(None),
                ClientHelloExtension::SupportedVersions(vec![]),
            ],
            &[
                ClientHelloExtension::ServerName(Some(Domain::from_static("example.com"))),
                ClientHelloExtension::ApplicationLayerProtocolNegotiation(vec![]),
            ],
        );
        assert_eq!(3, output.len());
        assert!(matches!(output[0], ClientHelloExtension::ServerName(_)));
        assert!(matches!(
            output[1],
            ClientHelloExtension::SupportedVersions(_)
        ));
        assert!(matches!(
            output[2],
            ClientHelloExtension::ApplicationLayerProtocolNegotiation(_)
        ));
    }
}
