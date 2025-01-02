use super::ClientHelloExtension;
use crate::tls::{ApplicationProtocol, CipherSuite, ProtocolVersion, SignatureScheme};

impl<'a> From<rustls::server::ClientHello<'a>> for super::ClientHello {
    fn from(value: rustls::server::ClientHello<'a>) -> Self {
        let cipher_suites = value
            .cipher_suites()
            .iter()
            .map(|cs| CipherSuite::from(*cs))
            .collect();

        let mut extensions = Vec::with_capacity(3);

        extensions.push(ClientHelloExtension::SignatureAlgorithms(
            value
                .signature_schemes()
                .iter()
                .map(|sc| SignatureScheme::from(*sc))
                .collect(),
        ));

        if let Some(domain) = value.server_name().and_then(|d| d.parse().ok()) {
            extensions.push(ClientHelloExtension::ServerName(Some(domain)));
        }

        if let Some(alpn) = value.alpn() {
            extensions.push(ClientHelloExtension::ApplicationLayerProtocolNegotiation(
                alpn.map(ApplicationProtocol::from).collect(),
            ));
        }

        Self {
            protocol_version: ProtocolVersion::Unknown(0), // TODO: support if rustls can handle this
            cipher_suites,
            compression_algorithms: vec![],
            extensions,
        }
    }
}
