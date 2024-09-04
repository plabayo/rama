//! CLI utilities for boring

use crate::error::{BoxError, ErrorContext};
use crate::http::Version;
use crate::tls::boring::dep::boring::pkey::PKey;
use crate::tls::boring::dep::boring::x509::X509;
use crate::tls::boring::server::ServerConfig;
use crate::tls::types::ApplicationProtocol;
use base64::Engine;

const BASE64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

#[derive(Debug, Clone)]
/// Tls cert/key pair that can be used to create a tls Server Config.
pub struct TlsServerCertKeyPair {
    tls_cert_pem_raw: String,
    tls_key_pem_raw: String,
    http_version: Option<Version>,
}

impl TlsServerCertKeyPair {
    /// Create a new [`TlsServerCertKeyPair`].
    pub const fn new(cert_pem_raw: String, key_pem_raw: String) -> Self {
        Self {
            tls_cert_pem_raw: cert_pem_raw,
            tls_key_pem_raw: key_pem_raw,
            http_version: None,
        }
    }

    /// Maybe define a specific http [`Version`].
    ///
    /// Used to defined the version in the ALPN.
    pub const fn maybe_http_version(mut self, version: Option<Version>) -> Self {
        self.http_version = version;
        self
    }

    /// Define a specific http [`Version`] instead of using the default `auto`.
    ///
    /// Used to defined the version in the ALPN.
    pub const fn http_version(mut self, version: Version) -> Self {
        self.http_version = Some(version);
        self
    }

    /// Define a specific http [`Version`] instead of using the default `auto`.
    ///
    /// Used to defined the version in the ALPN.
    pub fn set_http_version(&mut self, version: Version) -> &mut Self {
        self.http_version = Some(version);
        self
    }

    /// Consume this [`TlsServerCertKeyPair`] into a [`ServerConfig`].
    pub fn into_server_config(self) -> Result<ServerConfig, BoxError> {
        // server TLS Certs
        let tls_cert_pem_raw = BASE64
            .decode(self.tls_cert_pem_raw.as_bytes())
            .context("base64 decode x509 ca cert PEM data")?;
        let ca_cert_chain = X509::stack_from_pem(&tls_cert_pem_raw[..])
            .context("parse x509 ca cert from PEM content")?;

        let tls_key_pem_raw = BASE64
            .decode(self.tls_key_pem_raw.as_bytes())
            .context("base64 decode private key PEM data")?;
        let key = PKey::private_key_from_pem(&tls_key_pem_raw[..])
            .context("parse private key from PEM content")?;

        let mut server_config = ServerConfig::new(key, ca_cert_chain);

        // support key logging
        if let Ok(keylog_file) = std::env::var("SSLKEYLOGFILE") {
            server_config.keylog_filename = Some(keylog_file);
        }

        // set ALPN protocols
        server_config.alpn_protocols = match self.http_version {
            None => vec![ApplicationProtocol::HTTP_2, ApplicationProtocol::HTTP_11],
            Some(Version::HTTP_2) => vec![ApplicationProtocol::HTTP_2],
            _ => vec![ApplicationProtocol::HTTP_11],
        };

        // return the server config
        Ok(server_config)
    }
}
