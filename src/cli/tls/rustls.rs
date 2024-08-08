//! CLI utilities for rustls

use crate::error::BoxError;
use crate::http::Version;
use crate::tls::rustls::dep::pemfile;
use crate::tls::rustls::dep::rustls::{KeyLogFile, ServerConfig};
use base64::Engine;
use std::io::BufReader;
use std::sync::Arc;

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
    pub fn new(cert_pem_raw: String, key_pem_raw: String) -> Self {
        Self {
            tls_cert_pem_raw: cert_pem_raw,
            tls_key_pem_raw: key_pem_raw,
            http_version: None,
        }
    }

    /// Maybe define a specific http [`Version`].
    ///
    /// Used to defined the version in the ALPN.
    pub fn maybe_http_version(mut self, version: Option<Version>) -> Self {
        self.http_version = version;
        self
    }

    /// Define a specific http [`Version`] instead of using the default `auto`.
    ///
    /// Used to defined the version in the ALPN.
    pub fn http_version(mut self, version: Version) -> Self {
        self.http_version = Some(version);
        self
    }

    /// Consume this [`TlsServerCertKeyPair`] into a [`ServerConfig`].
    pub fn into_server_config(self) -> Result<ServerConfig, BoxError> {
        // server TLS Certs
        let tls_cert_pem_raw = BASE64.decode(self.tls_cert_pem_raw.as_bytes())?;
        let mut pem = BufReader::new(&tls_cert_pem_raw[..]);
        let mut certs = Vec::new();
        for cert in pemfile::certs(&mut pem) {
            certs.push(cert.expect("parse tls server cert"));
        }

        // server TLS key
        let tls_key_pem_raw = BASE64.decode(self.tls_key_pem_raw.as_bytes())?;
        let mut key_reader = BufReader::new(&tls_key_pem_raw[..]);
        let key = pemfile::private_key(&mut key_reader)
            .expect("read private key")
            .expect("private found");

        let mut server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?;

        // support key logging
        if std::env::var("SSLKEYLOGFILE").is_ok() {
            server_config.key_log = Arc::new(KeyLogFile::new());
        }

        // set ALPN protocols
        server_config.alpn_protocols = match self.http_version {
            None => vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            Some(Version::HTTP_2) => vec![b"h2".to_vec()],
            _ => vec![b"http/1.1".to_vec()],
        };

        // return the server config
        Ok(server_config)
    }
}
