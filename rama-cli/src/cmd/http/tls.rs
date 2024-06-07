use rama::{
    error::BoxError,
    tls::rustls::{
        dep::{
            pki_types::{CertificateDer, PrivateKeyDer},
            rustls::{
                version::{TLS12, TLS13},
                ClientConfig, KeyLogFile, RootCertStore,
            },
            webpki_roots,
        },
        verify::NoServerCertVerifier,
    },
};
use std::sync::Arc;

/// Create a new [`ClientConfig`] for a TLS cli client.
pub(super) async fn create_tls_client_config(
    insecure: bool,
    tls_version: Option<String>,
    client_cert_path: Option<String>,
    client_key_path: Option<String>,
) -> Result<Arc<ClientConfig>, BoxError> {
    let config = if let Some(version) = tls_version {
        match version.as_str() {
            "1.2" => ClientConfig::builder_with_protocol_versions(&[&TLS12]),
            "1.3" => ClientConfig::builder_with_protocol_versions(&[&TLS13]),
            _ => return Err(format!("Unsupported TLS version: {}", version).into()),
        }
    } else {
        ClientConfig::builder()
    };

    // TODO: allow root certs to be passed in / customised (e.g. use system roots perhaps by default?!)
    let mut root_storage = RootCertStore::empty();
    root_storage.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = config.with_root_certificates(root_storage);

    let mut config = if let Some(client_cert_path) = client_cert_path {
        let client_key_path = match client_key_path {
            Some(path) => path,
            None => {
                return Err(
                    "client_key_path must be provided if client_cert_path is provided".into(),
                )
            }
        };
        let client_cert = tokio::fs::read(client_cert_path).await?;
        let cert = CertificateDer::from(client_cert);

        let client_key = tokio::fs::read(client_key_path).await?;
        let key = PrivateKeyDer::try_from(client_key)?;
        config.with_client_auth_cert(vec![cert], key)?
    } else {
        config.with_no_client_auth()
    };

    if insecure {
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(NoServerCertVerifier::new()));
    }

    if std::env::var("SSLKEYLOGFILE").is_ok() {
        config.key_log = Arc::new(KeyLogFile::new());
    }

    Ok(Arc::new(config))
}
