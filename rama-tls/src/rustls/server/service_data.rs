use crate::dep::rcgen::{self, KeyPair};
use crate::rustls::dep::pemfile;
use crate::rustls::dep::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use crate::rustls::dep::rustls::{self, server::WebPkiClientVerifier, RootCertStore};
use crate::rustls::server::key_log::KeyLogFile;
use rama_core::error::{ErrorContext, OpaqueError};
use rama_net::tls::server::{ClientVerifyMode, SelfSignedData, ServerAuth};
use rama_net::tls::KeyLogIntent;
use std::io::BufReader;
use std::sync::Arc;

#[derive(Debug, Clone)]
/// Internal data used as configuration/input for the [`super::TlsAcceptorService`].
///
/// Created by converting a [`rustls::ServerConfig`] into it directly,
/// or by trying to turn the _rama_ opiniated [`rama_net::tls::server::ServerConfig`] into it.
pub struct ServiceData {
    pub(super) server_config: Arc<rustls::ServerConfig>,
}

impl From<rustls::ServerConfig> for ServiceData {
    #[inline]
    fn from(value: rustls::ServerConfig) -> Self {
        Arc::new(value).into()
    }
}

impl From<Arc<rustls::ServerConfig>> for ServiceData {
    fn from(value: Arc<rustls::ServerConfig>) -> Self {
        Self {
            server_config: value,
        }
    }
}

impl TryFrom<rama_net::tls::server::ServerConfig> for ServiceData {
    type Error = OpaqueError;

    fn try_from(value: rama_net::tls::server::ServerConfig) -> Result<Self, Self::Error> {
        let v: Vec<_> = value
            .protocol_versions
            .into_iter()
            .flatten()
            .filter_map(|v| v.try_into().ok())
            .collect();

        // builder with protocol versions defined (be it auto)
        let builder = if v.is_empty() {
            rustls::ServerConfig::builder_with_protocol_versions(rustls::ALL_VERSIONS)
        } else {
            rustls::ServerConfig::builder_with_protocol_versions(&v[..])
        };

        // builder with client auth configured
        let builder = match value.client_verify_mode {
            ClientVerifyMode::Auto | ClientVerifyMode::Disable => builder.with_no_client_auth(),
            ClientVerifyMode::ClientAuth(raw_pem) => {
                let client_cert_der = CertificateDer::from(raw_pem.as_bytes());
                let mut root_cert_storage = RootCertStore::empty();
                root_cert_storage
                    .add(client_cert_der)
                    .context("rusts/ServiceData: add client cert to root cert storage")?;
                let cert_verifier = WebPkiClientVerifier::builder(Arc::new(root_cert_storage))
                    .build()
                    .context("rusts/ServiceData: create webpki client verifier")?;
                builder.with_client_cert_verifier(cert_verifier)
            }
        };

        let mut server_config = match value.server_auth {
            ServerAuth::SelfSigned(data) => {
                let (cert_chain, key_der) =
                    self_signed_server_auth(data).context("rusts/ServiceData")?;
                builder
                    .with_single_cert(cert_chain, key_der)
                    .context("rusts/ServiceData: build base self-signed rustls ServerConfig")?
            }
            ServerAuth::Single(data) => {
                // server TLS Certs
                let mut pem = BufReader::new(data.cert_chain_pem.as_bytes());
                let mut cert_chain = Vec::new();
                for cert in pemfile::certs(&mut pem) {
                    cert_chain.push(cert.expect("parse tls server cert"));
                }

                // server TLS key
                let mut key_reader = BufReader::new(data.private_key_pem.as_bytes());
                let key_der = pemfile::private_key(&mut key_reader)
                    .expect("read private key")
                    .expect("private found");

                // builder with server auth configured
                match data.ocsp {
                    None => builder.with_single_cert(cert_chain, key_der),
                    Some(ocsp) => builder.with_single_cert_with_ocsp(cert_chain, key_der, ocsp),
                }
                .context("rusts/ServiceData: build base rustls ServerConfig")?
            }
        };

        // set key logger if one is requested
        match value.key_logger {
            KeyLogIntent::Disabled => (),
            KeyLogIntent::File(path) => {
                let key_logger = KeyLogFile::new(path).context("rusts/ServiceData")?;
                server_config.key_log = Arc::new(key_logger);
            }
        };

        // set ALPN for negotiation, resulting in the (default) empty Vec if none was defined
        server_config.alpn_protocols = value
            .application_layer_protocol_negotiation
            .into_iter()
            .flatten()
            .map(|p| p.as_bytes().to_vec())
            .collect();

        // return the created server config, all good if you reach here
        Ok(ServiceData {
            server_config: Arc::new(server_config),
        })
    }
}

fn self_signed_server_auth(
    data: SelfSignedData,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), OpaqueError> {
    // Create an issuer CA cert.
    let alg = &rcgen::PKCS_ECDSA_P256_SHA256;
    let ca_key_pair = KeyPair::generate_for(alg).context("self-signed: generate ca key pair")?;

    let mut ca_params =
        rcgen::CertificateParams::new(Vec::new()).context("self-signed: create ca params")?;
    ca_params.distinguished_name.push(
        rcgen::DnType::OrganizationName,
        data.organisation_name
            .unwrap_or_else(|| "Anonymous".to_owned()),
    );
    ca_params.distinguished_name.push(
        rcgen::DnType::CommonName,
        data.common_name.unwrap_or_else(|| "localhost".to_owned()),
    );
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    let ca_cert = ca_params
        .self_signed(&ca_key_pair)
        .context("self-signed: create ca cert")?;

    let server_key_pair =
        KeyPair::generate_for(alg).context("self-signed: create server key pair")?;
    let mut server_ee_params =
        rcgen::CertificateParams::new(data.subject_alternative_names.unwrap_or_default())
            .context("self-signed: create server EE params")?;
    server_ee_params.is_ca = rcgen::IsCa::NoCa;
    server_ee_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let server_cert = server_ee_params
        .signed_by(&server_key_pair, &ca_cert, &ca_key_pair)
        .context("self-signed: sign servert cert")?;
    let server_cert_der: CertificateDer = server_cert.into();
    let server_key_der = PrivatePkcs8KeyDer::from(server_key_pair.serialize_der());

    Ok((
        vec![server_cert_der],
        PrivatePkcs8KeyDer::from(server_key_der.secret_pkcs8_der().to_owned()).into(),
    ))
}
