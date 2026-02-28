use std::{fs, path::PathBuf};

use rama::{
    error::{BoxError, ErrorContext as _},
    net::{
        address::Domain,
        tls::{
            ApplicationProtocol, DataEncoding,
            server::{
                CacheKind, SelfSignedData, ServerAuth, ServerAuthData, ServerCertIssuerData,
                ServerCertIssuerKind, ServerConfig,
            },
        },
    },
    telemetry::tracing,
    tls::boring::server::utils::self_signed_server_ca,
    utils::str::NonEmptyStr,
};

#[derive(Debug, Clone)]
pub(super) struct MitmCaMaterial {
    pub(super) cert_pem: NonEmptyStr,
    pub(super) key_pem: NonEmptyStr,
}

#[derive(Debug, Clone)]
pub struct MitmTlsConfig {
    pub(super) server_config: ServerConfig,
    pub(super) root_ca_pem: NonEmptyStr,
}

pub fn load_or_create_mitm_tls_config() -> Result<MitmTlsConfig, BoxError> {
    let MitmCaMaterial { cert_pem, key_pem } =
        load_or_create_ca_material().context("load or create mitm root ca")?;

    let server_config = ServerConfig {
        application_layer_protocol_negotiation: Some(vec![
            ApplicationProtocol::HTTP_2, // TODO: In future this should mirror egress side
            ApplicationProtocol::HTTP_11,
        ]),
        ..ServerConfig::new(ServerAuth::CertIssuer(ServerCertIssuerData {
            kind: ServerCertIssuerKind::Single(ServerAuthData {
                private_key: DataEncoding::Pem(key_pem),
                cert_chain: DataEncoding::Pem(cert_pem.clone()),
                ocsp: None,
            }),
            cache_kind: CacheKind::default(),
        }))
    };

    Ok(MitmTlsConfig {
        server_config,
        root_ca_pem: cert_pem,
    })
}

fn load_or_create_ca_material() -> Result<MitmCaMaterial, BoxError> {
    let cert_path = root_ca_cert_path()?;
    let key_path = root_ca_key_path()?;

    if let Ok(cert_pem_raw) = fs::read_to_string(&cert_path) {
        let cert_pem: NonEmptyStr = cert_pem_raw
            .try_into()
            .context("loaded pem cert bytes as NonEmptyStr")?;
        let key_pem: NonEmptyStr = fs::read_to_string(&key_path)
            .context("read key file as PEM string")?
            .try_into()
            .context("loaded pem key bytes as NonEmptyStr")?;

        return Ok(MitmCaMaterial { cert_pem, key_pem });
    }

    if let Some(parent) = cert_path.parent() {
        fs::create_dir_all(parent).context("create root ca directory")?;
    }

    let (root_cert, root_key) = self_signed_server_ca(&SelfSignedData {
        organisation_name: Some("Rama Transparent Proxy Example".to_owned()),
        common_name: Some(Domain::from_static("rama-tproxy-mitm-ca.localhost")),
        ..Default::default()
    })
    .context("generate self-signed root ca")?;

    let cert_pem_bytes = root_cert.to_pem().context("encode root ca cert to pem")?;
    let key_pem_bytes = root_key
        .private_key_to_pem_pkcs8()
        .context("encode root ca key to pkcs8 pem")?;

    let cert_pem_str =
        String::from_utf8(cert_pem_bytes).context("root ca cert pem not valid utf-8")?;
    let key_pem_str =
        String::from_utf8(key_pem_bytes).context("root ca key pem not valid utf-8")?;

    let cert_pem = NonEmptyStr::try_from(cert_pem_str)
        .context("interpret newly created cert pem from string as NonEmptyStr")?;
    let key_pem = NonEmptyStr::try_from(key_pem_str)
        .context("interpret newly created key pem from string as NonEmptyStr")?;

    fs::write(&cert_path, cert_pem.as_bytes()).context("write root ca cert pem to disk")?;
    fs::write(&key_path, key_pem.as_bytes()).context("write root ca key pem to disk")?;

    tracing::info!(
        cert_path = %cert_path.display(),
        key_path = %key_path.display(),
        "generated and persisted MITM root CA"
    );

    Ok(MitmCaMaterial { cert_pem, key_pem })
}

fn root_ca_cert_path() -> Result<PathBuf, BoxError> {
    Ok(root_ca_base_dir()?.join("root.ca.pem"))
}

fn root_ca_key_path() -> Result<PathBuf, BoxError> {
    Ok(root_ca_base_dir()?.join("root.ca.key.pem"))
}

fn root_ca_base_dir() -> Result<PathBuf, BoxError> {
    let home = std::env::var("HOME").context("missing HOME environment variable")?;
    Ok(PathBuf::from(home)
        .join("Library")
        .join("Application Support")
        .join("org.ramaproxy.example.tproxy")
        .join("mitm"))
}
