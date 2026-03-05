use std::{fs, path::PathBuf, sync::OnceLock};

use rama::{
    error::{BoxError, ErrorContext as _},
    net::{address::Domain, tls::server::SelfSignedData},
    telemetry::tracing,
    tls::boring::{
        core::{
            pkey::{PKey, Private},
            x509::X509,
        },
        server::utils::self_signed_server_auth_gen_ca,
    },
};

pub fn load_or_create_mitm_ca_crt_key_pair() -> Result<(X509, PKey<Private>), BoxError> {
    let root_dir = root_ca_base_dir()?;

    let cert_path = root_dir.join("root.ca.pem");
    let key_path = root_dir.join("root.ca.key.pem");

    if cert_path.is_file() && key_path.is_file() {
        tracing::info!(
            "crt/key files exist: try to load existing CA crt/key from disk and fail otherwise!"
        );

        let cert_pem = fs::read(&cert_path).context("read root ca cert file as PEM bytes")?;
        let key_pem = fs::read(&key_path).context("read root ca key file as PEM bytes")?;
        let cert = X509::from_pem(&cert_pem).context("parse root ca cert PEM bytes into X509")?;
        let key = PKey::private_key_from_pem(&key_pem)
            .context("parse root ca private key PEM bytes into PKey<Private>")?;
        return Ok((cert, key));
    }

    tracing::info!(
        "no CA crt/key pair found... create new ones and store under {}",
        root_dir.display()
    );

    if let Some(parent) = cert_path.parent() {
        fs::create_dir_all(parent).context("create root ca directory")?;
    }

    let (root_cert, root_key) = self_signed_server_auth_gen_ca(&SelfSignedData {
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

    fs::write(&cert_path, cert_pem_str.as_bytes()).context("write root ca cert pem to disk")?;
    fs::write(&key_path, key_pem_str.as_bytes()).context("write root ca key pem to disk")?;

    tracing::info!(
        cert_path = %cert_path.display(),
        key_path = %key_path.display(),
        "generated and persisted MITM root CA"
    );

    Ok((root_cert, root_key))
}

fn root_ca_base_dir() -> Result<PathBuf, BoxError> {
    MITM_BASE_DIR
        .get()
        .cloned()
        .context("missing MITM_BASE_DIR; proxy not properly initialised?")
}

static MITM_BASE_DIR: OnceLock<PathBuf> = OnceLock::new();

pub fn set_mitm_base_dir(path: PathBuf) {
    let _ = MITM_BASE_DIR.set(path);
}
