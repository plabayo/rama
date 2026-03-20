use std::{path::PathBuf, sync::Arc, sync::OnceLock};

use apple_native_keyring_store::protected::Store as AppleProtectedStore;
use keyring_core::{Entry, Error as KeyringError, api::CredentialStoreApi};

use rama::{
    error::{BoxError, ErrorContext as _, ErrorExt as _},
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
    match (
        load_protected_secret(ROOT_CA_CERT_SERVICE),
        load_protected_secret(ROOT_CA_KEY_SERVICE),
    ) {
        (Ok(Some(cert_pem)), Ok(Some(key_pem))) => {
            tracing::info!("MITM CA present in Apple protected storage; loading existing keypair");

            let cert = X509::from_pem(&cert_pem)
                .context("parse protected-store root ca cert PEM bytes into X509")?;
            let key = PKey::private_key_from_pem(&key_pem).context(
                "parse protected-store root ca private key PEM bytes into PKey<Private>",
            )?;
            return Ok((cert, key));
        }
        (Err(err), _) | (_, Err(err)) => {
            tracing::warn!(
                "protected-store MITM CA unavailable; falling back to filesystem storage: {err}"
            );
        }
        _ => {}
    }

    if let (Some(cert_pem), Some(key_pem)) = (
        load_file_secret(ROOT_CA_CERT_SERVICE)?,
        load_file_secret(ROOT_CA_KEY_SERVICE)?,
    ) {
        tracing::info!("MITM CA present in filesystem storage; loading existing keypair");

        let cert = X509::from_pem(&cert_pem)
            .context("parse filesystem root ca cert PEM bytes into X509")?;
        let key = PKey::private_key_from_pem(&key_pem)
            .context("parse filesystem root ca private key PEM bytes into PKey<Private>")?;
        return Ok((cert, key));
    }

    tracing::info!("no MITM CA in Apple protected storage; generating new root CA keypair");

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

    match (
        store_protected_secret(ROOT_CA_CERT_SERVICE, &cert_pem_bytes),
        store_protected_secret(ROOT_CA_KEY_SERVICE, &key_pem_bytes),
    ) {
        (Ok(()), Ok(())) => {
            tracing::info!("generated and persisted MITM root CA in Apple protected storage");
        }
        (cert_result, key_result) => {
            if let Err(err) = cert_result.and(key_result) {
                tracing::warn!(
                    "failed to persist MITM CA in protected storage; storing on filesystem instead: {err}"
                );
            }
            store_file_secret(ROOT_CA_CERT_SERVICE, &cert_pem_bytes)?;
            store_file_secret(ROOT_CA_KEY_SERVICE, &key_pem_bytes)?;
            tracing::info!("generated and persisted MITM root CA in filesystem storage");
        }
    }

    Ok((root_cert, root_key))
}

const ROOT_CA_ACCOUNT: &str = env!("CARGO_PKG_NAME");
const ROOT_CA_CERT_SERVICE: &str = "mitm-root-ca-cert-pem";
const ROOT_CA_KEY_SERVICE: &str = "mitm-root-ca-key-pem";

static PROTECTED_STORE: OnceLock<Arc<AppleProtectedStore>> = OnceLock::new();

fn protected_store() -> Result<Arc<AppleProtectedStore>, BoxError> {
    if let Some(store) = PROTECTED_STORE.get() {
        return Ok(store.clone());
    }

    let store = AppleProtectedStore::new().context("create Apple Protected Data store")?;
    let _ = PROTECTED_STORE.set(store.clone());
    Ok(PROTECTED_STORE.get().cloned().unwrap_or(store))
}

fn new_protected_entry(service: &str) -> Result<Entry, BoxError> {
    protected_store()?
        .build(service, ROOT_CA_ACCOUNT, None)
        .context("create MITM CA protected-store entry")
        .context_str_field("service", service)
}

fn load_protected_secret(service: &str) -> Result<Option<Vec<u8>>, BoxError> {
    let entry = new_protected_entry(service)?;

    match entry.get_secret() {
        Ok(raw) => Ok(Some(raw)),
        Err(KeyringError::NoEntry) => Ok(None),
        Err(err) => Err(err
            .context("load protected-store secret")
            .context_str_field("service", service)),
    }
}

fn store_protected_secret(service: &str, secret: &[u8]) -> Result<(), BoxError> {
    new_protected_entry(service)?
        .set_secret(secret)
        .context("store protected-store secret")
        .context_str_field("service", service)
}

fn file_secret_path(service: &str) -> PathBuf {
    crate::utils::storage_dir().join(format!("{service}.pem"))
}

fn load_file_secret(service: &str) -> Result<Option<Vec<u8>>, BoxError> {
    let path = file_secret_path(service);
    match std::fs::read(&path) {
        Ok(raw) => Ok(Some(raw)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(BoxError::from(err)
            .context("load filesystem secret")
            .context_str_field("service", service)
            .context_str_field("path", path.display().to_string())),
    }
}

fn store_file_secret(service: &str, secret: &[u8]) -> Result<(), BoxError> {
    let path = file_secret_path(service);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).context("create filesystem secret parent dir")?;
    }
    std::fs::write(&path, secret)
        .context("store filesystem secret")
        .context_str_field("service", service)
        .context_str_field("path", path.display().to_string())
}
