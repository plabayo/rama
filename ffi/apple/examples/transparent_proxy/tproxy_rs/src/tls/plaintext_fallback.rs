//! Plaintext MITM CA storage used when the Mac has no usable Secure Enclave
//! (e.g. an Intel Mac without a T2 chip). PEMs are stored as-is in the
//! System Keychain — readable by anyone with admin access — so this path is
//! a fallback, not the preferred mode.

use rama::{
    error::{BoxError, ErrorContext as _},
    net::apple::networkextension::system_keychain,
    telemetry::tracing,
    tls::boring::core::{
        pkey::{PKey, Private},
        x509::X509,
    },
};

use super::{
    CA_ACCOUNT, CA_SERVICE_CERT, CA_SERVICE_KEY, SE_SERVICE_KEY, generate_ca_pair,
    wipe_all_ca_entries,
};

pub(super) fn load_or_create() -> Result<(X509, PKey<Private>), BoxError> {
    drop_orphan_se_blob()?;

    let cert_blob = system_keychain::load_secret(CA_SERVICE_CERT, CA_ACCOUNT)
        .context("load plaintext MITM CA cert PEM")?;
    let key_blob = system_keychain::load_secret(CA_SERVICE_KEY, CA_ACCOUNT)
        .context("load plaintext MITM CA key PEM")?;

    match (cert_blob, key_blob) {
        (Some(cert_pem), Some(key_pem)) => match parse_pair(&cert_pem, &key_pem) {
            Ok(pair) => {
                tracing::info!(
                    "tls: loaded MITM CA from plaintext system keychain entries (no SE)"
                );
                Ok(pair)
            }
            Err(err) => {
                tracing::error!(
                    error = %err,
                    "tls: FAILED to parse stored plaintext MITM CA PEMs; WIPING and \
                     regenerating from scratch"
                );
                wipe_all_ca_entries()?;
                generate_and_store()
            }
        },
        (cert_opt, key_opt) => {
            if cert_opt.is_some() || key_opt.is_some() {
                tracing::warn!(
                    cert_present = cert_opt.is_some(),
                    key_present = key_opt.is_some(),
                    "tls: partial plaintext MITM CA state; wiping and regenerating"
                );
                wipe_all_ca_entries()?;
            } else {
                tracing::info!("tls: no MITM CA on file; generating a fresh one");
            }
            generate_and_store()
        }
    }
}

pub(super) fn generate_and_store() -> Result<(X509, PKey<Private>), BoxError> {
    let (cert, key) = generate_ca_pair()?;
    let cert_pem = cert.to_pem().context("encode MITM CA cert to PEM")?;
    let key_pem = key
        .private_key_to_pem_pkcs8()
        .context("encode MITM CA key to PEM")?;

    system_keychain::store_secret(CA_SERVICE_CERT, CA_ACCOUNT, &cert_pem)
        .context("store MITM CA cert in system keychain")?;
    system_keychain::store_secret(CA_SERVICE_KEY, CA_ACCOUNT, &key_pem)
        .context("store MITM CA key in system keychain")?;

    tracing::info!(
        cert_service = CA_SERVICE_CERT,
        key_service = CA_SERVICE_KEY,
        account = CA_ACCOUNT,
        "tls: stored fresh plaintext MITM CA in system keychain (no SE on this Mac)"
    );

    Ok((cert, key))
}

/// Best-effort load of the existing plaintext MITM CA without regeneration.
/// Returns `Ok(None)` when the entries are missing or unparseable.
pub(super) fn try_load_existing() -> Result<Option<(X509, PKey<Private>)>, BoxError> {
    let cert_blob = system_keychain::load_secret(CA_SERVICE_CERT, CA_ACCOUNT)
        .context("load plaintext MITM CA cert PEM")?;
    let key_blob = system_keychain::load_secret(CA_SERVICE_KEY, CA_ACCOUNT)
        .context("load plaintext MITM CA key PEM")?;
    let (Some(cert_pem), Some(key_pem)) = (cert_blob, key_blob) else {
        return Ok(None);
    };
    match parse_pair(&cert_pem, &key_pem) {
        Ok(pair) => Ok(Some(pair)),
        Err(err) => {
            tracing::warn!(error = %err, "tls: try_load_existing plaintext parse failed; treating as absent");
            Ok(None)
        }
    }
}

fn parse_pair(cert_pem: &[u8], key_pem: &[u8]) -> Result<(X509, PKey<Private>), BoxError> {
    let cert = X509::from_pem(cert_pem).context("parse plaintext MITM CA cert PEM")?;
    let key = PKey::private_key_from_pem(key_pem).context("parse plaintext MITM CA key PEM")?;
    Ok((cert, key))
}

/// Best-effort cleanup: drop a stray SE key blob (e.g. left behind after the
/// SE was disabled or the boot disk was migrated to a Mac without one).
fn drop_orphan_se_blob() -> Result<(), BoxError> {
    let Some(orphan) = system_keychain::load_secret(SE_SERVICE_KEY, CA_ACCOUNT)
        .context("probe orphan Secure Enclave key blob")?
    else {
        return Ok(());
    };
    tracing::warn!(
        orphan_blob_len = orphan.len(),
        "tls: found orphaned Secure Enclave key blob on a Mac without SE; deleting"
    );
    system_keychain::delete_secret(SE_SERVICE_KEY, CA_ACCOUNT)
        .context("delete orphan Secure Enclave key blob")?;
    Ok(())
}
