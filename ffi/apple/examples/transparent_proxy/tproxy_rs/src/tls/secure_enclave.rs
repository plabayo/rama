//! Secure-Enclave-encrypted MITM CA storage.
//!
//! Used when [`secure_enclave::is_available`] returns `true`. Encryption is
//! mandatory on this path: any partial state, plaintext leftovers from a
//! previous build, or decrypt failure forces a wipe-and-regenerate.

use rama::{
    error::{BoxError, ErrorContext as _},
    net::apple::networkextension::system_keychain::{
        self,
        secure_enclave::{SecureEnclaveAccessibility, SecureEnclaveKey},
    },
    telemetry::tracing,
    tls::boring::core::{
        pkey::{PKey, Private},
        x509::X509,
    },
};

use super::{
    CA_ACCOUNT, CA_SERVICE_CERT, CA_SERVICE_KEY, SE_SERVICE_KEY, generate_ca_pair,
    is_pem_plaintext, wipe_all_ca_entries,
};

pub(super) fn load_or_create() -> Result<(X509, PKey<Private>), BoxError> {
    let se_blob = system_keychain::load_secret(SE_SERVICE_KEY, CA_ACCOUNT)
        .context("load Secure Enclave key blob")?;
    let cert_blob = system_keychain::load_secret(CA_SERVICE_CERT, CA_ACCOUNT)
        .context("load MITM CA cert blob")?;
    let key_blob = system_keychain::load_secret(CA_SERVICE_KEY, CA_ACCOUNT)
        .context("load MITM CA key blob")?;

    tracing::debug!(
        se_blob = se_blob.is_some(),
        cert_blob = cert_blob.is_some(),
        key_blob = key_blob.is_some(),
        "tls: SE keychain entry presence"
    );

    match (se_blob, cert_blob, key_blob) {
        (Some(se_blob), Some(cert_blob), Some(key_blob)) => {
            let se_key = SecureEnclaveKey::from_data_representation(se_blob);
            tracing::debug!(
                cert_envelope_len = cert_blob.len(),
                key_envelope_len = key_blob.len(),
                "tls: attempting to decrypt MITM CA with Secure Enclave"
            );
            match decrypt_pair(&se_key, &cert_blob, &key_blob) {
                Ok((cert, key)) => {
                    tracing::info!(
                        "tls: loaded MITM CA from SE-encrypted system keychain entries"
                    );
                    Ok((cert, key))
                }
                Err(err) => {
                    tracing::error!(
                        error = %err,
                        "tls: FAILED to decrypt stored MITM CA with Secure Enclave; WIPING \
                         all entries and regenerating from scratch"
                    );
                    wipe_all_ca_entries()?;
                    generate_and_store()
                }
            }
        }
        (se_blob, cert_blob, key_blob) => {
            tracing::warn!(
                se_blob_present = se_blob.is_some(),
                cert_blob_present = cert_blob.is_some(),
                key_blob_present = key_blob.is_some(),
                cert_blob_looks_plaintext = cert_blob.as_deref().is_some_and(|v| is_pem_plaintext(v)),
                key_blob_looks_plaintext = key_blob.as_deref().is_some_and(|v| is_pem_plaintext(v)),
                "tls: incomplete MITM CA state for Secure Enclave path; WIPING and \
                 regenerating from scratch (this is expected on first SE-enabled boot \
                 after a pre-encryption build)"
            );
            wipe_all_ca_entries()?;
            generate_and_store()
        }
    }
}

pub(super) fn generate_and_store() -> Result<(X509, PKey<Private>), BoxError> {
    tracing::info!("tls: generating fresh MITM CA + Secure Enclave key");
    let (cert, key) = generate_ca_pair()?;
    let cert_pem = cert.to_pem().context("encode MITM CA cert to PEM")?;
    let key_pem = key
        .private_key_to_pem_pkcs8()
        .context("encode MITM CA key to PEM")?;

    let se_key = SecureEnclaveKey::create(SecureEnclaveAccessibility::Always)
        .context("mint Secure Enclave key")?;
    tracing::info!(
        se_blob_len = se_key.data_representation().len(),
        "tls: minted new Secure Enclave P-256 key (kSecAttrAccessibleAlways)"
    );

    let cert_envelope = se_key
        .encrypt(&cert_pem)
        .context("encrypt MITM CA cert PEM with Secure Enclave")?;
    let key_envelope = se_key
        .encrypt(&key_pem)
        .context("encrypt MITM CA key PEM with Secure Enclave")?;
    tracing::debug!(
        cert_envelope_len = cert_envelope.len(),
        key_envelope_len = key_envelope.len(),
        "tls: encrypted MITM CA PEMs with Secure Enclave"
    );

    system_keychain::store_secret(SE_SERVICE_KEY, CA_ACCOUNT, se_key.data_representation())
        .context("store Secure Enclave key blob in system keychain")?;
    system_keychain::store_secret(CA_SERVICE_CERT, CA_ACCOUNT, &cert_envelope)
        .context("store SE-encrypted MITM CA cert in system keychain")?;
    system_keychain::store_secret(CA_SERVICE_KEY, CA_ACCOUNT, &key_envelope)
        .context("store SE-encrypted MITM CA key in system keychain")?;

    tracing::info!(
        se_service = SE_SERVICE_KEY,
        cert_service = CA_SERVICE_CERT,
        key_service = CA_SERVICE_KEY,
        account = CA_ACCOUNT,
        "tls: stored fresh SE-encrypted MITM CA in system keychain"
    );

    Ok((cert, key))
}

/// Best-effort load of the existing SE-encrypted MITM CA without any
/// regeneration. Returns `Ok(None)` when the entries are missing, partial,
/// look like leftover plaintext, or fail to decrypt — never wipes anything.
pub(super) fn try_load_existing() -> Result<Option<(X509, PKey<Private>)>, BoxError> {
    let se_blob = system_keychain::load_secret(SE_SERVICE_KEY, CA_ACCOUNT)
        .context("load Secure Enclave key blob")?;
    let cert_blob = system_keychain::load_secret(CA_SERVICE_CERT, CA_ACCOUNT)
        .context("load MITM CA cert blob")?;
    let key_blob = system_keychain::load_secret(CA_SERVICE_KEY, CA_ACCOUNT)
        .context("load MITM CA key blob")?;

    let (Some(se_blob), Some(cert_blob), Some(key_blob)) = (se_blob, cert_blob, key_blob) else {
        return Ok(None);
    };
    if is_pem_plaintext(&cert_blob) || is_pem_plaintext(&key_blob) {
        // Pre-encryption leftover; the caller (uninstall flow) doesn't need
        // these — we don't have the SE key's matching ciphertext.
        return Ok(None);
    }

    let se_key = SecureEnclaveKey::from_data_representation(se_blob);
    match decrypt_pair(&se_key, &cert_blob, &key_blob) {
        Ok(pair) => Ok(Some(pair)),
        Err(err) => {
            tracing::warn!(error = %err, "tls: try_load_existing decrypt failed; treating as absent");
            Ok(None)
        }
    }
}

fn decrypt_pair(
    se_key: &SecureEnclaveKey,
    cert_envelope: &[u8],
    key_envelope: &[u8],
) -> Result<(X509, PKey<Private>), BoxError> {
    let cert_pem = se_key
        .decrypt(cert_envelope)
        .context("decrypt MITM CA cert with Secure Enclave")?;
    let key_pem = se_key
        .decrypt(key_envelope)
        .context("decrypt MITM CA key with Secure Enclave")?;
    let cert = X509::from_pem(&cert_pem).context("parse decrypted MITM CA cert PEM")?;
    let key = PKey::private_key_from_pem(&key_pem).context("parse decrypted MITM CA key PEM")?;
    Ok((cert, key))
}
