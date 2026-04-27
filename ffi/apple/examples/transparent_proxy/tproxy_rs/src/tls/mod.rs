pub mod mitm_relay_policy;

use rama::tls::boring::proxy::{
    TlsMitmRelay,
    cert_issuer::{CachedBoringMitmCertIssuer, InMemoryBoringMitmCertIssuer},
};

pub(crate) type DemoTlsMitmRelay =
    TlsMitmRelay<CachedBoringMitmCertIssuer<InMemoryBoringMitmCertIssuer>>;

use rama::{
    error::{BoxError, ErrorContext as _},
    net::{
        address::Domain,
        apple::networkextension::system_keychain::{
            self,
            secure_enclave::{self, SecureEnclaveAccessibility, SecureEnclaveKey},
        },
        tls::server::SelfSignedData,
    },
    telemetry::tracing,
    tls::boring::{
        core::{
            pkey::{PKey, Private},
            x509::X509,
        },
        server::utils::self_signed_server_auth_gen_ca,
    },
};

const CA_SERVICE_CERT: &str = "rama-tproxy-demo-ca-crt";
const CA_SERVICE_KEY: &str = "rama-tproxy-demo-ca-key";
const SE_SERVICE_KEY: &str = "rama-tproxy-demo-ca-se-key";
const CA_ACCOUNT: &str = "org.ramaproxy.example.tproxy";

pub(crate) fn load_or_create_mitm_ca(
    cert_pem_override: Option<&str>,
    key_pem_override: Option<&str>,
) -> Result<(X509, PKey<Private>), BoxError> {
    if let (Some(cert_pem), Some(key_pem)) = (cert_pem_override, key_pem_override) {
        tracing::info!("tls: using override MITM CA PEMs from arguments; skipping system keychain");
        let cert =
            X509::from_pem(cert_pem.as_bytes()).context("parse override MITM CA cert PEM")?;
        let key = PKey::private_key_from_pem(key_pem.as_bytes())
            .context("parse override MITM CA key PEM")?;
        return Ok((cert, key));
    }

    let se_available = secure_enclave::is_available();
    tracing::info!(
        secure_enclave_available = se_available,
        "tls: resolving MITM CA from system keychain"
    );

    if se_available {
        load_or_create_with_se()
    } else {
        tracing::warn!(
            "tls: Secure Enclave NOT available on this Mac; falling back to plaintext keychain \
             storage. PEMs will be readable by anyone with admin access to the System Keychain."
        );
        load_or_create_plaintext()
    }
}

// ───────────────────────── Secure Enclave path ──────────────────────────────

fn load_or_create_with_se() -> Result<(X509, PKey<Private>), BoxError> {
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
                    tracing::info!("tls: loaded MITM CA from SE-encrypted system keychain entries");
                    Ok((cert, key))
                }
                Err(err) => {
                    tracing::error!(
                        error = %err,
                        "tls: FAILED to decrypt stored MITM CA with Secure Enclave; WIPING \
                         all entries and regenerating from scratch"
                    );
                    wipe_all_ca_entries()?;
                    generate_and_store_with_se()
                }
            }
        }
        (se_blob, cert_blob, key_blob) => {
            tracing::warn!(
                se_blob_present = se_blob.is_some(),
                cert_blob_present = cert_blob.is_some(),
                key_blob_present = key_blob.is_some(),
                cert_blob_looks_plaintext = cert_blob.as_deref().is_some_and(is_pem_plaintext),
                key_blob_looks_plaintext = key_blob.as_deref().is_some_and(is_pem_plaintext),
                "tls: incomplete MITM CA state for Secure Enclave path; WIPING and \
                 regenerating from scratch (this is expected on first SE-enabled boot \
                 after a pre-encryption build)"
            );
            wipe_all_ca_entries()?;
            generate_and_store_with_se()
        }
    }
}

fn generate_and_store_with_se() -> Result<(X509, PKey<Private>), BoxError> {
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

// ───────────────────────── plaintext fallback path ──────────────────────────

fn load_or_create_plaintext() -> Result<(X509, PKey<Private>), BoxError> {
    // Sanity: drop any orphan SE blob since we have no SE on this Mac.
    if let Some(orphan) = system_keychain::load_secret(SE_SERVICE_KEY, CA_ACCOUNT)
        .context("probe orphan Secure Enclave key blob")?
    {
        tracing::warn!(
            orphan_blob_len = orphan.len(),
            "tls: found orphaned Secure Enclave key blob on a Mac without SE; deleting"
        );
        system_keychain::delete_secret(SE_SERVICE_KEY, CA_ACCOUNT)
            .context("delete orphan Secure Enclave key blob")?;
    }

    let cert_blob = system_keychain::load_secret(CA_SERVICE_CERT, CA_ACCOUNT)
        .context("load plaintext MITM CA cert PEM")?;
    let key_blob = system_keychain::load_secret(CA_SERVICE_KEY, CA_ACCOUNT)
        .context("load plaintext MITM CA key PEM")?;

    match (cert_blob, key_blob) {
        (Some(cert_pem), Some(key_pem)) => match parse_pair_plaintext(&cert_pem, &key_pem) {
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
                generate_and_store_plaintext()
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
            generate_and_store_plaintext()
        }
    }
}

fn generate_and_store_plaintext() -> Result<(X509, PKey<Private>), BoxError> {
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

fn parse_pair_plaintext(
    cert_pem: &[u8],
    key_pem: &[u8],
) -> Result<(X509, PKey<Private>), BoxError> {
    let cert = X509::from_pem(cert_pem).context("parse plaintext MITM CA cert PEM")?;
    let key = PKey::private_key_from_pem(key_pem).context("parse plaintext MITM CA key PEM")?;
    Ok((cert, key))
}

// ───────────────────────── shared helpers ───────────────────────────────────

fn generate_ca_pair() -> Result<(X509, PKey<Private>), BoxError> {
    let pair = self_signed_server_auth_gen_ca(&SelfSignedData {
        organisation_name: Some("Rama Transparent Proxy Example Root CA".to_owned()),
        common_name: Some(Domain::from_static("rama-tproxy-mitm-ca.localhost")),
        ..Default::default()
    })
    .context("generate MITM CA")?;
    tracing::debug!("tls: generated self-signed MITM CA");
    Ok(pair)
}

/// Best-effort cleanup of every keychain entry this module owns.
fn wipe_all_ca_entries() -> Result<(), BoxError> {
    tracing::warn!(
        cert_service = CA_SERVICE_CERT,
        key_service = CA_SERVICE_KEY,
        se_service = SE_SERVICE_KEY,
        account = CA_ACCOUNT,
        "tls: wiping every MITM CA related entry from the System Keychain"
    );
    system_keychain::delete_secret(CA_SERVICE_CERT, CA_ACCOUNT)
        .context("delete MITM CA cert from system keychain")?;
    system_keychain::delete_secret(CA_SERVICE_KEY, CA_ACCOUNT)
        .context("delete MITM CA key from system keychain")?;
    system_keychain::delete_secret(SE_SERVICE_KEY, CA_ACCOUNT)
        .context("delete Secure Enclave key blob from system keychain")?;
    Ok(())
}

fn is_pem_plaintext(bytes: &[u8]) -> bool {
    bytes.starts_with(b"-----BEGIN")
}
