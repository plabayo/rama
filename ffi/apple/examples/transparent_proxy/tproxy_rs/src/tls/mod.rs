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
        let cert =
            X509::from_pem(cert_pem.as_bytes()).context("parse override MITM CA cert PEM")?;
        let key = PKey::private_key_from_pem(key_pem.as_bytes())
            .context("parse override MITM CA key PEM")?;
        return Ok((cert, key));
    }

    let se_key = load_se_key().context("load Secure Enclave key from system keychain")?;

    let cert_blob = system_keychain::load_secret(CA_SERVICE_CERT, CA_ACCOUNT)
        .context("load MITM CA cert blob from system keychain")?;
    let key_blob = system_keychain::load_secret(CA_SERVICE_KEY, CA_ACCOUNT)
        .context("load MITM CA key blob from system keychain")?;

    match (cert_blob, key_blob) {
        (Some(cert_blob), Some(key_blob)) => {
            match decode_pems(se_key.as_ref(), &cert_blob, &key_blob) {
                Ok(pair) => Ok(pair),
                Err(err) => {
                    tracing::warn!(
                        error = %err,
                        "stored MITM CA could not be decoded; regenerating",
                    );
                    wipe_stored_ca()?;
                    generate_and_store_mitm_ca()
                }
            }
        }
        (cert_opt, key_opt) => {
            if cert_opt.is_some() || key_opt.is_some() {
                wipe_stored_ca()?;
            }
            generate_and_store_mitm_ca()
        }
    }
}

fn generate_and_store_mitm_ca() -> Result<(X509, PKey<Private>), BoxError> {
    let (cert, key) = self_signed_server_auth_gen_ca(&SelfSignedData {
        organisation_name: Some("Rama Transparent Proxy Example Root CA".to_owned()),
        common_name: Some(Domain::from_static("rama-tproxy-mitm-ca.localhost")),
        ..Default::default()
    })
    .context("generate MITM CA")?;

    let cert_pem = cert.to_pem().context("encode MITM CA cert to PEM")?;
    let key_pem = key
        .private_key_to_pem_pkcs8()
        .context("encode MITM CA key to PEM")?;

    let se_key = mint_or_reuse_se_key().context("provision Secure Enclave key for MITM CA")?;
    let cert_blob = encode_pem(se_key.as_ref(), &cert_pem).context("encode MITM CA cert blob")?;
    let key_blob = encode_pem(se_key.as_ref(), &key_pem).context("encode MITM CA key blob")?;

    system_keychain::store_secret(CA_SERVICE_CERT, CA_ACCOUNT, &cert_blob)
        .context("store MITM CA cert in system keychain")?;
    system_keychain::store_secret(CA_SERVICE_KEY, CA_ACCOUNT, &key_blob)
        .context("store MITM CA key in system keychain")?;

    Ok((cert, key))
}

/// Load the existing SE key, if any.
///
/// Returns `Ok(None)` either when no key has been stored yet, or when this Mac
/// has no Secure Enclave (e.g. Intel without T2). In the latter case the
/// caller falls back to plaintext storage of the PEMs.
fn load_se_key() -> Result<Option<SecureEnclaveKey>, BoxError> {
    if !secure_enclave::is_available() {
        return Ok(None);
    }
    let blob = system_keychain::load_secret(SE_SERVICE_KEY, CA_ACCOUNT)
        .context("load Secure Enclave key blob")?;
    Ok(blob.map(SecureEnclaveKey::from_data_representation))
}

/// Reuse an existing SE key, or mint and persist a fresh one.
///
/// Returns `Ok(None)` when the Mac has no Secure Enclave.
fn mint_or_reuse_se_key() -> Result<Option<SecureEnclaveKey>, BoxError> {
    if !secure_enclave::is_available() {
        tracing::warn!(
            "Secure Enclave unavailable on this Mac; storing MITM CA material in plaintext",
        );
        return Ok(None);
    }
    if let Some(existing) = load_se_key()? {
        return Ok(Some(existing));
    }
    // `Always` is the only accessibility class usable from a sysext daemon
    // that may run before any user has logged in.
    let key = SecureEnclaveKey::create(SecureEnclaveAccessibility::Always)
        .context("mint Secure Enclave key")?;
    system_keychain::store_secret(SE_SERVICE_KEY, CA_ACCOUNT, key.data_representation())
        .context("store Secure Enclave key blob")?;
    Ok(Some(key))
}

/// Wrap a PEM blob with the SE key when available; otherwise pass through.
fn encode_pem(se_key: Option<&SecureEnclaveKey>, pem: &[u8]) -> Result<Vec<u8>, BoxError> {
    match se_key {
        Some(key) => key
            .encrypt(pem)
            .map_err(BoxError::from)
            .context("encrypt PEM with Secure Enclave"),
        None => Ok(pem.to_vec()),
    }
}

/// Inverse of [`encode_pem`]. When `se_key` is `Some` the input is treated as
/// an SE envelope; when `None` it is treated as raw PEM bytes.
fn decode_pems(
    se_key: Option<&SecureEnclaveKey>,
    cert_blob: &[u8],
    key_blob: &[u8],
) -> Result<(X509, PKey<Private>), BoxError> {
    let (cert_pem, key_pem) = match se_key {
        Some(key) => {
            let cert_pem = key
                .decrypt(cert_blob)
                .map_err(BoxError::from)
                .context("decrypt MITM CA cert with Secure Enclave")?;
            let key_pem = key
                .decrypt(key_blob)
                .map_err(BoxError::from)
                .context("decrypt MITM CA key with Secure Enclave")?;
            (cert_pem, key_pem)
        }
        None => (cert_blob.to_vec(), key_blob.to_vec()),
    };
    let cert = X509::from_pem(&cert_pem).context("parse MITM CA cert PEM")?;
    let key = PKey::private_key_from_pem(&key_pem).context("parse MITM CA key PEM")?;
    Ok((cert, key))
}

/// Best-effort cleanup of every keychain entry this module owns.
fn wipe_stored_ca() -> Result<(), BoxError> {
    system_keychain::delete_secret(CA_SERVICE_CERT, CA_ACCOUNT)
        .context("delete MITM CA cert from system keychain")?;
    system_keychain::delete_secret(CA_SERVICE_KEY, CA_ACCOUNT)
        .context("delete MITM CA key from system keychain")?;
    system_keychain::delete_secret(SE_SERVICE_KEY, CA_ACCOUNT)
        .context("delete Secure Enclave key blob from system keychain")?;
    Ok(())
}
