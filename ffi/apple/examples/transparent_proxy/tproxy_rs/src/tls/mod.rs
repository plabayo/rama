pub mod mitm_relay_policy;

mod plaintext_fallback;
mod secure_enclave;

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
            // function-namespace import — does not clash with our `mod secure_enclave;`
            // which lives in the type namespace.
            secure_enclave::is_available as secure_enclave_is_available,
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

    let se_available = secure_enclave_is_available();
    tracing::info!(
        secure_enclave_available = se_available,
        "tls: resolving MITM CA from system keychain"
    );

    if se_available {
        secure_enclave::load_or_create()
    } else {
        tracing::warn!(
            "tls: Secure Enclave NOT available on this Mac; falling back to plaintext keychain \
             storage. PEMs will be readable by anyone with admin access to the System Keychain."
        );
        plaintext_fallback::load_or_create()
    }
}

/// Best-effort load of the existing MITM CA from the system keychain
/// without regenerating one when the state is missing or broken.
///
/// Returns `Ok(None)` if no CA is currently stored — useful for the
/// `uninstall_root_ca` flow, which should be a no-op when there's nothing to
/// remove.
pub(crate) fn try_load_existing_mitm_ca() -> Result<Option<(X509, PKey<Private>)>, BoxError> {
    if secure_enclave_is_available() {
        secure_enclave::try_load_existing()
    } else {
        plaintext_fallback::try_load_existing()
    }
}

/// Install the current MITM CA into the macOS System Keychain.
///
/// If no CA has been minted yet, one is generated first. The cert is added
/// as a keychain item under `/Library/Keychains/System.keychain`. Trust
/// settings are intentionally **not** modified here — the admin trust
/// domain requires an interactive auth dialog (the sysext can't present
/// one), so the container app handles the trust step on the cert DER
/// returned by this function.
///
/// Returns the DER-encoded cert. Idempotent on the keychain side.
pub(crate) fn install_root_ca() -> Result<Vec<u8>, BoxError> {
    tracing::info!("tls: install_root_ca requested");
    let (cert, _key) = load_or_create_mitm_ca(None, None)?;
    let der = cert.to_der().context("encode MITM CA cert to DER")?;
    tracing::debug!(der_len = der.len(), "tls: installing MITM CA into System Keychain");
    system_keychain::install_system_ca(&der).context("install_system_ca failed")?;
    tracing::info!("tls: MITM CA cert added to System Keychain (trust handled by container)");
    Ok(der)
}

/// Inverse of [`install_root_ca`]: delete the current MITM CA from the
/// System Keychain.
///
/// Returns `Ok(Some(der))` for the cert that was uninstalled (so the
/// container can drop the matching admin-domain trust setting), or
/// `Ok(None)` when no CA is stored — the call is idempotent. The stored
/// (SE-encrypted or plaintext) CA blobs in the System Keychain are left
/// untouched, so the next provider start loads the same CA again.
pub(crate) fn uninstall_root_ca() -> Result<Option<Vec<u8>>, BoxError> {
    tracing::info!("tls: uninstall_root_ca requested");
    let Some((cert, _key)) = try_load_existing_mitm_ca()? else {
        tracing::info!("tls: no MITM CA stored; uninstall_root_ca is a no-op");
        return Ok(None);
    };
    let der = cert.to_der().context("encode MITM CA cert to DER")?;
    tracing::debug!(der_len = der.len(), "tls: removing MITM CA from System Keychain");
    system_keychain::uninstall_system_ca(&der).context("uninstall_system_ca failed")?;
    tracing::info!("tls: MITM CA cert removed from System Keychain (trust handled by container)");
    Ok(Some(der))
}

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
