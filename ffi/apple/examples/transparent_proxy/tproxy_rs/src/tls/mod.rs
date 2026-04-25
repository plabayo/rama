pub mod mitm_relay_policy;

use rama::{
    error::{BoxError, ErrorContext as _},
    net::{
        address::Domain,
        apple::networkextension::system_keychain,
        tls::server::SelfSignedData,
    },
    tls::boring::{
        core::{pkey::{PKey, Private}, x509::X509},
        server::utils::self_signed_server_auth_gen_ca,
    },
};

const CA_SERVICE_CERT: &str = "tls-root-selfsigned-ca-crt";
const CA_SERVICE_KEY: &str = "tls-root-selfsigned-ca-key";
const CA_ACCOUNT: &str = "org.ramaproxy.example.tproxy";

pub(crate) fn load_or_create_mitm_ca(
    cert_pem_override: Option<&str>,
    key_pem_override: Option<&str>,
) -> Result<(X509, PKey<Private>), BoxError> {
    if let (Some(cert_pem), Some(key_pem)) = (cert_pem_override, key_pem_override) {
        let cert = X509::from_pem(cert_pem.as_bytes()).context("parse override MITM CA cert PEM")?;
        let key = PKey::private_key_from_pem(key_pem.as_bytes()).context("parse override MITM CA key PEM")?;
        return Ok((cert, key));
    }

    let cert_bytes = system_keychain::load_secret(CA_SERVICE_CERT, CA_ACCOUNT)
        .context("load MITM CA cert from system keychain")?;
    let key_bytes = system_keychain::load_secret(CA_SERVICE_KEY, CA_ACCOUNT)
        .context("load MITM CA key from system keychain")?;

    match (cert_bytes, key_bytes) {
        (Some(cert_pem), Some(key_pem)) => {
            let cert = X509::from_pem(&cert_pem).context("parse MITM CA cert PEM")?;
            let key =
                PKey::private_key_from_pem(&key_pem).context("parse MITM CA key PEM")?;
            Ok((cert, key))
        }
        (cert_opt, key_opt) => {
            if cert_opt.is_some() {
                system_keychain::delete_secret(CA_SERVICE_CERT, CA_ACCOUNT)
                    .context("delete partial MITM CA cert from system keychain")?;
            }
            if key_opt.is_some() {
                system_keychain::delete_secret(CA_SERVICE_KEY, CA_ACCOUNT)
                    .context("delete partial MITM CA key from system keychain")?;
            }
            generate_and_store_mitm_ca()
        }
    }
}

fn generate_and_store_mitm_ca(
) -> Result<(X509, PKey<Private>), BoxError> {
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

    system_keychain::store_secret(CA_SERVICE_CERT, CA_ACCOUNT, &cert_pem)
        .context("store MITM CA cert in system keychain")?;
    system_keychain::store_secret(CA_SERVICE_KEY, CA_ACCOUNT, &key_pem)
        .context("store MITM CA key in system keychain")?;

    Ok((cert, key))
}
