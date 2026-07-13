use rama::{
    crypto::{
        cert::self_signed_server_auth,
        pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    },
    error::{BoxError, ErrorContext as _},
    http::tls::CertIssuerHttpClient,
    net::address::Host,
    rt::Executor,
    telemetry::tracing,
    tls::boring::{
        core::x509::X509,
        server::{BoringServerConfigExt as _, CacheKind, ServerCertIssuerData},
    },
    tls::{
        ApplicationProtocol,
        client::TlsServerCertPin,
        server::{SelfSignedData, ServerAuthData, TlsServerConfig},
    },
    utils::str::NATIVE_NEWLINE,
};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as ENGINE;

pub fn try_new_server_config(
    alpn: Option<Vec<ApplicationProtocol>>,
    exec: Executor,
) -> Result<TlsServerConfig, BoxError> {
    let mut config = TlsServerConfig::new();
    match CertIssuerHttpClient::try_from_env(exec) {
        Ok(issuer) => {
            config.set_cert_issuer(ServerCertIssuerData {
                kind: issuer.into(),
                cache_kind: CacheKind::default(),
            });
        }
        Err(err) => {
            tracing::debug!("failed to create CertIssuerHttpClient from env: {err}");
            config.set_server_auth(try_new_server_auth()?);
        }
    }
    if let Some(alpn) = alpn {
        config.set_alpn(alpn.into());
    }
    Ok(config)
}

fn try_new_server_auth() -> Result<ServerAuthData, BoxError> {
    let Ok(tls_key_pem_raw) = std::env::var("RAMA_TLS_KEY") else {
        let (cert_chain, private_key) = self_signed_server_auth(SelfSignedData::default())?;
        return Ok(ServerAuthData::new(cert_chain, private_key));
    };
    let tls_key_pem_raw = &ENGINE
        .decode(tls_key_pem_raw)
        .context("base64 decode RAMA_TLS_KEY")?[..];

    let tls_crt_pem_raw = std::env::var("RAMA_TLS_CRT")
        .context("RAMA_TLS_CRT env to be available when RAMA_TLS_KEY is available")?;
    let tls_crt_pem_raw = &ENGINE
        .decode(tls_crt_pem_raw)
        .context("base64 decode RAMA_TLS_CRT")?[..];

    let cert_chain = CertificateDer::pem_slice_iter(tls_crt_pem_raw)
        .collect::<Result<Vec<_>, _>>()
        .context("parse crt pem chain")?;
    let private_key =
        PrivateKeyDer::from_pem_slice(tls_key_pem_raw).context("parse private key")?;

    Ok(ServerAuthData {
        private_key,
        cert_chain,
        ocsp: None,
    })
}

pub(crate) fn write_cert_info(
    x509: &X509,
    row_prefix: &str,
    w: &mut impl std::io::Write,
) -> std::io::Result<()> {
    write!(w, "{row_prefix}subject:",)?;
    fmt_crt_name(x509.subject_name(), w)?;
    writeln!(w)?;

    write!(
        w,
        "{row_prefix}start date: {}{NATIVE_NEWLINE}",
        x509.not_before()
    )?;
    write!(
        w,
        "{row_prefix}expire date: {}{NATIVE_NEWLINE}",
        x509.not_after()
    )?;

    if let Some(alt_names) = x509.subject_alt_names()
        && !alt_names.is_empty()
    {
        write!(w, "{row_prefix}subjectAltNames:")?;
        for (index, alt_name) in alt_names.iter().enumerate() {
            let separator = if index == 0 { " " } else { ", " };
            if let Some(domain) = alt_name.dnsname() {
                write!(w, "{separator}DNS={domain}")?;
            } else if let Some(uri) = alt_name.uri() {
                write!(w, "{separator}URI={uri}")?;
            } else if let Some(email) = alt_name.email() {
                write!(w, "{separator}EMAIL={email}")?;
            } else if let Some(ip_bytes) = alt_name.ipaddress() {
                if let Ok(host) = Host::try_from(ip_bytes) {
                    write!(w, "{separator}IP={host}")?;
                } else {
                    write!(w, "{separator}IP=<{ip_bytes:?}>")?;
                }
            } else {
                write!(w, "{separator}UNKNOWN=<{alt_name:?}>")?;
            }
        }
        writeln!(w)?;
    }

    if let Ok(der) = x509.to_der()
        && let Ok(pin) = TlsServerCertPin::spki_sha256_of(&CertificateDer::from(der))
    {
        write!(w, "{row_prefix}public key pin: {pin}{NATIVE_NEWLINE}")?;
    }

    write!(w, "{row_prefix}issuer:")?;
    fmt_crt_name(x509.issuer_name(), w)?;
    writeln!(w)?;

    Ok(())
}

fn fmt_crt_name(
    x: &rama::tls::boring::core::x509::X509NameRef,
    w: &mut impl std::io::Write,
) -> std::io::Result<()> {
    for (index, e) in x.entries().enumerate() {
        let obj = e.object();
        let short = obj.nid().short_name().unwrap_or("OBJ");
        let separator = if index == 0 { " " } else { ", " };
        let entry_data = e.data();
        if let Ok(utf8_str) = entry_data.as_utf8() {
            write!(w, "{separator}{short}={utf8_str}")?;
        } else {
            write!(w, "{separator}{short}=")?;
            fmt_hex(entry_data.as_slice(), ":", w)?;
        }
    }

    Ok(())
}

fn fmt_hex(bytes: &[u8], sep: &str, w: &mut impl std::io::Write) -> std::io::Result<()> {
    for (i, b) in bytes.iter().enumerate() {
        let separator = if i == 0 { "" } else { sep };
        write!(w, "{separator}{b:02X}")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama::crypto::cert::SelfSignedData;

    #[test]
    fn write_cert_info_includes_copyable_key_pin() {
        let (chain, _) = self_signed_server_auth(SelfSignedData::default()).unwrap();
        let leaf = X509::from_der(chain[0].as_ref()).unwrap();
        let expected_pin = TlsServerCertPin::spki_sha256_of(&chain[0]).unwrap();

        let mut out = Vec::new();
        write_cert_info(&leaf, "* ", &mut out).unwrap();

        let out = String::from_utf8(out).unwrap();
        assert!(
            out.contains(&format!("* public key pin: {expected_pin}")),
            "{out}"
        );
    }
}
