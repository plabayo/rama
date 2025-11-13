use rama::{
    http::tls::CertIssuerHttpClient,
    net::{
        address::Host,
        tls::{
            ApplicationProtocol, DataEncoding,
            server::{
                CacheKind, SelfSignedData, ServerAuth, ServerAuthData, ServerCertIssuerData,
                ServerConfig,
            },
        },
    },
    telemetry::tracing,
    tls::boring::core::x509::X509,
    utils::str::NATIVE_NEWLINE,
};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as ENGINE;

#[must_use]
pub fn new_server_config(alpn: Option<Vec<ApplicationProtocol>>) -> ServerConfig {
    match CertIssuerHttpClient::try_from_env() {
        Ok(issuer) => {
            return ServerConfig {
                application_layer_protocol_negotiation: alpn,
                ..ServerConfig::new(ServerAuth::CertIssuer(ServerCertIssuerData {
                    kind: issuer.into(),
                    cache_kind: CacheKind::default(),
                }))
            };
        }
        Err(err) => {
            tracing::debug!("failed to create CertIssuerHttpClient from env: {err}");
        }
    }

    let Ok(tls_key_pem_raw) = std::env::var("RAMA_TLS_KEY") else {
        return ServerConfig {
            application_layer_protocol_negotiation: alpn,
            ..ServerConfig::new(ServerAuth::SelfSigned(SelfSignedData::default()))
        };
    };
    let tls_key_pem_raw = std::str::from_utf8(
        &ENGINE
            .decode(tls_key_pem_raw)
            .expect("base64 decode RAMA_TLS_KEY")[..],
    )
    .expect("base64-decoded RAMA_TLS_KEY valid utf-8")
    .try_into()
    .expect("tls_key_pem_raw => NonEmptyStr (RAMA_TLS_KEY)");
    let tls_crt_pem_raw = std::env::var("RAMA_TLS_CRT").expect("RAMA_TLS_CRT");
    let tls_crt_pem_raw = std::str::from_utf8(
        &ENGINE
            .decode(tls_crt_pem_raw)
            .expect("base64 decode RAMA_TLS_CRT")[..],
    )
    .expect("base64-decoded RAMA_TLS_CRT valid utf-8")
    .try_into()
    .expect("tls_crt_pem_raw => NonEmptyStr (RAMA_TLS_CRT)");
    ServerConfig {
        application_layer_protocol_negotiation: alpn,
        ..ServerConfig::new(ServerAuth::Single(ServerAuthData {
            private_key: DataEncoding::Pem(tls_key_pem_raw),
            cert_chain: DataEncoding::Pem(tls_crt_pem_raw),
            ocsp: None,
        }))
    }
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
